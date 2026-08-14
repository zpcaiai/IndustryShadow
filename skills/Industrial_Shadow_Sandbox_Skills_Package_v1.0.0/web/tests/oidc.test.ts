import {
  SignJWT,
  exportJWK,
  generateKeyPair,
  type CryptoKey,
  type JWK,
  type JWTPayload,
} from 'jose'
import { describe, expect, it, vi } from 'vitest'

import {
  loadAuthConfig,
  OidcIdTokenVerifier,
  OidcPkceClient,
  type OidcAuthConfig,
} from '../src/auth/oidc'

class MemoryStorage implements Storage {
  private readonly data = new Map<string, string>()
  get length() {
    return this.data.size
  }
  clear() {
    this.data.clear()
  }
  getItem(key: string) {
    return this.data.get(key) ?? null
  }
  key(index: number) {
    return [...this.data.keys()][index] ?? null
  }
  removeItem(key: string) {
    this.data.delete(key)
  }
  setItem(key: string, value: string) {
    this.data.set(key, value)
  }
  values() {
    return [...this.data.values()]
  }
}

const config: OidcAuthConfig = {
  mode: 'oidc_pkce',
  issuer: 'https://identity.example.test/tenant',
  audience: 'industrial-shadow-api',
  client_id: 'industrial-shadow-web',
  discovery_endpoint:
    'https://identity.example.test/tenant/.well-known/openid-configuration',
  jwks_uri: 'https://identity.example.test/tenant/keys',
  id_token_signing_algorithms: ['RS256'],
  authorization_endpoint: 'https://identity.example.test/tenant/authorize',
  token_endpoint: 'https://identity.example.test/tenant/token',
  end_session_endpoint: 'https://identity.example.test/tenant/logout',
  scopes: ['openid', 'profile'],
  redirect_path: '/auth/callback',
}

const NOW = 1_800_000_000_000

type SigningKey = {
  kid: string
  privateKey: CryptoKey
  publicJwk: JWK
}

async function signingKey(kid: string): Promise<SigningKey> {
  const pair = await generateKeyPair('RS256', { extractable: true })
  return {
    kid,
    privateKey: pair.privateKey,
    publicJwk: {
      ...(await exportJWK(pair.publicKey)),
      alg: 'RS256',
      kid,
      key_ops: ['verify'],
      use: 'sig',
    },
  }
}

async function idToken(
  key: SigningKey,
  claims: Partial<JWTPayload> = {},
  protectedHeader: Record<string, unknown> = {},
): Promise<string> {
  const now = Math.floor(NOW / 1000)
  return new SignJWT({
    iss: config.issuer,
    aud: config.client_id,
    sub: 'human-operator',
    nonce: 'expected-nonce',
    iat: now,
    exp: now + 300,
    ...claims,
  })
    .setProtectedHeader({
      alg: 'RS256',
      kid: key.kid,
      typ: 'JWT',
      ...protectedHeader,
    })
    .sign(key.privateKey)
}

function discovery(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    issuer: config.issuer,
    authorization_endpoint: config.authorization_endpoint,
    token_endpoint: config.token_endpoint,
    jwks_uri: config.jwks_uri,
    end_session_endpoint: config.end_session_endpoint,
    response_types_supported: ['code'],
    scopes_supported: ['openid', 'profile'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    id_token_signing_alg_values_supported: ['RS256'],
    ...overrides,
  }
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function providerFetcher(
  keys: () => JWK[],
  tokenResponse: () => unknown = () => ({
    error: 'no token response configured',
  }),
  metadata: () => Record<string, unknown> = () => discovery(),
) {
  return vi.fn(async (input: string | URL | Request) => {
    const url =
      typeof input === 'string'
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url
    if (url === config.discovery_endpoint) return jsonResponse(metadata())
    if (url === config.jwks_uri) return jsonResponse({ keys: keys() })
    if (url === config.token_endpoint) return jsonResponse(tokenResponse())
    throw new Error(`unexpected request: ${url}`)
  })
}

function verifier(
  fetcher: ReturnType<typeof providerFetcher>,
): OidcIdTokenVerifier {
  return new OidcIdTokenVerifier(
    config,
    fetcher as unknown as typeof fetch,
    () => NOW,
  )
}

function encodeJson(value: object): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url')
}

describe('OIDC runtime configuration and discovery binding', () => {
  it('loads the public runtime configuration with separate API and human audiences', async () => {
    const fetcher = vi.fn().mockResolvedValue(jsonResponse(config))
    await expect(loadAuthConfig(fetcher)).resolves.toEqual(config)
    expect(fetcher).toHaveBeenCalledWith(
      '/api/v1/auth/config',
      expect.objectContaining({
        credentials: 'same-origin',
        redirect: 'error',
      }),
    )
  })

  it('rejects insecure URLs, unsafe algorithms, and a reused API audience', async () => {
    for (const override of [
      { end_session_endpoint: 'http://identity.example.test/logout' },
      { redirect_path: 'https://attacker.example/callback' },
      { id_token_signing_algorithms: ['none'] },
      { id_token_signing_algorithms: ['HS256'] },
      { audience: config.client_id },
      {
        discovery_endpoint:
          'https://identity.example.test/unbound/.well-known/openid-configuration',
      },
    ]) {
      const fetcher = vi
        .fn()
        .mockResolvedValue(jsonResponse({ ...config, ...override }))
      await expect(loadAuthConfig(fetcher)).rejects.toThrow(
        /HTTPS|same-origin|algorithms|audience|discovery/,
      )
    }
  })

  it('rejects discovery metadata that is not bound to the trusted issuer and JWKS URI', async () => {
    for (const override of [
      { issuer: 'https://attacker.example.test' },
      { jwks_uri: 'https://attacker.example.test/keys' },
      { code_challenge_methods_supported: ['plain'] },
      { token_endpoint_auth_methods_supported: ['client_secret_basic'] },
      { id_token_signing_alg_values_supported: ['ES256'] },
    ]) {
      const fetcher = providerFetcher(
        () => [],
        undefined,
        () => discovery(override),
      )
      await expect(verifier(fetcher).ensureProviderMetadata()).rejects.toThrow(
        'does not match the trusted runtime configuration',
      )
    }
  })
})

describe('OIDC ID token JWS and claims verification', () => {
  it('accepts a valid asymmetric signature and exact OIDC claims', async () => {
    const key = await signingKey('key-1')
    const fetcher = providerFetcher(() => [key.publicJwk])
    await expect(
      verifier(fetcher).validate(await idToken(key), 'expected-nonce', true),
    ).resolves.toBeUndefined()
    expect(
      fetcher.mock.calls.filter(([url]) => String(url) === config.jwks_uri),
    ).toHaveLength(1)
  })

  it('rejects a tampered signature', async () => {
    const key = await signingKey('key-1')
    const signed = await idToken(key)
    const parts = signed.split('.')
    parts[2] = `${parts[2][0] === 'A' ? 'B' : 'A'}${parts[2].slice(1)}`
    const fetcher = providerFetcher(() => [key.publicJwk])
    await expect(
      verifier(fetcher).validate(parts.join('.'), 'expected-nonce', true),
    ).rejects.toThrow('signature or claims validation failed')
  })

  it('rejects alg none, missing required headers, and an unapproved protected header', async () => {
    const payload = encodeJson({
      iss: config.issuer,
      aud: config.client_id,
      sub: 'human-operator',
      nonce: 'expected-nonce',
      iat: NOW / 1000,
      exp: NOW / 1000 + 300,
    })
    const none = `${encodeJson({ alg: 'none', kid: 'key-1', typ: 'JWT' })}.${payload}.`
    const key = await signingKey('key-1')
    const missingTyp = await idToken(key, {}, { typ: undefined })
    const missingKid = await idToken(key, {}, { kid: undefined })
    const remoteJku = await idToken(
      key,
      {},
      { jku: 'https://attacker.example.test/keys' },
    )
    const fetcher = providerFetcher(() => [key.publicJwk])
    const validator = verifier(fetcher)
    for (const token of [none, missingTyp, missingKid, remoteJku]) {
      await expect(
        validator.validate(token, 'expected-nonce', true),
      ).rejects.toThrow('signature or claims validation failed')
    }
  })

  it('rejects an unknown kid', async () => {
    const trusted = await signingKey('trusted-key')
    const unknown = await signingKey('unknown-key')
    const fetcher = providerFetcher(() => [trusted.publicJwk])
    await expect(
      verifier(fetcher).validate(
        await idToken(unknown),
        'expected-nonce',
        true,
      ),
    ).rejects.toThrow('signature or claims validation failed')
  })

  it('requires azp for multiple audiences and binds it to the human client', async () => {
    const key = await signingKey('key-1')
    const fetcher = providerFetcher(() => [key.publicJwk])
    const validator = verifier(fetcher)
    await expect(
      validator.validate(
        await idToken(key, {
          aud: [config.client_id, 'another-client'],
          azp: config.client_id,
        }),
        'expected-nonce',
        true,
      ),
    ).resolves.toBeUndefined()
    for (const azp of [undefined, 'another-client']) {
      await expect(
        validator.validate(
          await idToken(key, {
            aud: [config.client_id, 'another-client'],
            azp,
          }),
          'expected-nonce',
          true,
        ),
      ).rejects.toThrow('signature or claims validation failed')
    }
  })

  it('rejects invalid issuer, audience, time, and nonce claims', async () => {
    const key = await signingKey('key-1')
    const now = NOW / 1000
    const fetcher = providerFetcher(() => [key.publicJwk])
    const validator = verifier(fetcher)
    for (const [claims, nonce] of [
      [{ exp: now - 120 }, 'expected-nonce'],
      [{ exp: undefined }, 'expected-nonce'],
      [{ iat: now + 120 }, 'expected-nonce'],
      [{ iat: undefined }, 'expected-nonce'],
      [{ nbf: now + 120 }, 'expected-nonce'],
      [{ iss: 'https://attacker.example.test' }, 'expected-nonce'],
      [{ aud: config.audience }, 'expected-nonce'],
      [{}, 'wrong-nonce'],
      [{ nonce: undefined }, 'expected-nonce'],
    ] as const) {
      await expect(
        validator.validate(await idToken(key, claims), nonce, true),
      ).rejects.toThrow('signature or claims validation failed')
    }
  })

  it('reloads the remote JWKS when a new kid appears', async () => {
    const first = await signingKey('key-1')
    const rotated = await signingKey('key-2')
    let activeKeys = [first.publicJwk]
    const fetcher = providerFetcher(() => activeKeys)
    const validator = verifier(fetcher)
    await validator.validate(await idToken(first), 'expected-nonce', true)
    activeKeys = [rotated.publicJwk]
    await expect(
      validator.validate(await idToken(rotated), 'expected-nonce', true),
    ).resolves.toBeUndefined()
    expect(
      fetcher.mock.calls.filter(([url]) => String(url) === config.jwks_uri),
    ).toHaveLength(2)
  })
})

describe('OIDC Authorization Code + PKCE client', () => {
  it('binds discovery, state, nonce, PKCE, signed tokens, refresh, and logout', async () => {
    const key = await signingKey('key-1')
    const storage = new MemoryStorage()
    let now = NOW
    let tokenResponse: unknown = { error: 'not ready' }
    const fetcher = providerFetcher(
      () => [key.publicJwk],
      () => tokenResponse,
    )
    const client = new OidcPkceClient(
      config,
      storage,
      fetcher as unknown as typeof fetch,
      globalThis.crypto,
      () => now,
    )
    const authorize = new URL(
      await client.authorizationUrl('https://shadow.example.test', '/runs'),
    )
    expect(authorize.searchParams.get('response_type')).toBe('code')
    expect(authorize.searchParams.get('client_id')).toBe(config.client_id)
    expect(authorize.searchParams.get('audience')).toBe(config.audience)
    expect(authorize.searchParams.get('code_challenge_method')).toBe('S256')
    expect(authorize.searchParams.get('code_challenge')).toMatch(
      /^[A-Za-z0-9_-]{43}$/,
    )
    const pending = JSON.parse(storage.values()[0]) as {
      state: string
      nonce: string
    }
    const signed = await idToken(key, { nonce: pending.nonce })
    tokenResponse = {
      token_type: 'Bearer',
      access_token: 'access-1',
      refresh_token: 'refresh-1',
      id_token: signed,
      expires_in: 60,
    }
    await expect(
      client.complete(
        `https://shadow.example.test/auth/callback?code=code-1&state=${pending.state}`,
      ),
    ).resolves.toBe('/runs')
    await expect(client.accessToken()).resolves.toBe('access-1')
    now += 61_000
    tokenResponse = {
      token_type: 'Bearer',
      access_token: 'access-2',
      expires_in: 60,
    }
    const refreshes = await Promise.all([
      client.accessToken(),
      client.accessToken(),
    ])
    expect(refreshes).toEqual(['access-2', 'access-2'])
    expect(
      fetcher.mock.calls.filter(
        ([url]) => String(url) === config.token_endpoint,
      ),
    ).toHaveLength(2)
    const logout = new URL(client.logoutUrl('https://shadow.example.test'))
    expect(logout.origin + logout.pathname).toBe(config.end_session_endpoint)
    expect(logout.searchParams.get('id_token_hint')).toBe(signed)
    expect(client.hasSession()).toBe(false)
  })

  it('fails closed on state mismatch after validating provider metadata', async () => {
    const storage = new MemoryStorage()
    const fetcher = providerFetcher(() => [])
    const client = new OidcPkceClient(
      config,
      storage,
      fetcher as unknown as typeof fetch,
      globalThis.crypto,
    )
    await client.authorizationUrl(
      'https://shadow.example.test',
      '//attacker.example',
    )
    await expect(
      client.complete(
        'https://shadow.example.test/auth/callback?code=code-1&state=wrong',
      ),
    ).rejects.toThrow('state validation failed')
    expect(
      fetcher.mock.calls.filter(
        ([url]) => String(url) === config.token_endpoint,
      ),
    ).toHaveLength(0)
    expect(client.hasSession()).toBe(false)
  })

  it('normalizes an external return target to the application root', async () => {
    const key = await signingKey('key-1')
    const storage = new MemoryStorage()
    let tokenResponse: unknown
    const fetcher = providerFetcher(
      () => [key.publicJwk],
      () => tokenResponse,
    )
    const client = new OidcPkceClient(
      config,
      storage,
      fetcher as unknown as typeof fetch,
      globalThis.crypto,
      () => NOW,
    )
    await client.authorizationUrl(
      'https://shadow.example.test',
      '//attacker.example',
    )
    const pending = JSON.parse(storage.values()[0]) as {
      state: string
      nonce: string
    }
    tokenResponse = {
      token_type: 'Bearer',
      access_token: 'access-safe-return',
      id_token: await idToken(key, { nonce: pending.nonce }),
      expires_in: 60,
    }
    await expect(
      client.complete(
        `https://shadow.example.test/auth/callback?code=code-1&state=${pending.state}`,
      ),
    ).resolves.toBe('/')
  })

  it('rejects a callback delivered to a different origin or path', async () => {
    for (const callback of [
      'https://attacker.example/auth/callback',
      'https://shadow.example.test/not-the-callback',
    ]) {
      const storage = new MemoryStorage()
      const fetcher = providerFetcher(() => [])
      const client = new OidcPkceClient(
        config,
        storage,
        fetcher as unknown as typeof fetch,
        globalThis.crypto,
      )
      await client.authorizationUrl('https://shadow.example.test', '/')
      const pending = JSON.parse(storage.values()[0]) as { state: string }
      await expect(
        client.complete(`${callback}?code=code-1&state=${pending.state}`),
      ).rejects.toThrow('callback URL does not match')
      expect(
        fetcher.mock.calls.filter(
          ([url]) => String(url) === config.token_endpoint,
        ),
      ).toHaveLength(0)
    }
  })
})
