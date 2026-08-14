import {
  createRemoteJWKSet,
  customFetch,
  decodeProtectedHeader,
  jwtVerify,
  type RemoteJWKSet,
} from 'jose'

export type DevelopmentAuthConfig = { mode: 'development' }

const SAFE_ID_TOKEN_ALGORITHMS = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
] as const

export type IdTokenAlgorithm = (typeof SAFE_ID_TOKEN_ALGORITHMS)[number]

export type OidcAuthConfig = {
  mode: 'oidc_pkce'
  issuer: string
  audience: string
  client_id: string
  discovery_endpoint: string
  jwks_uri: string
  id_token_signing_algorithms: IdTokenAlgorithm[]
  authorization_endpoint: string
  token_endpoint: string
  end_session_endpoint?: string | null
  scopes: string[]
  redirect_path: string
}

export type AuthConfig = DevelopmentAuthConfig | OidcAuthConfig

type PendingAuthorization = {
  state: string
  nonce: string
  verifier: string
  redirect_uri: string
  return_to: string
  created_at: number
}

type TokenSession = {
  access_token: string
  refresh_token?: string
  id_token: string
  nonce: string
  expires_at: number
  token_type: 'Bearer'
}

const PENDING_KEY = 'industrial-shadow.oidc.pending.v1'
const TOKEN_KEY = 'industrial-shadow.oidc.tokens.v2'
const MAX_PENDING_AGE_MS = 10 * 60 * 1000
const MAX_ID_TOKEN_AGE_SECONDS = 10 * 60
const CLOCK_TOLERANCE_SECONDS = 60

type ProviderMetadata = {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
  end_session_endpoint?: string
  response_types_supported: string[]
  scopes_supported: string[]
  code_challenge_methods_supported: string[]
  token_endpoint_auth_methods_supported: string[]
  id_token_signing_alg_values_supported: string[]
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const value of bytes) binary += String.fromCharCode(value)
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

function randomValue(cryptoProvider: Crypto, size = 32): string {
  const bytes = new Uint8Array(size)
  cryptoProvider.getRandomValues(bytes)
  return encodeBase64Url(bytes)
}

async function challenge(
  cryptoProvider: Crypto,
  verifier: string,
): Promise<string> {
  const digest = await cryptoProvider.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(verifier),
  )
  return encodeBase64Url(new Uint8Array(digest))
}

function safeReturnTo(value: string): string {
  const base = new URL('https://local-return.invalid/')
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\'))
    return '/'
  const parsed = new URL(value, base)
  return parsed.origin === base.origin
    ? `${parsed.pathname}${parsed.search}${parsed.hash}`
    : '/'
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.trim())
    throw new Error(`OIDC ${field} is invalid`)
  return value
}

function requireStringArray(value: unknown, field: string): string[] {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((item) => typeof item !== 'string' || !item.trim())
  ) {
    throw new Error(`OIDC ${field} is invalid`)
  }
  const result = value as string[]
  if (new Set(result).size !== result.length)
    throw new Error(`OIDC ${field} must be unique`)
  return [...result]
}

function requireHttpsUrl(
  value: unknown,
  field: string,
  issuer = false,
): string {
  const raw = requireString(value, field)
  try {
    const parsed = new URL(raw)
    if (
      parsed.protocol !== 'https:' ||
      parsed.username ||
      parsed.password ||
      parsed.hash ||
      (issuer &&
        (parsed.search ||
          parsed.pathname.endsWith('/.well-known/openid-configuration')))
    ) {
      throw new Error('invalid URL')
    }
    return raw
  } catch {
    throw new Error(
      `OIDC ${field} must be an HTTPS URL without credentials or fragments`,
    )
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parseProviderMetadata(value: unknown): ProviderMetadata {
  if (!isRecord(value)) throw new Error('OIDC discovery document is invalid')
  return {
    issuer: requireString(value.issuer, 'discovery issuer'),
    authorization_endpoint: requireString(
      value.authorization_endpoint,
      'discovery authorization endpoint',
    ),
    token_endpoint: requireString(
      value.token_endpoint,
      'discovery token endpoint',
    ),
    jwks_uri: requireString(value.jwks_uri, 'discovery JWKS URI'),
    end_session_endpoint:
      typeof value.end_session_endpoint === 'string'
        ? value.end_session_endpoint
        : undefined,
    response_types_supported: requireStringArray(
      value.response_types_supported,
      'discovery response types',
    ),
    scopes_supported: requireStringArray(
      value.scopes_supported,
      'discovery scopes',
    ),
    code_challenge_methods_supported: requireStringArray(
      value.code_challenge_methods_supported,
      'discovery PKCE methods',
    ),
    token_endpoint_auth_methods_supported: requireStringArray(
      value.token_endpoint_auth_methods_supported,
      'discovery token endpoint authentication methods',
    ),
    id_token_signing_alg_values_supported: requireStringArray(
      value.id_token_signing_alg_values_supported,
      'discovery ID token algorithms',
    ),
  }
}

function responseStayedAt(response: Response, expected: string): boolean {
  if (
    response.type === 'opaqueredirect' ||
    (response.status >= 300 && response.status < 400)
  ) {
    return false
  }
  return (
    !response.url ||
    new URL(response.url).toString() === new URL(expected).toString()
  )
}

export class OidcIdTokenVerifier {
  private resolverPromise: Promise<RemoteJWKSet> | null = null

  constructor(
    private readonly config: OidcAuthConfig,
    private readonly fetcher: typeof fetch = fetch,
    private readonly now: () => number = Date.now,
  ) {}

  async ensureProviderMetadata(): Promise<void> {
    await this.resolver()
  }

  async validate(
    token: string,
    expectedNonce: string,
    requireNonce: boolean,
  ): Promise<void> {
    try {
      const header = decodeProtectedHeader(token)
      if (
        typeof header.alg !== 'string' ||
        !this.config.id_token_signing_algorithms.includes(
          header.alg as IdTokenAlgorithm,
        ) ||
        typeof header.kid !== 'string' ||
        !header.kid.trim() ||
        header.kid.length > 256 ||
        header.typ !== 'JWT' ||
        header.crit !== undefined ||
        header.jku !== undefined ||
        header.jwk !== undefined ||
        header.x5u !== undefined
      ) {
        throw new Error('untrusted JOSE protected header')
      }

      const { payload } = await jwtVerify(token, await this.resolver(), {
        algorithms: this.config.id_token_signing_algorithms,
        issuer: this.config.issuer,
        audience: this.config.client_id,
        typ: 'JWT',
        currentDate: new Date(this.now()),
        clockTolerance: CLOCK_TOLERANCE_SECONDS,
        maxTokenAge: MAX_ID_TOKEN_AGE_SECONDS,
        requiredClaims: ['sub', 'exp', 'iat'],
      })

      const audiences =
        typeof payload.aud === 'string' ? [payload.aud] : payload.aud
      if (
        !Array.isArray(audiences) ||
        audiences.length === 0 ||
        audiences.some(
          (audience) => typeof audience !== 'string' || !audience,
        ) ||
        new Set(audiences).size !== audiences.length ||
        !audiences.includes(this.config.client_id) ||
        typeof payload.sub !== 'string' ||
        !payload.sub
      ) {
        throw new Error('invalid OIDC subject or audience claims')
      }
      if (
        (audiences.length > 1 && payload.azp !== this.config.client_id) ||
        (payload.azp !== undefined && payload.azp !== this.config.client_id)
      ) {
        throw new Error('invalid OIDC authorized party claim')
      }
      if (
        (requireNonce && payload.nonce !== expectedNonce) ||
        (!requireNonce &&
          payload.nonce !== undefined &&
          payload.nonce !== expectedNonce)
      ) {
        throw new Error('invalid OIDC nonce claim')
      }
    } catch (cause) {
      throw new Error('OIDC ID token signature or claims validation failed', {
        cause,
      })
    }
  }

  private resolver(): Promise<RemoteJWKSet> {
    if (!this.resolverPromise) {
      this.resolverPromise = this.buildResolver().catch((error: unknown) => {
        this.resolverPromise = null
        throw error
      })
    }
    return this.resolverPromise
  }

  private async buildResolver(): Promise<RemoteJWKSet> {
    const response = await this.fetcher(this.config.discovery_endpoint, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    })
    if (
      !response.ok ||
      !responseStayedAt(response, this.config.discovery_endpoint)
    ) {
      throw new Error(`OIDC discovery failed (${response.status})`)
    }
    const metadata = parseProviderMetadata(await response.json())
    if (
      metadata.issuer !== this.config.issuer ||
      metadata.authorization_endpoint !== this.config.authorization_endpoint ||
      metadata.token_endpoint !== this.config.token_endpoint ||
      metadata.jwks_uri !== this.config.jwks_uri ||
      (this.config.end_session_endpoint !== null &&
        metadata.end_session_endpoint !== this.config.end_session_endpoint) ||
      !metadata.response_types_supported.includes('code') ||
      !metadata.scopes_supported.includes('openid') ||
      !metadata.code_challenge_methods_supported.includes('S256') ||
      !metadata.token_endpoint_auth_methods_supported.includes('none') ||
      this.config.id_token_signing_algorithms.some(
        (algorithm) =>
          !metadata.id_token_signing_alg_values_supported.includes(algorithm),
      )
    ) {
      throw new Error(
        'OIDC discovery document does not match the trusted runtime configuration',
      )
    }

    const expectedJwksUrl = new URL(this.config.jwks_uri).toString()
    return createRemoteJWKSet(new URL(expectedJwksUrl), {
      timeoutDuration: 5_000,
      cooldownDuration: 0,
      cacheMaxAge: 5 * 60 * 1000,
      [customFetch]: async (url, options) => {
        if (new URL(url).toString() !== expectedJwksUrl) {
          throw new Error('OIDC JWKS request escaped the trusted URI')
        }
        const jwksResponse = await this.fetcher(url, {
          ...options,
          credentials: 'omit',
          cache: 'no-store',
          referrerPolicy: 'no-referrer',
        })
        if (
          !jwksResponse.ok ||
          !responseStayedAt(jwksResponse, expectedJwksUrl)
        ) {
          throw new Error(`OIDC JWKS request failed (${jwksResponse.status})`)
        }
        return jwksResponse
      },
    })
  }
}

function parseStored<T>(storage: Storage, key: string): T | null {
  const raw = storage.getItem(key)
  if (!raw) return null
  try {
    return JSON.parse(raw) as T
  } catch {
    storage.removeItem(key)
    return null
  }
}

export async function loadAuthConfig(
  fetcher: typeof fetch = fetch,
): Promise<AuthConfig> {
  const response = await fetcher('/api/v1/auth/config', {
    headers: { Accept: 'application/json' },
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
  })
  if (!response.ok)
    throw new Error(`Authentication configuration failed (${response.status})`)
  const value = (await response.json()) as Record<string, unknown>
  if (value.mode === 'development') return { mode: 'development' }
  if (value.mode !== 'oidc_pkce')
    throw new Error('Unsupported authentication mode')
  const config: OidcAuthConfig = {
    mode: 'oidc_pkce',
    issuer: requireHttpsUrl(value.issuer, 'issuer', true),
    audience: requireString(value.audience, 'audience'),
    client_id: requireString(value.client_id, 'client ID'),
    discovery_endpoint: requireHttpsUrl(
      value.discovery_endpoint,
      'discovery endpoint',
    ),
    jwks_uri: requireHttpsUrl(value.jwks_uri, 'JWKS URI'),
    id_token_signing_algorithms: requireStringArray(
      value.id_token_signing_algorithms,
      'ID token signing algorithms',
    ) as IdTokenAlgorithm[],
    authorization_endpoint: requireHttpsUrl(
      value.authorization_endpoint,
      'authorization endpoint',
    ),
    token_endpoint: requireHttpsUrl(value.token_endpoint, 'token endpoint'),
    end_session_endpoint:
      value.end_session_endpoint === null ||
      value.end_session_endpoint === undefined
        ? null
        : requireHttpsUrl(value.end_session_endpoint, 'end session endpoint'),
    scopes: requireStringArray(value.scopes, 'scopes'),
    redirect_path: requireString(value.redirect_path, 'redirect path'),
  }
  if (
    config.audience === config.client_id ||
    !config.audience.trim() ||
    !config.client_id.trim()
  ) {
    throw new Error('OIDC API audience and human client ID must be separate')
  }
  const expectedDiscoveryEndpoint = `${config.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`
  if (config.discovery_endpoint !== expectedDiscoveryEndpoint) {
    throw new Error(
      'OIDC discovery endpoint is not canonical for the configured issuer',
    )
  }
  if (
    config.id_token_signing_algorithms.length === 0 ||
    config.id_token_signing_algorithms.some(
      (algorithm) => !SAFE_ID_TOKEN_ALGORITHMS.includes(algorithm),
    )
  ) {
    throw new Error('OIDC ID token signing algorithms are not approved')
  }
  if (!config.scopes.includes('openid'))
    throw new Error('OIDC scopes must include openid')
  if (
    !config.redirect_path.startsWith('/') ||
    config.redirect_path.startsWith('//') ||
    config.redirect_path.includes('\\') ||
    new URL(config.redirect_path, 'https://local-redirect.invalid').origin !==
      'https://local-redirect.invalid'
  ) {
    throw new Error('OIDC redirect path must be same-origin')
  }
  return config
}

export class OidcPkceClient {
  private refreshPromise: Promise<string | null> | null = null
  private readonly idTokenVerifier: OidcIdTokenVerifier

  constructor(
    readonly config: OidcAuthConfig,
    private readonly storage: Storage = sessionStorage,
    private readonly fetcher: typeof fetch = fetch,
    private readonly cryptoProvider: Crypto = crypto,
    private readonly now: () => number = Date.now,
  ) {
    this.idTokenVerifier = new OidcIdTokenVerifier(config, fetcher, now)
  }

  async authorizationUrl(origin: string, returnTo: string): Promise<string> {
    if (new URL(origin).protocol !== 'https:') {
      throw new Error('OIDC authorization requires an HTTPS application origin')
    }
    await this.idTokenVerifier.ensureProviderMetadata()
    const redirectUri = new URL(this.config.redirect_path, origin).toString()
    const pending: PendingAuthorization = {
      state: randomValue(this.cryptoProvider),
      nonce: randomValue(this.cryptoProvider),
      verifier: randomValue(this.cryptoProvider, 64),
      redirect_uri: redirectUri,
      return_to: safeReturnTo(returnTo),
      created_at: this.now(),
    }
    this.storage.setItem(PENDING_KEY, JSON.stringify(pending))
    const url = new URL(this.config.authorization_endpoint)
    url.searchParams.set('client_id', this.config.client_id)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('redirect_uri', redirectUri)
    url.searchParams.set('scope', this.config.scopes.join(' '))
    url.searchParams.set('audience', this.config.audience)
    url.searchParams.set('state', pending.state)
    url.searchParams.set('nonce', pending.nonce)
    url.searchParams.set(
      'code_challenge',
      await challenge(this.cryptoProvider, pending.verifier),
    )
    url.searchParams.set('code_challenge_method', 'S256')
    return url.toString()
  }

  async complete(callbackUrl: string): Promise<string> {
    const pending = parseStored<PendingAuthorization>(this.storage, PENDING_KEY)
    this.storage.removeItem(PENDING_KEY)
    if (!pending || this.now() - pending.created_at > MAX_PENDING_AGE_MS) {
      throw new Error('OIDC authorization request is missing or expired')
    }
    const callback = new URL(callbackUrl)
    const expectedCallback = new URL(pending.redirect_uri)
    if (
      callback.origin !== expectedCallback.origin ||
      callback.pathname !== expectedCallback.pathname ||
      callback.hash
    ) {
      throw new Error(
        'OIDC callback URL does not match the authorization request',
      )
    }
    const error = callback.searchParams.get('error')
    if (error) throw new Error(`OIDC authorization failed: ${error}`)
    if (callback.searchParams.get('state') !== pending.state) {
      throw new Error('OIDC state validation failed')
    }
    const code = callback.searchParams.get('code')
    if (!code) throw new Error('OIDC authorization code is missing')
    const response = await this.fetcher(this.config.token_endpoint, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: this.config.client_id,
        code,
        redirect_uri: pending.redirect_uri,
        code_verifier: pending.verifier,
      }),
    })
    if (!response.ok)
      throw new Error(`OIDC token exchange failed (${response.status})`)
    const session = this.tokenSession(await response.json(), pending.nonce)
    await this.idTokenVerifier.validate(session.id_token, session.nonce, true)
    this.storage.setItem(TOKEN_KEY, JSON.stringify(session))
    return pending.return_to
  }

  async accessToken(): Promise<string | null> {
    const session = parseStored<TokenSession>(this.storage, TOKEN_KEY)
    if (!session) return null
    if (session.expires_at > this.now() + 30_000) return session.access_token
    if (!session.refresh_token) {
      this.clear()
      return null
    }
    if (this.refreshPromise) return this.refreshPromise
    this.refreshPromise = this.refresh(session, session.refresh_token)
    try {
      return await this.refreshPromise
    } finally {
      this.refreshPromise = null
    }
  }

  private async refresh(
    session: TokenSession,
    refreshToken: string,
  ): Promise<string | null> {
    const response = await this.fetcher(this.config.token_endpoint, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: this.config.client_id,
        refresh_token: refreshToken,
      }),
    })
    if (!response.ok) {
      this.clear()
      return null
    }
    const refreshed = this.tokenSession(
      await response.json(),
      session.nonce,
      session,
    )
    if (refreshed.id_token !== session.id_token) {
      try {
        await this.idTokenVerifier.validate(
          refreshed.id_token,
          refreshed.nonce,
          false,
        )
      } catch (error) {
        this.clear()
        throw error
      }
    }
    this.storage.setItem(TOKEN_KEY, JSON.stringify(refreshed))
    return refreshed.access_token
  }

  hasSession(): boolean {
    return parseStored<TokenSession>(this.storage, TOKEN_KEY) !== null
  }

  logoutUrl(origin: string): string {
    const session = parseStored<TokenSession>(this.storage, TOKEN_KEY)
    this.clear()
    if (!this.config.end_session_endpoint)
      return new URL('/', origin).toString()
    const url = new URL(this.config.end_session_endpoint)
    if (session?.id_token)
      url.searchParams.set('id_token_hint', session.id_token)
    url.searchParams.set(
      'post_logout_redirect_uri',
      new URL('/', origin).toString(),
    )
    return url.toString()
  }

  clear(): void {
    this.storage.removeItem(PENDING_KEY)
    this.storage.removeItem(TOKEN_KEY)
  }

  private tokenSession(
    value: unknown,
    nonce: string,
    prior?: TokenSession,
  ): TokenSession {
    const token = value as Record<string, unknown>
    const expiresIn = Number(token.expires_in)
    if (
      token.token_type !== 'Bearer' ||
      typeof token.access_token !== 'string' ||
      !token.access_token ||
      !Number.isFinite(expiresIn) ||
      expiresIn <= 0
    ) {
      throw new Error('OIDC token response is invalid')
    }
    const idToken =
      typeof token.id_token === 'string' ? token.id_token : prior?.id_token
    if (!idToken) throw new Error('OIDC ID token is missing')
    return {
      access_token: token.access_token,
      refresh_token:
        typeof token.refresh_token === 'string'
          ? token.refresh_token
          : prior?.refresh_token,
      id_token: idToken,
      nonce,
      expires_at: this.now() + expiresIn * 1000,
      token_type: 'Bearer',
    }
  }
}
