import { describe, expect, it, vi } from 'vitest'

import { loadAuthConfig, OidcPkceClient, type OidcAuthConfig } from '../src/auth/oidc'

class MemoryStorage implements Storage {
  private readonly data = new Map<string, string>()
  get length() { return this.data.size }
  clear() { this.data.clear() }
  getItem(key: string) { return this.data.get(key) ?? null }
  key(index: number) { return [...this.data.keys()][index] ?? null }
  removeItem(key: string) { this.data.delete(key) }
  setItem(key: string, value: string) { this.data.set(key, value) }
  values() { return [...this.data.values()] }
}

const config: OidcAuthConfig = {
  mode: 'oidc_pkce',
  issuer: 'https://identity.example.test/tenant',
  audience: 'industrial-shadow',
  client_id: 'industrial-shadow-web',
  authorization_endpoint: 'https://identity.example.test/tenant/authorize',
  token_endpoint: 'https://identity.example.test/tenant/token',
  end_session_endpoint: 'https://identity.example.test/tenant/logout',
  scopes: ['openid', 'profile'],
  redirect_path: '/auth/callback',
}

function jwt(payload: Record<string, unknown>): string {
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url')
  return `${encode({ alg: 'RS256', kid: 'test' })}.${encode(payload)}.signature`
}

describe('OIDC Authorization Code + PKCE client', () => {
  it('loads and validates the public runtime configuration', async () => {
    const fetcher = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(config), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
    await expect(loadAuthConfig(fetcher)).resolves.toEqual(config)
    expect(fetcher).toHaveBeenCalledWith('/api/v1/auth/config', expect.objectContaining({ credentials: 'same-origin' }))
  })

  it('rejects insecure logout endpoints and cross-origin redirect paths', async () => {
    for (const override of [
      { end_session_endpoint: 'http://identity.example.test/logout' },
      { redirect_path: 'https://attacker.example/callback' },
    ]) {
      const fetcher = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ ...config, ...override }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      await expect(loadAuthConfig(fetcher)).rejects.toThrow(/HTTPS|same-origin/)
    }
  })

  it('binds state, nonce, PKCE verifier, token claims, refresh, and logout', async () => {
    const storage = new MemoryStorage()
    let now = 1_800_000_000_000
    const fetcher = vi.fn()
    const client = new OidcPkceClient(config, storage, fetcher, globalThis.crypto, () => now)
    const authorize = new URL(await client.authorizationUrl('https://shadow.example.test', '/runs'))
    expect(authorize.searchParams.get('response_type')).toBe('code')
    expect(authorize.searchParams.get('code_challenge_method')).toBe('S256')
    expect(authorize.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/)
    const pending = JSON.parse(storage.values()[0]) as { state: string; nonce: string }
    const idToken = jwt({
      iss: config.issuer,
      aud: config.client_id,
      nonce: pending.nonce,
      exp: now / 1000 + 3600,
    })
    fetcher.mockResolvedValueOnce(
      new Response(JSON.stringify({
        token_type: 'Bearer', access_token: 'access-1', refresh_token: 'refresh-1',
        id_token: idToken, expires_in: 60,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
    await expect(
      client.complete(`https://shadow.example.test/auth/callback?code=code-1&state=${pending.state}`),
    ).resolves.toBe('/runs')
    await expect(client.accessToken()).resolves.toBe('access-1')
    now += 61_000
    fetcher.mockResolvedValueOnce(
      new Response(JSON.stringify({ token_type: 'Bearer', access_token: 'access-2', expires_in: 60 }), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      }),
    )
    const refreshes = await Promise.all([client.accessToken(), client.accessToken()])
    expect(refreshes).toEqual(['access-2', 'access-2'])
    expect(fetcher).toHaveBeenCalledTimes(2)
    const logout = new URL(client.logoutUrl('https://shadow.example.test'))
    expect(logout.origin + logout.pathname).toBe(config.end_session_endpoint)
    expect(logout.searchParams.get('id_token_hint')).toBe(idToken)
    expect(client.hasSession()).toBe(false)
  })

  it('fails closed on state mismatch', async () => {
    const storage = new MemoryStorage()
    const fetcher = vi.fn()
    const client = new OidcPkceClient(config, storage, fetcher, globalThis.crypto)
    await client.authorizationUrl('https://shadow.example.test', '//attacker.example')
    await expect(
      client.complete('https://shadow.example.test/auth/callback?code=code-1&state=wrong'),
    ).rejects.toThrow('state validation failed')
    expect(fetcher).not.toHaveBeenCalled()
    expect(client.hasSession()).toBe(false)
  })

  it('normalizes an external return target to the application root', async () => {
    const storage = new MemoryStorage()
    const now = 1_800_000_000_000
    const fetcher = vi.fn()
    const client = new OidcPkceClient(config, storage, fetcher, globalThis.crypto, () => now)
    await client.authorizationUrl('https://shadow.example.test', '//attacker.example')
    const pending = JSON.parse(storage.values()[0]) as { state: string; nonce: string }
    fetcher.mockResolvedValueOnce(
      new Response(JSON.stringify({
        token_type: 'Bearer',
        access_token: 'access-safe-return',
        id_token: jwt({
          iss: config.issuer,
          aud: config.client_id,
          nonce: pending.nonce,
          exp: now / 1000 + 3600,
        }),
        expires_in: 60,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
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
      const fetcher = vi.fn()
      const client = new OidcPkceClient(config, storage, fetcher, globalThis.crypto)
      await client.authorizationUrl('https://shadow.example.test', '/')
      const pending = JSON.parse(storage.values()[0]) as { state: string }
      await expect(
        client.complete(`${callback}?code=code-1&state=${pending.state}`),
      ).rejects.toThrow('callback URL does not match')
      expect(fetcher).not.toHaveBeenCalled()
    }
  })
})
