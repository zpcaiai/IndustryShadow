export type DevelopmentAuthConfig = { mode: 'development' }

export type OidcAuthConfig = {
  mode: 'oidc_pkce'
  issuer: string
  audience: string
  client_id: string
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

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const value of bytes) binary += String.fromCharCode(value)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function decodeBase64Url(value: string): string {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
  return atob(padded)
}

function randomValue(cryptoProvider: Crypto, size = 32): string {
  const bytes = new Uint8Array(size)
  cryptoProvider.getRandomValues(bytes)
  return encodeBase64Url(bytes)
}

async function challenge(cryptoProvider: Crypto, verifier: string): Promise<string> {
  const digest = await cryptoProvider.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return encodeBase64Url(new Uint8Array(digest))
}

function safeReturnTo(value: string): string {
  const base = new URL('https://local-return.invalid/')
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return '/'
  const parsed = new URL(value, base)
  return parsed.origin === base.origin ? `${parsed.pathname}${parsed.search}${parsed.hash}` : '/'
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`OIDC ${field} is invalid`)
  return value
}

function parseIdToken(token: string): Record<string, unknown> {
  const parts = token.split('.')
  if (parts.length !== 3) throw new Error('OIDC ID token is malformed')
  try {
    return JSON.parse(decodeBase64Url(parts[1])) as Record<string, unknown>
  } catch {
    throw new Error('OIDC ID token payload is invalid')
  }
}

function validateIdTokenClaims(
  token: string,
  config: OidcAuthConfig,
  expectedNonce: string,
  now: number,
  requireNonce: boolean,
): void {
  const claims = parseIdToken(token)
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
  const nonceMatches = requireNonce
    ? claims.nonce === expectedNonce
    : claims.nonce === undefined || claims.nonce === expectedNonce
  if (
    !nonceMatches ||
    claims.iss !== config.issuer ||
    !audience.includes(config.client_id) ||
    typeof claims.exp !== 'number' ||
    claims.exp * 1000 <= now
  ) {
    throw new Error('OIDC ID token claims do not match the authorization request')
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

export async function loadAuthConfig(fetcher: typeof fetch = fetch): Promise<AuthConfig> {
  const response = await fetcher('/api/v1/auth/config', {
    headers: { Accept: 'application/json' },
    credentials: 'same-origin',
  })
  if (!response.ok) throw new Error(`Authentication configuration failed (${response.status})`)
  const value = (await response.json()) as Record<string, unknown>
  if (value.mode === 'development') return { mode: 'development' }
  if (value.mode !== 'oidc_pkce') throw new Error('Unsupported authentication mode')
  const config: OidcAuthConfig = {
    mode: 'oidc_pkce',
    issuer: requireString(value.issuer, 'issuer'),
    audience: requireString(value.audience, 'audience'),
    client_id: requireString(value.client_id, 'client ID'),
    authorization_endpoint: requireString(value.authorization_endpoint, 'authorization endpoint'),
    token_endpoint: requireString(value.token_endpoint, 'token endpoint'),
    end_session_endpoint:
      typeof value.end_session_endpoint === 'string' ? value.end_session_endpoint : null,
    scopes: Array.isArray(value.scopes) ? value.scopes.map(String) : [],
    redirect_path: requireString(value.redirect_path, 'redirect path'),
  }
  for (const endpoint of [
    config.issuer,
    config.authorization_endpoint,
    config.token_endpoint,
    ...(config.end_session_endpoint ? [config.end_session_endpoint] : []),
  ]) {
    if (new URL(endpoint).protocol !== 'https:') throw new Error('OIDC endpoints must use HTTPS')
  }
  if (!config.scopes.includes('openid')) throw new Error('OIDC scopes must include openid')
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

  constructor(
    readonly config: OidcAuthConfig,
    private readonly storage: Storage = sessionStorage,
    private readonly fetcher: typeof fetch = fetch,
    private readonly cryptoProvider: Crypto = crypto,
    private readonly now: () => number = Date.now,
  ) {}

  async authorizationUrl(origin: string, returnTo: string): Promise<string> {
    if (new URL(origin).protocol !== 'https:') {
      throw new Error('OIDC authorization requires an HTTPS application origin')
    }
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
    url.searchParams.set('code_challenge', await challenge(this.cryptoProvider, pending.verifier))
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
      throw new Error('OIDC callback URL does not match the authorization request')
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
      headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: this.config.client_id,
        code,
        redirect_uri: pending.redirect_uri,
        code_verifier: pending.verifier,
      }),
    })
    if (!response.ok) throw new Error(`OIDC token exchange failed (${response.status})`)
    const session = this.tokenSession(await response.json(), pending.nonce)
    validateIdTokenClaims(session.id_token, this.config, session.nonce, this.now(), true)
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

  private async refresh(session: TokenSession, refreshToken: string): Promise<string | null> {
    const response = await this.fetcher(this.config.token_endpoint, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
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
    const refreshed = this.tokenSession(await response.json(), session.nonce, session)
    if (refreshed.id_token !== session.id_token) {
      validateIdTokenClaims(
        refreshed.id_token,
        this.config,
        refreshed.nonce,
        this.now(),
        false,
      )
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
    if (!this.config.end_session_endpoint) return new URL('/', origin).toString()
    const url = new URL(this.config.end_session_endpoint)
    if (session?.id_token) url.searchParams.set('id_token_hint', session.id_token)
    url.searchParams.set('post_logout_redirect_uri', new URL('/', origin).toString())
    return url.toString()
  }

  clear(): void {
    this.storage.removeItem(PENDING_KEY)
    this.storage.removeItem(TOKEN_KEY)
  }

  private tokenSession(value: unknown, nonce: string, prior?: TokenSession): TokenSession {
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
    const idToken = typeof token.id_token === 'string' ? token.id_token : prior?.id_token
    if (!idToken) throw new Error('OIDC ID token is missing')
    return {
      access_token: token.access_token,
      refresh_token:
        typeof token.refresh_token === 'string' ? token.refresh_token : prior?.refresh_token,
      id_token: idToken,
      nonce,
      expires_at: this.now() + expiresIn * 1000,
      token_type: 'Bearer',
    }
  }
}
