import { assertApiRoute, type ApiMethod, type ApiPath, type GetPath, type PatchPath, type PostPath } from './generated-contract'

export type Problem = { code: string; detail: string; status: number; context?: Record<string, unknown> }

export class ApiError extends Error {
  constructor(public readonly problem: Problem) { super(problem.detail) }
}

export type IdentityHeaders = { actorId: string; tenantId: string; workspaceId: string; roles: string[] }
let identity: IdentityHeaders = { actorId: 'dev-engineer', tenantId: 'dev-tenant', workspaceId: 'dev-workspace', roles: ['Engineer', 'Viewer'] }
let authenticationMode: 'development' | 'oidc_pkce' = 'development'
let tokenProvider: () => Promise<string | null> = async () => null
export function setIdentity(value: IdentityHeaders) { identity = value }
export function configureApiAuthentication(
  mode: 'development' | 'oidc_pkce',
  provider: () => Promise<string | null> = async () => null,
) {
  authenticationMode = mode
  tokenProvider = provider
}

export function isSha256Digest(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value) && value !== '0'.repeat(64)
}

async function request<T>(path: ApiPath, options: RequestInit & { idempotencyKey?: string; version?: number } = {}): Promise<T> {
  const method = String(options.method ?? 'GET').toUpperCase() as ApiMethod
  assertApiRoute(method, path)
  const headers = new Headers(options.headers)
  headers.set('Accept', 'application/json')
  if (authenticationMode === 'oidc_pkce') {
    const token = await tokenProvider()
    if (!token) {
      throw new ApiError({ code: 'AUTHENTICATION_REQUIRED', detail: 'Sign in is required', status: 401 })
    }
    headers.set('Authorization', `Bearer ${token}`)
    headers.delete('X-Actor-Id'); headers.delete('X-Tenant-Id')
    headers.delete('X-Workspace-Id'); headers.delete('X-Roles')
  } else {
    headers.set('X-Actor-Id', identity.actorId)
    headers.set('X-Tenant-Id', identity.tenantId); headers.set('X-Workspace-Id', identity.workspaceId)
    headers.set('X-Roles', identity.roles.join(','))
  }
  if (options.body) headers.set('Content-Type', 'application/json')
  if (options.idempotencyKey) headers.set('Idempotency-Key', options.idempotencyKey)
  if (options.version !== undefined) headers.set('If-Match', String(options.version))
  const response = await fetch(`/api/v1${path}`, { ...options, headers })
  const contentType = response.headers.get('content-type') ?? ''
  const value = contentType.includes('json') ? await response.json() : await response.text()
  if (!response.ok) throw new ApiError(typeof value === 'object' && value?.code ? value as Problem : { code: `HTTP_${response.status}`, detail: String(value), status: response.status })
  return value as T
}

export function api<T>(path: GetPath): Promise<T> {
  return request<T>(path)
}

export function post<T>(path: PostPath, body: unknown, idempotencyKey?: string) {
  return request<T>(path, { method: 'POST', body: JSON.stringify(body), idempotencyKey })
}
export function patch<T>(path: PatchPath, body: unknown, version: number) {
  return request<T>(path, { method: 'PATCH', body: JSON.stringify(body), version })
}
