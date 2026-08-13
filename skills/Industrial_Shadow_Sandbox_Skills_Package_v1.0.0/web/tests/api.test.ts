import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError, api, configureApiAuthentication, isSha256Digest, setIdentity } from '../src/api/client'

describe('API client', () => {
  afterEach(() => {
    configureApiAuthentication('development')
    vi.unstubAllGlobals()
  })

  it('binds trusted workspace headers and parses JSON', async () => {
    setIdentity({ actorId: 'actor', tenantId: 'tenant', workspaceId: 'workspace', roles: ['Viewer'] })
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: 'ready' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(api<{ status: string }>('/health/ready')).resolves.toEqual({ status: 'ready' })
    const request = fetchMock.mock.calls[0][1] as RequestInit
    const headers = request.headers as Headers
    expect(headers.get('X-Workspace-Id')).toBe('workspace')
    expect(headers.get('X-Roles')).toBe('Viewer')
  })

  it('raises the stable problem contract', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ code: 'DATABASE_UNAVAILABLE', detail: 'not ready', status: 503 }), {
          status: 503,
          headers: { 'Content-Type': 'application/problem+json' },
        }),
      ),
    )
    await expect(api('/health/ready')).rejects.toMatchObject({ message: 'not ready' } satisfies Partial<ApiError>)
  })

  it('sends only the bearer token in production authentication mode', async () => {
    configureApiAuthentication('oidc_pkce', async () => 'signed-access-token')
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ actor_id: 'engineer' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    await api('/me')
    const headers = fetchMock.mock.calls[0][1].headers as Headers
    expect(headers.get('Authorization')).toBe('Bearer signed-access-token')
    expect(headers.has('X-Actor-Id')).toBe(false)
    expect(headers.has('X-Workspace-Id')).toBe(false)
    expect(headers.has('X-Roles')).toBe(false)
  })

  it('fails before the request when an OIDC session is missing', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    configureApiAuthentication('oidc_pkce', async () => null)
    await expect(api('/me')).rejects.toMatchObject({
      problem: { code: 'AUTHENTICATION_REQUIRED', status: 401 },
    })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('accepts only non-placeholder lowercase SHA-256 bundle digests', () => {
    expect(isSha256Digest('a'.repeat(64))).toBe(true)
    expect(isSha256Digest('0'.repeat(64))).toBe(false)
    expect(isSha256Digest('A'.repeat(64))).toBe(false)
    expect(isSha256Digest('not-a-digest')).toBe(false)
  })
})
