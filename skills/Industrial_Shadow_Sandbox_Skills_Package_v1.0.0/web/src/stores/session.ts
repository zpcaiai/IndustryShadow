import { computed, ref, watch } from 'vue'
import { defineStore } from 'pinia'
import { api, configureApiAuthentication, setIdentity } from '../api/client'
import { loadAuthConfig, OidcPkceClient, type AuthConfig } from '../auth/oidc'

export type Session = { actor_id: string; tenant_id: string; workspace_id: string; roles: string[]; permissions: string[] }

export const useSessionStore = defineStore('session', () => {
  const session = ref<Session | null>(null); const loading = ref(false); const error = ref('')
  const roleText = ref('Engineer,Viewer')
  const authConfig = ref<AuthConfig | null>(null)
  const authenticated = computed(() => session.value !== null)
  let oidc: OidcPkceClient | null = null
  const permissions = computed(() => new Set(session.value?.permissions ?? []))
  const isAdmin = computed(() => session.value?.roles.includes('Admin') ?? false)
  async function loadSession() {
    loading.value = true; error.value = ''
    try { session.value = await api<Session>('/me') }
    catch (reason) {
      session.value = null
      error.value = reason instanceof Error ? reason.message : String(reason)
    }
    finally { loading.value = false }
  }
  function setDevelopmentIdentity() {
    setIdentity({ actorId: 'dev-user', tenantId: 'dev-tenant', workspaceId: 'dev-workspace', roles: roleText.value.split(',').map((item) => item.trim()).filter(Boolean) })
  }
  async function initialize() {
    loading.value = true; error.value = ''
    try {
      authConfig.value = await loadAuthConfig()
      if (authConfig.value.mode === 'development') {
        configureApiAuthentication('development')
        setDevelopmentIdentity()
        await loadSession()
        return
      }
      oidc = new OidcPkceClient(authConfig.value)
      configureApiAuthentication('oidc_pkce', () => oidc?.accessToken() ?? Promise.resolve(null))
      if (oidc.hasSession()) await loadSession()
    } catch (reason) {
      error.value = reason instanceof Error ? reason.message : String(reason)
    } finally { loading.value = false }
  }
  async function login(returnTo = '/') {
    if (!oidc || authConfig.value?.mode !== 'oidc_pkce') return
    window.location.assign(await oidc.authorizationUrl(window.location.origin, returnTo))
  }
  async function finishLogin(callbackUrl: string): Promise<string> {
    if (!oidc) {
      authConfig.value = await loadAuthConfig()
      if (authConfig.value.mode !== 'oidc_pkce') throw new Error('OIDC is not enabled')
      oidc = new OidcPkceClient(authConfig.value)
    }
    const returnTo = await oidc.complete(callbackUrl)
    configureApiAuthentication('oidc_pkce', () => oidc?.accessToken() ?? Promise.resolve(null))
    await loadSession()
    return returnTo
  }
  function logout() {
    session.value = null
    if (oidc) window.location.assign(oidc.logoutUrl(window.location.origin))
    else configureApiAuthentication('oidc_pkce')
  }
  watch(roleText, async () => {
    if (authConfig.value?.mode === 'development') {
      setDevelopmentIdentity()
      await loadSession()
    }
  })
  return { session, loading, error, roleText, authConfig, authenticated, permissions, isAdmin, initialize, login, finishLogin, logout }
})
