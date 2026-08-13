<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { RouterLink, RouterView, useRoute } from 'vue-router'
import { useI18n, type Locale } from '../i18n'
import { canAccess, visibleNavigation } from '../security/navigation'
import { useSessionStore } from '../stores/session'
import ForbiddenView from '../views/ForbiddenView.vue'
const session = useSessionStore(); const route = useRoute()
const { locale, setLocale, t } = useI18n()
const items = computed(() => visibleNavigation(session.permissions))
const routeAllowed = computed(() => canAccess(route.meta.requiredAny, session.permissions))
const localeModel = computed({ get: () => locale.value, set: (value: Locale) => setLocale(value) })
onMounted(session.initialize)
</script>
<template>
  <RouterView v-if="route.name === 'auth-callback'" />
  <main v-else-if="session.loading" class="auth-page"><div class="state-card" role="status">{{ t('auth.loading') }}</div></main>
  <main v-else-if="!session.authConfig" class="auth-page" aria-labelledby="auth-error-title">
    <section class="panel">
      <h1 id="auth-error-title">{{ t('auth.unavailableTitle') }}</h1>
      <div class="state-card error" role="alert">{{ session.error || t('auth.unavailableFallback') }}</div>
      <button type="button" @click="session.initialize">{{ t('auth.retry') }}</button>
    </section>
  </main>
  <main v-else-if="session.authConfig?.mode === 'oidc_pkce' && !session.authenticated" class="auth-page" aria-labelledby="sign-in-title">
    <section class="panel">
      <p class="eyebrow">{{ t('auth.eyebrow') }}</p>
      <h1 id="sign-in-title">{{ t('auth.title') }}</h1>
      <p>{{ t('auth.description') }}</p>
      <div v-if="session.error" class="state-card error" role="alert">{{ session.error }}</div>
      <button type="button" @click="session.login(route.fullPath)">{{ t('auth.signIn') }}</button>
    </section>
  </main>
  <div v-else class="app-shell">
    <a class="skip-link" href="#main-content">{{ t('app.skip') }}</a>
    <aside>
      <div class="brand"><span aria-hidden="true">IS</span><div><strong>{{ t('app.name') }}</strong><small>{{ t('app.sandbox') }}</small></div></div>
      <nav :aria-label="t('app.primary')"><RouterLink v-for="item in items" :key="item.name" :to="{ name: item.name }" :aria-current="route.name === item.name ? 'page' : undefined">{{ t(item.labelKey) }}</RouterLink></nav>
      <div class="aside-controls">
        <label>{{ t('app.locale') }}<select v-model="localeModel"><option value="en">English</option><option value="zh-CN">简体中文</option></select></label>
        <label v-if="session.authConfig?.mode === 'development'">{{ t('app.roles') }}<select v-model="session.roleText"><option>Viewer</option><option>Engineer,Viewer</option><option>Approver,Viewer</option><option>PackAuthor,Viewer</option><option>Admin,Viewer</option><option>Auditor,Viewer</option><option>Admin,Engineer,Approver,Auditor</option></select></label>
      </div>
    </aside>
    <div class="page">
      <header class="topbar"><p><strong>{{ session.session?.workspace_id ?? t('app.connecting') }}</strong><span> · {{ t('app.boundary') }}</span></p><span class="identity">{{ session.session?.actor_id }}</span><button v-if="session.authConfig?.mode === 'oidc_pkce'" class="secondary" type="button" @click="session.logout">{{ t('auth.signOut') }}</button></header>
      <main id="main-content" tabindex="-1"><ForbiddenView v-if="!routeAllowed" /><RouterView v-else /></main>
    </div>
  </div>
</template>
