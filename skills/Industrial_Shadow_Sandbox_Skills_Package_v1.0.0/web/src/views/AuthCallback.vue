<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useSessionStore } from '../stores/session'

const session = useSessionStore()
const router = useRouter()
const error = ref('')

onMounted(async () => {
  try {
    const returnTo = await session.finishLogin(window.location.href)
    await router.replace(returnTo)
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason)
  }
})
</script>

<template>
  <main class="auth-page" aria-labelledby="auth-title">
    <section class="panel">
      <h1 id="auth-title">Completing secure sign-in</h1>
      <p v-if="!error" role="status">Validating the OIDC response and loading your workspace…</p>
      <div v-else class="state-card error" role="alert">{{ error }}</div>
    </section>
  </main>
</template>
