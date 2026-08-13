<script setup lang="ts">
import { ref } from 'vue'

import { api, isSha256Digest, post } from '../../api/client'
import AsyncState from '../../components/AsyncState.vue'

const id = ref('')
const bundleDigest = ref('')
const data = ref<unknown>()
const error = ref('')
const loading = ref(false)

async function load() {
  loading.value = true
  error.value = ''
  try {
    data.value = await api(`/evaluations/${id.value}`)
  } catch (caught) {
    error.value = caught instanceof Error ? caught.message : String(caught)
  } finally {
    loading.value = false
  }
}

async function gate() {
  error.value = ''
  if (!isSha256Digest(bundleDigest.value)) {
    error.value = 'Enter the non-placeholder lowercase SHA-256 digest of the exact release bundle.'
    return
  }
  loading.value = true
  try {
    data.value = await post('/release-gates/evaluate', {
      evaluation_id: id.value,
      bundle_digest: bundleDigest.value,
    })
  } catch (caught) {
    error.value = caught instanceof Error ? caught.message : String(caught)
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <section class="panel">
    <div class="panel-head">
      <div>
        <h2>Certification metrics</h2>
        <p>Corpus coverage, slices, thresholds, red lines, and promotion binding.</p>
      </div>
      <div class="inline">
        <input v-model="id" placeholder="evaluation_id">
        <input v-model="bundleDigest" placeholder="exact bundle SHA-256">
        <button @click="load">Open</button>
        <button class="secondary" @click="gate">Evaluate Gate</button>
      </div>
    </div>
    <AsyncState :loading="loading" :error="error" :empty="!data">
      <pre>{{ data }}</pre>
    </AsyncState>
  </section>
</template>
