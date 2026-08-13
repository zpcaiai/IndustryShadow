<script setup lang="ts">
import { RouterLink } from 'vue-router'
import { useI18n } from '../i18n'
const { t } = useI18n()
</script>
<template>
  <section class="panel forbidden" role="alert" aria-labelledby="forbidden-title">
    <p class="eyebrow">{{ t('forbidden.eyebrow') }}</p>
    <h1 id="forbidden-title" tabindex="-1">{{ t('forbidden.title') }}</h1>
    <p>{{ t('forbidden.description') }}</p>
    <RouterLink class="button-link" :to="{ name: 'home' }">{{ t('forbidden.home') }}</RouterLink>
  </section>
</template>
