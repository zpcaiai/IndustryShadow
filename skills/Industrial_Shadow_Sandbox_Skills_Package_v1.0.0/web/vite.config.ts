import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [vue()],
  server: {
    host: '127.0.0.1',
    proxy: { '/api': 'http://127.0.0.1:8000' },
  },
  build: {
    sourcemap: process.env.SHADOW_WEB_SOURCEMAPS === 'true',
    target: 'es2022',
  },
  test: {
    environment: 'node',
    clearMocks: true,
    include: ['tests/**/*.test.ts'],
    testTimeout: 15_000,
  },
})
