import { existsSync } from 'node:fs'
import { defineConfig, devices } from '@playwright/test'

const systemChrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const executablePath = process.env.SHADOW_E2E_EXECUTABLE ??
  (existsSync(systemChrome) ? systemChrome : undefined)
const port = Number(process.env.SHADOW_E2E_PORT ?? '41873')
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('SHADOW_E2E_PORT is invalid')
const productionBaseURL = process.env.SHADOW_E2E_PRODUCTION_URL?.replace(/\/+$/, '')
if (productionBaseURL) {
  const target = new URL(productionBaseURL)
  if (target.protocol !== 'https:' || target.username || target.password || target.search || target.hash)
    throw new Error('SHADOW_E2E_PRODUCTION_URL must be a credential-free HTTPS origin')
}
const baseURL = productionBaseURL ?? `http://127.0.0.1:${port}`

// Local readiness checks must never be sent through a workstation or CI proxy.
// Preserve caller exclusions while making the loopback behavior deterministic.
for (const name of ['NO_PROXY', 'no_proxy'] as const) {
  const entries = new Set(
    (process.env[name] ?? '').split(',').map((entry) => entry.trim()).filter(Boolean),
  )
  entries.add('127.0.0.1')
  entries.add('localhost')
  process.env[name] = [...entries].join(',')
}

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: true,
  retries: 1,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  outputDir: 'test-results/artifacts',
  reporter: [['list'], ['json', { outputFile: 'test-results/playwright.json' }]],
  use: {
    ...devices['Desktop Chrome'],
    baseURL,
    trace: productionBaseURL ? 'off' : 'retain-on-failure',
    screenshot: productionBaseURL ? 'off' : 'only-on-failure',
    video: productionBaseURL ? 'off' : 'retain-on-failure',
    launchOptions: { executablePath },
  },
  webServer: productionBaseURL ? undefined : {
    command: `npm run dev -- --port ${port} --strictPort`,
    url: baseURL,
    env: { ...process.env },
    reuseExistingServer: false,
    timeout: 60_000,
  },
})
