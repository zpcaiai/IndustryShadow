import { createHash } from 'node:crypto'
import { linkSync, mkdirSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, test, type Page } from '@playwright/test'
import { readPrivateJsonObject } from './secure-private-json'

const PERSONA_ROLES = {
  viewer: 'Viewer',
  engineer: 'Engineer',
  approver: 'Approver',
  pack_author: 'PackAuthor',
  admin: 'Admin',
  auditor: 'Auditor',
} as const

type Persona = keyof typeof PERSONA_ROLES
type LoginStep = {
  action: 'fill' | 'click'
  selector: string
  value?: 'username' | 'password'
}
type PersonaSecret = { username: string; password: string }
type BrowserSecrets = {
  schema_version: 1
  issuer_origin: string
  sign_in_name: string
  sign_out_name: string
  login_steps: LoginStep[]
  logout_steps: LoginStep[]
  personas: Record<Persona, PersonaSecret>
}
type JourneyBinding = {
  acceptance_run_id: string
  release_digest: string
  candidate_image_digest: string
  web_candidate_image_digest: string
  build_digest: string
  simulator_build_digest: string
  environment_digest: string
  deployment_plan_digest: string
}

const productionURL = process.env.SHADOW_E2E_PRODUCTION_URL?.replace(/\/+$/, '')
const secretsPath = process.env.SHADOW_OIDC_BROWSER_SECRETS_FILE
const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const DIGEST = /^[a-f0-9]{64}$/
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/
test.skip(!productionURL || !secretsPath, 'real production OIDC inputs are not configured')

function exactKeys(value: object, expected: string[]): boolean {
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort())
}

function requiredEnvironment(name: string): string {
  const value = process.env[name]
  if (!value) throw new Error(`${name} is required for the production OIDC journey`)
  return value
}

function exactDigest(name: string): string {
  const value = requiredEnvironment(name)
  if (!DIGEST.test(value) || value === '0'.repeat(64))
    throw new Error(`${name} must be a non-zero SHA-256 digest`)
  return value
}

function immutableImageDigest(name: string): string {
  const value = requiredEnvironment(name)
  const match = /^[^@\s]+@sha256:([a-f0-9]{64})$/.exec(value)
  if (!match || match[1] === '0'.repeat(64))
    throw new Error(`${name} must be an immutable non-zero image digest`)
  return match[1]
}

function canonicalJson(value: Record<string, string>): string {
  return JSON.stringify(
    Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]])),
  )
}

function journeyBinding(): JourneyBinding {
  const acceptanceRunId = requiredEnvironment('SHADOW_ACCEPTANCE_RUN_ID')
  if (!RUN_ID.test(acceptanceRunId)) throw new Error('acceptance run ID is invalid')
  const coordinates = {
    candidate_image: requiredEnvironment('SHADOW_CANDIDATE_IMAGE'),
    build_digest: exactDigest('SHADOW_BUILD_DIGEST'),
    simulator_build_digest: exactDigest('SHADOW_SIMULATOR_BUILD_DIGEST'),
    environment_digest: exactDigest('SHADOW_PRODUCTION_ENVIRONMENT_DIGEST'),
    deployment_plan_digest: exactDigest('SHADOW_DEPLOYMENT_PLAN_DIGEST'),
  }
  return {
    acceptance_run_id: acceptanceRunId,
    release_digest: createHash('sha256').update(canonicalJson(coordinates)).digest('hex'),
    candidate_image_digest: immutableImageDigest('SHADOW_CANDIDATE_IMAGE'),
    web_candidate_image_digest: immutableImageDigest('SHADOW_WEB_CANDIDATE_IMAGE'),
    build_digest: coordinates.build_digest,
    simulator_build_digest: coordinates.simulator_build_digest,
    environment_digest: coordinates.environment_digest,
    deployment_plan_digest: coordinates.deployment_plan_digest,
  }
}

function journeyOutput(binding: JourneyBinding): string {
  const configured = requiredEnvironment('SHADOW_OIDC_BROWSER_JOURNEY')
  const expected = `web/test-results/production-oidc-journey-${binding.acceptance_run_id}.json`
  if (configured !== expected) throw new Error('OIDC journey output is not run-attempt bound')
  return resolve(PACKAGE_ROOT, configured)
}

function loadSecrets(pathValue: string): BrowserSecrets {
  const value = readPrivateJsonObject<BrowserSecrets>(resolve(PACKAGE_ROOT, pathValue))
  if (
    !value ||
    !exactKeys(value, [
      'schema_version',
      'issuer_origin',
      'sign_in_name',
      'sign_out_name',
      'login_steps',
      'logout_steps',
      'personas',
    ]) ||
    value.schema_version !== 1 ||
    new URL(value.issuer_origin).origin !== value.issuer_origin ||
    !value.sign_in_name.trim() ||
    !value.sign_out_name.trim() ||
    !exactKeys(value.personas, Object.keys(PERSONA_ROLES))
  ) throw new Error('OIDC browser secrets contract is invalid')
  for (const identity of Object.keys(PERSONA_ROLES) as Persona[]) {
    const persona = value.personas[identity]
    if (
      !exactKeys(persona, ['username', 'password']) ||
      !persona.username.trim() ||
      !persona.password
    ) throw new Error(`OIDC browser persona ${identity} is invalid`)
  }
  for (const step of [...value.login_steps, ...value.logout_steps]) {
    if (
      !exactKeys(step, step.action === 'fill' ? ['action', 'selector', 'value'] : ['action', 'selector']) ||
      !step.selector.trim() ||
      (step.action === 'fill' && !['username', 'password'].includes(String(step.value)))
    ) throw new Error('OIDC browser login step is invalid')
  }
  if (!value.login_steps.some((step) => step.value === 'username') ||
      !value.login_steps.some((step) => step.value === 'password'))
    throw new Error('OIDC browser journey must fill both username and password')
  return value
}

async function executeSteps(page: Page, steps: LoginStep[], secret: PersonaSecret): Promise<void> {
  for (const step of steps) {
    const target = page.locator(step.selector)
    await expect(target).toBeVisible()
    if (step.action === 'click') await target.click()
    else await target.fill(secret[step.value as 'username' | 'password'])
  }
}

test('six personas complete signed S256 PKCE login, API use, and logout', async ({ browser, request }) => {
  if (!productionURL || !secretsPath) throw new Error('production OIDC configuration is absent')
  const binding = journeyBinding()
  const output = journeyOutput(binding)
  const productionOrigin = new URL(productionURL).origin
  if (new URL(productionURL).protocol !== 'https:') throw new Error('production web URL must use HTTPS')
  const secrets = loadSecrets(secretsPath)
  const authResponse = await request.get(`${productionURL}/api/v1/auth/config`, { maxRedirects: 0 })
  expect(authResponse.status()).toBe(200)
  const auth = await authResponse.json() as Record<string, unknown>
  expect(auth.mode).toBe('oidc_pkce')
  const issuer = String(auth.issuer)
  const clientId = String(auth.client_id)
  const authorizationEndpoint = String(auth.authorization_endpoint)
  const tokenEndpoint = String(auth.token_endpoint)
  const endSessionEndpoint = String(auth.end_session_endpoint)
  const discoveryEndpoint = String(auth.discovery_endpoint)
  const jwksUri = String(auth.jwks_uri)
  expect(new URL(issuer).origin).toBe(secrets.issuer_origin)
  expect(clientId).not.toHaveLength(0)
  for (const endpoint of [authorizationEndpoint, tokenEndpoint, endSessionEndpoint, discoveryEndpoint, jwksUri])
    expect(new URL(endpoint).protocol).toBe('https:')

  const startedAt = new Date().toISOString()
  let safeProtocolRequests = true
  for (const identity of Object.keys(PERSONA_ROLES) as Persona[]) {
    const context = await browser.newContext()
    const page = await context.newPage()
    page.on('response', (response) => {
      if ([tokenEndpoint, discoveryEndpoint, jwksUri].includes(response.url()) && response.status() >= 300)
        safeProtocolRequests = false
    })
    const authorizationRequest = page.waitForRequest((request) => request.url().startsWith(authorizationEndpoint))
    await page.goto(productionURL)
    await page.getByRole('button', { name: secrets.sign_in_name, exact: true }).click()
    const authorization = await authorizationRequest
    const authorizationURL = new URL(authorization.url())
    expect(authorizationURL.origin).toBe(secrets.issuer_origin)
    expect(authorizationURL.searchParams.get('response_type')).toBe('code')
    expect(authorizationURL.searchParams.get('client_id')).toBe(clientId)
    expect(authorizationURL.searchParams.get('code_challenge_method')).toBe('S256')
    expect(authorizationURL.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(authorizationURL.searchParams.get('state')).toMatch(/^[A-Za-z0-9_-]{32,}$/)
    expect(authorizationURL.searchParams.get('nonce')).toMatch(/^[A-Za-z0-9_-]{32,}$/)
    expect(authorizationURL.searchParams.get('scope')?.split(' ')).toContain('openid')
    expect(new URL(String(authorizationURL.searchParams.get('redirect_uri'))).origin).toBe(productionOrigin)

    const tokenRequest = page.waitForRequest((request) => request.url() === tokenEndpoint)
    const identityResponse = page.waitForResponse(
      (response) => response.url() === `${productionOrigin}/api/v1/me` && response.status() === 200,
    )
    await executeSteps(page, secrets.login_steps, secrets.personas[identity])
    const exchange = await tokenRequest
    expect(exchange.method()).toBe('POST')
    const tokenForm = new URLSearchParams(exchange.postData() ?? '')
    expect(tokenForm.get('grant_type')).toBe('authorization_code')
    expect(tokenForm.get('code')).not.toHaveLength(0)
    expect(tokenForm.get('code_verifier')).toMatch(/^[A-Za-z0-9._~-]{43,128}$/)
    expect(tokenForm.get('client_id')).toBe(clientId)
    expect(tokenForm.has('client_secret')).toBe(false)
    expect(new URL(String(tokenForm.get('redirect_uri'))).origin).toBe(productionOrigin)
    const me = await (await identityResponse).json() as Record<string, unknown>
    expect(me.roles).toEqual([PERSONA_ROLES[identity]])
    expect(me.service).toBe(false)
    await expect(page.getByRole('button', { name: secrets.sign_out_name, exact: true })).toBeVisible()

    const logoutRequest = page.waitForRequest((request) => request.url().startsWith(endSessionEndpoint))
    await page.getByRole('button', { name: secrets.sign_out_name, exact: true }).click()
    expect((await logoutRequest).url()).toContain('post_logout_redirect_uri=')
    if (secrets.logout_steps.length) await executeSteps(page, secrets.logout_steps, secrets.personas[identity])
    await page.waitForURL((url) => url.origin === productionOrigin)
    await expect(page.getByRole('button', { name: secrets.sign_in_name, exact: true })).toBeVisible()
    await context.close()
  }

  expect(safeProtocolRequests).toBe(true)
  const summary = {
    schema_version: 2,
    ...binding,
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    web_origin: productionOrigin,
    issuer,
    client_id_digest: createHash('sha256').update(clientId).digest('hex'),
    personas: Object.keys(PERSONA_ROLES).sort(),
    checks: {
      authorization_code: true,
      pkce_s256: true,
      token_exchange: true,
      id_token_verified: true,
      access_token_api: true,
      logout: true,
      no_cross_origin_redirect: true,
    },
  }
  mkdirSync(dirname(output), { recursive: true })
  const temporary = `${output}.${process.pid}.tmp`
  writeFileSync(temporary, `${JSON.stringify(summary)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
    flag: 'wx',
  })
  try {
    linkSync(temporary, output)
  } finally {
    unlinkSync(temporary)
  }
})
