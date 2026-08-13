import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page, type Route } from '@playwright/test'

const permissionsByRole: Record<string, string[]> = {
  Viewer: ['run:view', 'report:view'],
  Engineer: ['run:view', 'run:create', 'model:edit', 'scenario:edit', 'report:view'],
  Approver: ['run:view', 'approval:view', 'approval:decide', 'report:view'],
  PackAuthor: ['run:view', 'pack:edit', 'model:publish', 'scenario:publish', 'report:view'],
  Admin: ['run:view', 'admin:manage', 'endpoint:manage', 'policy:manage', 'report:view'],
  Auditor: ['run:view', 'audit:view', 'report:view', 'gold:metadata'],
}

async function fulfillApi(route: Route): Promise<void> {
  const url = new URL(route.request().url())
  const headers = route.request().headers()
  if (url.pathname === '/api/v1/auth/config') {
    await route.fulfill({ json: { mode: 'development' } })
    return
  }
  if (url.pathname === '/api/v1/me') {
    const roles = (headers['x-roles'] ?? 'Engineer,Viewer').split(',').filter(Boolean)
    const permissions = [...new Set(roles.flatMap((role) => permissionsByRole[role] ?? []))].sort()
    await route.fulfill({
      json: {
        actor_id: headers['x-actor-id'] ?? 'dev-user',
        tenant_id: headers['x-tenant-id'] ?? 'dev-tenant',
        workspace_id: headers['x-workspace-id'] ?? 'dev-workspace',
        roles,
        permissions,
      },
    })
    return
  }
  if (url.pathname === '/api/v1/health/ready') {
    await route.fulfill({ json: { status: 'ready' } })
    return
  }
  await route.fulfill({ status: 404, contentType: 'application/problem+json', json: { code: 'NOT_FOUND', detail: 'not mocked', status: 404 } })
}

async function openApplication(page: Page, path = '/'): Promise<void> {
  await page.route('**/api/v1/**', fulfillApi)
  await page.goto(path)
  await expect(page.getByRole('navigation', { name: 'Primary navigation' })).toBeVisible()
}

test('six human personas receive permission-derived navigation', async ({ page }) => {
  await openApplication(page)
  const expectations: Record<string, string[]> = {
    Viewer: ['Overview', 'Runs', 'Diagnosis'],
    'Engineer,Viewer': ['Overview', 'Assets', 'Scenarios', 'Runs', 'Diagnosis', 'Imports'],
    'Approver,Viewer': ['Overview', 'Runs', 'Diagnosis', 'Approvals'],
    'PackAuthor,Viewer': ['Overview', 'Assets', 'Scenarios', 'Runs', 'Diagnosis'],
    'Admin,Viewer': ['Overview', 'Runs', 'Diagnosis', 'Edge', 'Admin'],
    'Auditor,Viewer': ['Overview', 'Runs', 'Diagnosis', 'Evaluation', 'Edge'],
  }
  for (const [roles, expectedLabels] of Object.entries(expectations)) {
    await page.getByLabel('Local roles').selectOption(roles)
    const links = page.getByRole('navigation', { name: 'Primary navigation' }).getByRole('link')
    await expect(links).toHaveText(expectedLabels)
  }
})

test('direct forbidden route remains fail-closed', async ({ page }) => {
  await openApplication(page, '/admin')
  await expect(page.getByRole('heading', { name: 'Access denied' })).toBeVisible()
  await expect(page.getByText('Your signed identity does not grant permission')).toBeVisible()
})

test('authentication configuration failure never exposes the application shell', async ({ page }) => {
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/v1/auth/config') {
      await route.fulfill({
        status: 503,
        contentType: 'application/problem+json',
        json: { code: 'IDENTITY_UNAVAILABLE', detail: 'identity unavailable', status: 503 },
      })
      return
    }
    await fulfillApi(route)
  })
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Authentication is unavailable' })).toBeVisible()
  await expect(page.getByRole('navigation')).toHaveCount(0)
})

test('core shell has no automated WCAG A/AA violations', async ({ page }) => {
  await openApplication(page)
  await expect(page.getByRole('heading', { name: 'Operational overview' })).toBeVisible()
  const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze()
  expect(result.violations).toEqual([])
})

test('keyboard skip link and Chinese industrial labels work', async ({ page }) => {
  await openApplication(page)
  await page.keyboard.press('Tab')
  await expect(page.getByRole('link', { name: 'Skip to main content' })).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(page.locator('#main-content')).toBeFocused()
  await page.getByLabel('Language').selectOption('zh-CN')
  await expect(page.getByRole('navigation', { name: '主导航' })).toContainText('诊断')
  await expect(page.getByText('真实端点只读边界')).toBeVisible()
})
