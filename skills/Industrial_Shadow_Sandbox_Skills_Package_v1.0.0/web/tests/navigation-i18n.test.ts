import { afterEach, describe, expect, it } from 'vitest'
import { canAccess, visibleNavigation } from '../src/security/navigation'
import { setLocale, translate } from '../src/i18n'

afterEach(() => setLocale('en'))

describe('permission-derived navigation', () => {
  it('only exposes routes authorized by the signed permission set', () => {
    const viewer = visibleNavigation(new Set(['run:view', 'report:view'])).map((item) => item.name)
    expect(viewer).toEqual(['home', 'runs', 'diagnosis'])
    expect(canAccess(['admin:manage'], new Set(['report:view']))).toBe(false)
    expect(canAccess(['admin:manage'], new Set(['admin:manage']))).toBe(true)
  })

  it('supports the six interactive personas without treating hiding as authorization', () => {
    expect(visibleNavigation(new Set(['model:edit', 'scenario:edit', 'run:view', 'report:view'])).map((item) => item.name)).toContain('assets')
    expect(visibleNavigation(new Set(['approval:view', 'approval:decide', 'run:view', 'report:view'])).map((item) => item.name)).toContain('approvals')
    expect(visibleNavigation(new Set(['model:publish', 'scenario:publish', 'pack:edit', 'run:view', 'report:view'])).map((item) => item.name)).toEqual(expect.arrayContaining(['assets', 'scenarios']))
    expect(visibleNavigation(new Set(['audit:view', 'run:view', 'report:view'])).map((item) => item.name)).toEqual(expect.arrayContaining(['evaluation', 'edge']))
    expect(visibleNavigation(new Set(['admin:manage', 'endpoint:manage', 'run:view', 'report:view'])).map((item) => item.name)).toEqual(expect.arrayContaining(['admin', 'edge']))
  })
})

describe('industrial localization resources', () => {
  it('switches all core navigation and security-boundary labels', () => {
    setLocale('zh-CN')
    expect(translate('nav.diagnosis')).toBe('诊断')
    expect(translate('forbidden.title')).toBe('拒绝访问')
    expect(translate('app.boundary')).toBe('真实端点只读边界')
  })
})
