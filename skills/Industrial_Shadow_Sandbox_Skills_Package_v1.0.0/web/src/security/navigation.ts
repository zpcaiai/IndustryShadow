import type { MessageKey } from '../i18n'

export type NavigationItem = {
  name: string
  labelKey: MessageKey
  requiredAny: readonly string[]
}

export const navigationItems: readonly NavigationItem[] = [
  { name: 'home', labelKey: 'nav.overview', requiredAny: ['report:view'] },
  { name: 'assets', labelKey: 'nav.assets', requiredAny: ['model:edit', 'model:publish'] },
  { name: 'scenarios', labelKey: 'nav.scenarios', requiredAny: ['scenario:edit', 'scenario:publish'] },
  { name: 'runs', labelKey: 'nav.runs', requiredAny: ['run:view'] },
  { name: 'diagnosis', labelKey: 'nav.diagnosis', requiredAny: ['run:view'] },
  { name: 'approvals', labelKey: 'nav.approvals', requiredAny: ['approval:view'] },
  { name: 'evaluation', labelKey: 'nav.evaluation', requiredAny: ['evaluation:execute', 'audit:view'] },
  { name: 'imports', labelKey: 'nav.imports', requiredAny: ['model:edit'] },
  { name: 'edge', labelKey: 'nav.edge', requiredAny: ['endpoint:manage', 'audit:view'] },
  { name: 'admin', labelKey: 'nav.admin', requiredAny: ['admin:manage'] },
] as const

export function canAccess(requiredAny: readonly string[] | undefined, permissions: ReadonlySet<string>): boolean {
  return !requiredAny?.length || requiredAny.some((permission) => permissions.has(permission))
}

export function visibleNavigation(permissions: ReadonlySet<string>): readonly NavigationItem[] {
  return navigationItems.filter((item) => canAccess(item.requiredAny, permissions))
}
