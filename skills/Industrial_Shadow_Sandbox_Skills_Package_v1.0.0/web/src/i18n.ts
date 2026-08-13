import { computed, ref } from 'vue'

export type Locale = 'en' | 'zh-CN'

const messages = {
  en: {
    'app.name': 'Industrial Shadow', 'app.sandbox': 'Sandbox', 'app.primary': 'Primary navigation',
    'app.skip': 'Skip to main content', 'app.locale': 'Language', 'app.roles': 'Local roles',
    'app.boundary': 'read-only real endpoint boundary', 'app.connecting': 'Connecting…',
    'auth.loading': 'Loading trusted identity…', 'auth.eyebrow': 'Industrial Shadow Sandbox',
    'auth.title': 'Sign in through your approved identity provider',
    'auth.description': 'Access is derived from signed OIDC claims. Browser-supplied roles and workspace headers are ignored in production.',
    'auth.signIn': 'Sign in', 'auth.signOut': 'Sign out',
    'auth.unavailableTitle': 'Authentication is unavailable', 'auth.retry': 'Retry',
    'auth.unavailableFallback': 'No trusted authentication configuration was returned.',
    'forbidden.eyebrow': 'PERMISSION BOUNDARY', 'forbidden.title': 'Access denied',
    'forbidden.description': 'Your signed identity does not grant permission to view this page.',
    'forbidden.home': 'Return to an allowed page',
    'state.loading': 'Loading verified state…', 'state.empty': 'No records in this workspace.',
    'nav.overview': 'Overview', 'nav.assets': 'Assets', 'nav.scenarios': 'Scenarios', 'nav.runs': 'Runs',
    'nav.diagnosis': 'Diagnosis', 'nav.approvals': 'Approvals', 'nav.evaluation': 'Evaluation',
    'nav.imports': 'Imports', 'nav.edge': 'Edge', 'nav.admin': 'Admin',
  },
  'zh-CN': {
    'app.name': '工业影子', 'app.sandbox': '沙箱', 'app.primary': '主导航',
    'app.skip': '跳到主要内容', 'app.locale': '语言', 'app.roles': '本地角色',
    'app.boundary': '真实端点只读边界', 'app.connecting': '正在连接…',
    'auth.loading': '正在加载可信身份…', 'auth.eyebrow': '工业影子沙箱',
    'auth.title': '通过获准的身份提供商登录',
    'auth.description': '访问权限来自签名 OIDC 声明；生产环境会忽略浏览器提供的角色和工作区请求头。',
    'auth.signIn': '登录', 'auth.signOut': '退出登录',
    'auth.unavailableTitle': '身份认证不可用', 'auth.retry': '重试',
    'auth.unavailableFallback': '未返回可信的身份认证配置。',
    'forbidden.eyebrow': '权限边界', 'forbidden.title': '拒绝访问',
    'forbidden.description': '你的签名身份没有查看此页面所需的权限。',
    'forbidden.home': '返回允许访问的页面',
    'state.loading': '正在加载已验证状态…', 'state.empty': '当前工作区没有记录。',
    'nav.overview': '概览', 'nav.assets': '资产', 'nav.scenarios': '场景', 'nav.runs': '运行',
    'nav.diagnosis': '诊断', 'nav.approvals': '审批', 'nav.evaluation': '评估',
    'nav.imports': '导入', 'nav.edge': '边缘', 'nav.admin': '管理',
  },
} as const

export type MessageKey = keyof typeof messages.en
const stored = typeof window === 'undefined' ? null : window.localStorage.getItem('industrial-shadow-locale')
const locale = ref<Locale>(stored === 'zh-CN' ? 'zh-CN' : 'en')

export function setLocale(value: Locale): void {
  locale.value = value
  if (typeof window !== 'undefined') window.localStorage.setItem('industrial-shadow-locale', value)
  if (typeof document !== 'undefined') document.documentElement.lang = value
}

export function translate(key: MessageKey): string {
  return messages[locale.value][key] ?? messages.en[key]
}

export function useI18n() {
  return { locale, setLocale, t: (key: MessageKey) => translate(key), htmlLang: computed(() => locale.value) }
}

setLocale(locale.value)
