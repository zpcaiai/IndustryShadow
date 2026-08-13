import { createRouter, createWebHistory } from 'vue-router'

declare module 'vue-router' {
  interface RouteMeta {
    requiredAny?: readonly string[]
  }
}

export default createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/auth/callback', name: 'auth-callback', component: () => import('../views/AuthCallback.vue') },
    { path: '/', name: 'home', component: () => import('../views/SystemHome.vue'), meta: { requiredAny: ['report:view'] } },
    { path: '/assets', name: 'assets', component: () => import('../views/AssetsView.vue'), meta: { requiredAny: ['model:edit', 'model:publish'] } },
    { path: '/scenarios', name: 'scenarios', component: () => import('../views/ScenariosView.vue'), meta: { requiredAny: ['scenario:edit', 'scenario:publish'] } },
    { path: '/runs', name: 'runs', component: () => import('../views/RunsView.vue'), meta: { requiredAny: ['run:view'] } },
    { path: '/diagnosis/:runId?', name: 'diagnosis', component: () => import('../views/DiagnosisView.vue'), meta: { requiredAny: ['run:view'] } },
    { path: '/approvals', name: 'approvals', component: () => import('../views/ApprovalsView.vue'), meta: { requiredAny: ['approval:view'] } },
    { path: '/evaluation', name: 'evaluation', component: () => import('../views/EvaluationView.vue'), meta: { requiredAny: ['evaluation:execute', 'audit:view'] } },
    { path: '/imports', name: 'imports', component: () => import('../views/ImportsView.vue'), meta: { requiredAny: ['model:edit'] } },
    { path: '/edge', name: 'edge', component: () => import('../views/EdgeView.vue'), meta: { requiredAny: ['endpoint:manage', 'audit:view'] } },
    { path: '/admin', name: 'admin', component: () => import('../views/AdminView.vue'), meta: { requiredAny: ['admin:manage'] } },
    { path: '/:pathMatch(.*)*', component: () => import('../views/NotFound.vue') },
  ],
})
