# Batch 21: Web/admin completion, RBAC, audit, and health

## Context

- Completed dependencies: full S0 simulation/diagnosis/approval/recovery/replay/evaluation backend loop.
- Earlier batches include feature views; this batch closes navigation, identity, authorization, administration, audit, operational health, and consistent UX.
- UI permissions are informative; APIs and services remain the enforcement boundary.

## Outcome

- Operators, engineers, approvers, Pack authors, admins, and auditors have role-appropriate end-to-end workspaces.
- Admins manage endpoints, policies, versions, quotas, retention, service health, and secrets references without seeing secret values.
- Auditors can reconstruct who changed, viewed, approved, executed, evaluated, and promoted each artifact.

## Inputs

- All user/API surfaces, events, audit hooks, and system health signals from Batches 01–20.
- Enterprise identity adapter abstraction; local OIDC provider is used in development.
- Role/permission matrix and separation-of-duties policies from the system contract.
- Data retention, export, deletion, and legal-hold policies for metadata/raw/Gold/reports/audit.

## Code modules

- `backend/src/shadow_sandbox/security/identity.py`, `authn.py`, `authz.py`, `roles.py`, and `tenant_context.py`.
- `backend/src/shadow_sandbox/security/audit/entities.py`, `service.py`, `sink.py`, and `api.py`.
- `backend/src/shadow_sandbox/admin/endpoints.py`, `policies.py`, `versions.py`, `quotas.py`, `retention.py`, and `health.py`.
- `backend/src/shadow_sandbox/common/pagination.py` and permission-aware query filters.
- `migrations/*_identity_rbac_audit_admin.py`.
- `web/src/router/`, `layouts/`, `stores/session.ts`, `features/admin/`, `features/audit/`, and shared states/components.
- `web/src/api/generated/`: generated client from OpenAPI.
- `tests/e2e/personas/`, `tests/security/rbac/`, and accessibility suite.
- `deploy/compose/compose.identity.yaml` for local OIDC.

## Interfaces

- Roles: Viewer, Engineer, Approver, PackAuthor, Admin, Auditor, and least-privilege service identities.
- Permissions cover view/edit/publish/run/approve/execute-evaluator/read-Gold-metadata/manage-endpoint/manage-policy/audit/export/promote.
- `GET /api/v1/me`, `/permissions`, `/admin/system-health`, `/admin/quotas`, `/admin/version-registry`, `/audit-records`.
- Admin command APIs use idempotency, optimistic lock, reason, audit, and high-risk dual approval where configured.
- Audit record: actor/service identity, tenant/workspace, action, target, before/after digest or diff, policy decision, Run/Trace, time, source, and result.
- Pagination/filter/sort contracts are consistent across runs, scenarios, approvals, evaluations, reports, and audits.
- Frontend navigation is generated from permissions but direct routes still handle 401/403 safely.

## Implementation requirements

1. Implement OIDC validation, session/token expiry, CSRF strategy where applicable, logout, and service identity authentication.
2. Derive tenant/workspace server-side and enforce isolation in repository queries; use PostgreSQL RLS when compatible as defense in depth.
3. Implement role and resource/action permission policies, including maker-checker separation.
4. Aggregate all prior feature pages into coherent navigation and shared design/response states.
5. Generate typed frontend API client from the checked-in OpenAPI digest and fail CI on drift.
6. Create append-only audit records for identity, configuration, endpoint, version, Run, tool, approval, action, Gold, Gate, report, and export operations.
7. Redact secrets, Gold, sensitive raw values, tokens, and excessive request bodies from audit/logs.
8. Provide health views for backend, database, simulator, Collector, workers, queue, storage, OTel, endpoint freshness, and version compatibility.
9. Implement quotas/retention preview, protected-reference checks, and safe background enforcement.
10. Provide loading/empty/error/offline/forbidden/stale/conflict states and accessible keyboard/focus behavior.
11. Add localization resources for Chinese and English industrial labels.
12. Track product analytics/feedback only with privacy-preserving event definitions and opt-out policy.

## Tests

- Unit: permission matrix, tenant context, audit redaction, retention protection, pagination, and health aggregation.
- Security: horizontal/vertical privilege escalation, forged tenant, expired token, CSRF, direct route/API, service identity scopes.
- Database: tenant isolation/RLS and append-only audit constraints.
- E2E personas: Viewer, Engineer, Approver, PackAuthor, Admin, and Auditor complete allowed flows and receive 403 for forbidden flows.
- Audit: every critical action from Batches 01–20 creates a correlated redacted record.
- Frontend: OpenAPI client drift, responsive layouts, loading/error/offline/conflict, and localization.
- Accessibility: automated WCAG checks plus keyboard workflows for diagnosis and approval.
- Retention: preview/delete unreferenced data, retain protected snapshots/reports/Gold/audit, and record results.

## Required evidence

- `docs/evidence/batch-21/manifest.json`.
- Permission matrix test and cross-tenant/privilege escalation report.
- Persona Playwright traces covering the end-to-end user journeys.
- Audit coverage/redaction report and sample sanitized records.
- OpenAPI frontend-client drift check.
- Accessibility, localization, responsive, and error-state reports.
- Health dashboard capture, retention-protection test, migration, and identity integration logs.

## Definition of Done

- All P0 workflows are reachable through consistent authenticated navigation and live APIs.
- Server-side authorization and tenant isolation pass persona and adversarial tests.
- Critical operations produce append-only, correlated, redacted audit records.
- Health/admin pages expose actionable real state, not static indicators.
- Generated frontend client matches current OpenAPI and CI fails on drift.
- Retention cannot delete protected evidence, Gold, snapshots, reports, or audit records.
- Core pages meet declared accessibility and Chinese/English resource requirements.

## Out of scope

- Real Shadow edge deployment, full enterprise directory provisioning, billing, and public marketplace.
- Treating frontend hiding as authorization.

