# Batch 01: Repository foundation and executable evidence ledger

## Context

- Product thesis: build a read-only industrial diagnosis validation platform with simulation-only side effects.
- Completed dependencies: none; this is the foundation batch.
- Reuse an existing repository if present. Do not replace working conventions merely to match this reference.
- Greenfield defaults are Python/FastAPI/PostgreSQL, Vue/TypeScript, Docker Compose, OpenTelemetry, pytest, and Playwright.
- The batch must leave a running vertical skeleton, not a directory-only scaffold.

## Outcome

- A developer can clone the repository, run one documented command, apply migrations, start backend/web/PostgreSQL, and call health and readiness endpoints.
- CI proves formatting, type checking, unit tests, migration validity, frontend build, and package-contract validation.
- `IMPLEMENTATION_STATUS.yaml` and the evidence manifest distinguish implemented, verified, partial, and blocked work.

## Inputs

- `references/system-contract.md` from this skill.
- Existing `AGENTS.md`, dependency manifests, CI, Compose, lint, formatting, and test conventions.
- Runtime versions supported by the execution environment.
- No production credentials or external services are required.

## Code modules

- `backend/pyproject.toml`: pinned application and development dependencies.
- `backend/src/shadow_sandbox/main.py`: FastAPI application factory.
- `backend/src/shadow_sandbox/common/config.py`: typed environment configuration.
- `backend/src/shadow_sandbox/common/db.py`: engine/session lifecycle.
- `backend/src/shadow_sandbox/common/problem.py`: stable problem-details errors.
- `backend/src/shadow_sandbox/observability/bootstrap.py`: OTel bootstrap and correlation IDs.
- `backend/src/shadow_sandbox/api/health.py`: liveness/readiness/version routes.
- `web/package.json`, `web/src/main.ts`, `web/src/router/index.ts`, `web/src/views/SystemHome.vue`.
- `migrations/`: initial Alembic configuration and migration tracking.
- `deploy/compose/compose.yaml`: PostgreSQL, backend, web, and observability development profile.
- `.github/workflows/ci.yml` or the repository's equivalent CI entry.
- `IMPLEMENTATION_STATUS.yaml` and `docs/evidence/batch-01/`.

## Interfaces

- `GET /api/v1/health/live` returns process liveness without checking dependencies.
- `GET /api/v1/health/ready` checks database migration state and critical configuration; use 503 with stable error codes when unready.
- `GET /api/v1/version` returns build digest, schema version, and runtime versions without exposing secrets.
- OpenAPI is generated and saved as `schemas/api/openapi.json` in CI.
- Common event envelope and command headers are represented as Pydantic types even if no domain events are emitted yet.
- `IMPLEMENTATION_STATUS.yaml` schema contains batch, status, evidence paths, commands, commit/build digest, limits, and DoD results.

## Implementation requirements

1. Inspect and preserve the current worktree before editing.
2. Use an application factory so tests create isolated apps and configuration.
3. Validate configuration at startup; secret values must not appear in logs or `/version`.
4. Configure request/trace correlation and structured JSON logs.
5. Create a database connection check and migration-head check for readiness.
6. Serve a minimal Vue route that calls readiness and shows loading, ready, unready, and network-error states.
7. Add consistent backend and frontend formatting, lint, type-check, and test commands.
8. Configure Compose health checks and dependency ordering without hiding startup failures.
9. Add a transactional test database strategy and deterministic test configuration.
10. Seed only non-sensitive development metadata needed to prove database access.
11. Produce a Makefile/task runner or equivalent with `bootstrap`, `migrate`, `dev`, `test`, and `evidence` targets.
12. Do not add domain behavior that belongs to later batches.

## Tests

- Unit: configuration parsing, secret redaction, error serialization, correlation ID behavior.
- API contract: live/ready/version schemas, status codes, content types, and stable error codes.
- Migration: upgrade an empty database to head, downgrade where supported, and re-upgrade.
- Integration: start Compose, wait for health, call all three endpoints, and query the rendered web route.
- Frontend: component tests for four health states and a production build.
- Security: confirm a deliberately supplied secret cannot be found in logs, OpenAPI, `/version`, or error responses.
- Failure: stop PostgreSQL and prove liveness remains 200 while readiness becomes 503.
- CI: run the same commands used locally and archive reports.

## Required evidence

- `docs/evidence/batch-01/manifest.json`.
- `backend-tests.xml`, frontend test report, type-check and lint logs.
- `migration-up.log` and `migration-head.txt`.
- `compose-ps.txt`, backend health responses, and web smoke screenshot or Playwright trace.
- `schemas/api/openapi.json` with SHA-256 in the manifest.
- `secret-redaction-test.log` containing only test assertions, never the secret.
- Build/image digests and exact bootstrap/test commands with exit code 0.

## Definition of Done

- A clean environment reaches ready state through the documented bootstrap path.
- Backend and frontend production builds succeed.
- Empty-database migration succeeds and readiness detects migration drift.
- Health UI reflects real API state rather than static data.
- CI executes format, lint, type check, unit, migration, frontend build, and integration smoke checks.
- Evidence files exist, hashes match, and the batch manifest reports no missing artifact.
- `IMPLEMENTATION_STATUS.yaml` records Batch 01 as completed only after the above evidence exists.
- No credentials, business-domain stubs, skipped critical tests, or hard-coded green health responses remain.

## Out of scope

- Asset models, OPC UA, simulation, scenarios, diagnosis, approval, replay, and evaluation.
- Enterprise SSO, multi-site RBAC, high availability, Kubernetes, or production OT connectivity.

