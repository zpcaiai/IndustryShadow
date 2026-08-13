# Batch 24: Security, resilience, performance, and production closure

## Context

- Completed dependencies: all S0–S2 feature batches, including real read-only pilot capability.
- This final batch integrates and verifies the complete product; it does not add a hidden real-control feature.
- Release readiness requires executable evidence for normal, failure, adversarial, upgrade, rollback, privacy, and operations stories.

## Outcome

- One reproducible production candidate passes architecture, dependency, migration, E2E, scenario, security, resilience, performance, privacy, observability, deployment, rollback, and release checks.
- SLI/SLO, alerts, dashboards, runbooks, backup/restore, incident process, and continuous recertification are operational.
- A signed Production Closure Certificate states the exact certified scope, versions, thresholds, limitations, and non-goals.

## Inputs

- All code, schemas, migrations, Domain Packs, datasets, tests, evidence, Runbooks, Gates, and deployment artifacts from Batches 01–23.
- Target deployment profile, capacity, retention, availability, RPO/RTO, security, and incident requirements.
- Approved test environments for Sandbox, historical S1, and read-only S2 pilot.
- Prior MVP Gate baseline and at least one rollback-compatible previous release.

## Code modules

- `backend/src/shadow_sandbox/release/catalog.py`, `readiness.py`, `closure.py`, and `recertification.py`.
- `backend/src/shadow_sandbox/operations/slo.py`, `alerts.py`, `backup.py`, `privacy.py`, and `incidents.py`.
- `deploy/production/`: pinned manifests, secrets references, network policies, migrations, health, backup, and rollback.
- `deploy/dashboards/` and `deploy/alerts/`.
- `.github/workflows/release.yml`, security scan, SBOM/provenance/signing, and scheduled recertification workflows.
- `tests/system/`, `tests/resilience/`, `tests/security/`, `tests/performance/`, `tests/upgrade/`, and `tests/privacy/`.
- `docs/runbooks/`: deployment, rollback, DB/storage restore, Collector/Edge outage, policy violation, Gold exposure, and incident handling.
- `docs/evidence/batch-24/` and generated closure certificate/report.
- No new application business module is permitted without updating earlier contracts and regression suites.

## Interfaces

- Service catalog declares owner, dependencies, data, SLI/SLO, alerts, runbook, deployment, version, and criticality for API, worker, simulator, Collector, Edge, database, object storage, OTel, and web.
- Release Manifest contains source/build/image/SBOM/schema/migration/Domain Pack/dataset/gate/config digests and supported upgrade range.
- Readiness API aggregates dependency/version/migration/storage/queue/policy/certificate/Gate state with redacted machine codes.
- Continuous recertification API/job runs fixed suites on dependency, model, Prompt, Pack, policy, or build changes.
- Production Closure Certificate includes scope S0/S1/S2, explicit exclusion of real write/control, SLO, Gate results, tests, residual risks, rollback target, and signatories.
- Alerts link SLI symptom to dashboard and runbook; no alert is released without an owner and test.

## Implementation requirements

1. Audit module dependencies and remove duplicate domain types, dead adapters, unsafe generic clients, debug bypasses, and inconsistent Schemas.
2. Validate every migration from the oldest supported release, fresh install, rollback boundary, and backup restore.
3. Run the complete ≥150-Episode benchmark plus E2E approval/action/replay/evaluation and read-only pilot paths.
4. Build a threat model and test authn/authz/tenant, injection, SSRF, file, secrets, Gold, Prompt, supply-chain, replay, endpoint spoof, and OT network boundaries.
5. Generate SBOM, dependency/vulnerability/license reports, signed artifacts, and provenance; block according to severity policy.
6. Inject database, storage, worker, simulator, Collector, Edge/uplink, network, OTel, and model-provider failures and verify safe recovery/degradation.
7. Load test declared point rate, concurrent Runs, replay speed, report volume, UI, storage, and retention; publish capacity envelope, not untested claims.
8. Define and instrument SLI/SLO for ingestion freshness, Run success, diagnostic latency, approval, replay, reports, and safety-policy violations.
9. Test alerts for precision, routing, deduplication, maintenance suppression, and linked runbooks.
10. Verify privacy classification, least data, retention, export, deletion, legal hold, audit, and backups.
11. Execute canary/upgrade/rollback including database compatibility and post-rollback data integrity.
12. Make release creation depend on all critical evidence and a passed exact-bundle Release Gate; no manual bypass.

## Tests

- Full regression: unit, type, lint, contract, migration, integration, scenario, replay, E2E, accessibility, and API-client drift.
- Security: SAST, secret scan, dependency/container/IaC, DAST, fuzz/API/DSL, tenant/authz, Prompt Injection, Gold leak, endpoint spoof, and network egress.
- Resilience: dependency kill/restart, latency, packet loss, disk full, corrupt snapshot/Parquet, expired cert, queue backlog, and model outage.
- Performance: point/event rate, concurrent Episode/suite, 10×/50× replay, query, dashboard, report, and Edge buffer/uplink.
- Upgrade: fresh install, N-1 upgrade, supported downgrade/rollback, backup restore, config/schema/Pack compatibility.
- Privacy: retention/export/delete/legal hold and backup expiry.
- Operations: synthetic SLI breach fires correct alert and runbook; incident exercise produces timeline and learning action.
- Release: modified artifact/policy/schema after Gate invalidates certification and promotion.

## Required evidence

- `docs/evidence/batch-24/manifest.json` linking every evidence artifact and digest.
- Full test/coverage reports and ≥150-Episode benchmark Gate result.
- Threat model, penetration/adversarial reports, SBOM, vulnerability/license, image signature, and provenance.
- Resilience matrix with recovery/degradation result and data-integrity checks.
- Performance/capacity report with reference hardware and bottlenecks.
- Migration/upgrade/backup-restore/canary/rollback logs and hashes.
- SLI/SLO dashboards, tested alert routes, runbook execution records, privacy results, and incident exercise.
- Signed Production Closure Certificate and exact Release Manifest.

## Definition of Done

- Clean install and supported upgrade complete; backup restore and rollback are actually executed and verified.
- Full benchmark and end-to-end product journeys pass the exact-bundle Release Gate with all safety red lines at zero.
- Security, Gold, Prompt, endpoint, network, tenant, file, and supply-chain critical tests pass or release is blocked.
- Failure injection proves safe degradation/recovery without duplicate actions, silent data trust, or control-boundary breach.
- Capacity envelope and SLOs are measured on declared hardware; alerts and runbooks are tested.
- Privacy/retention/export/delete/legal-hold behavior is executable and auditable.
- Release artifacts are pinned, signed, traceable, rollback-ready, and continuously recertifiable.
- Closure Certificate explicitly limits certification to simulation, historical replay, and real read-only Shadow; no real write/control claim exists.

## Out of scope

- S5 real-device actuation, autonomous closed-loop control, regulator-issued certification, and guarantees outside the measured Domain Pack/corpus/capacity envelope.
- Waiving critical evidence or safety red lines to meet a release date.

