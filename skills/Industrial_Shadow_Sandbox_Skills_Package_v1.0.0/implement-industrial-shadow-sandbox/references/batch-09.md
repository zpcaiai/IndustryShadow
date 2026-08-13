# Batch 09: Gold isolation, scenario suites, and benchmark corpus

## Context

- Completed dependencies: publishable Scenarios and deterministic F01–F10 fault runtime.
- Evaluation truth must be stored separately from Agent-visible Scenario content, ordinary APIs, logs, traces, and reports.
- A benchmark requires both fault and normal Episodes across load, severity, seed, startup, shutdown, setpoint changes, and network transients.

## Outcome

- Evaluator-only identities can create, validate, seal, and resolve versioned Gold Specs.
- Engineers can define immutable Scenario Suites that expand a coverage matrix into at least 100 fault and 50 normal Episodes.
- Automated leakage tests prove that Agent-facing paths cannot retrieve Gold.

## Inputs

- Published Scenario versions and F01–F10 matrix from Batches 07–08.
- Canonical root-cause, symptom, check, and forbidden-action identifiers; later batches implement the consumers.
- Service-identity and database configuration from Batch 01.
- Normal Scenario catalog covering startup, shutdown, load/setpoint change, noise, jitter, and maintenance.

## Code modules

- `backend/src/shadow_sandbox/evaluation/gold/entities.py`: Gold draft/sealed versions.
- `backend/src/shadow_sandbox/evaluation/gold/schemas.py`: evaluator-only Gold Spec v1.
- `backend/src/shadow_sandbox/evaluation/gold/service.py`: validate, seal, resolve, and audit.
- `backend/src/shadow_sandbox/evaluation/gold/repository.py`: separate schema/connection role.
- `backend/src/shadow_sandbox/scenarios/suites/entities.py`, `expander.py`, `service.py`, and `api.py`.
- `backend/src/shadow_sandbox/security/gold_boundary.py`: identity and response/log redaction policy.
- `migrations/*_gold_vault.py` and `*_scenario_suites.py` with separate grants.
- `schemas/scenarios/gold-spec-v1.json` and `scenario-suite-v1.json`.
- `domain-packs/pump-tank-v1/gold/` and `scenarios/suites/mvp-benchmark.yaml`.
- `tests/security/gold_leakage/` and corpus validation tests.

## Interfaces

- `GoldSpecV1`: Scenario ref, one/multiple root causes, expected symptom windows, required checks with weights/order, critical safety steps, forbidden actions, acceptable alternatives, and label provenance.
- Gold service is bound to an evaluator service identity; no ordinary user/Agent endpoint returns Gold payloads.
- Admin workflow exposes only sealed status, version, labeler, review state, and digest; sensitive content uses a separately authorized review endpoint.
- `ScenarioSuiteV1`: Scenario refs or templates, parameter axes, seeds, exclusions, expected Episode count, and split label.
- `POST /api/v1/scenario-suites/{id}/validate`, `/publish`, and `/expand`; expansion returns Episode manifests without Gold.
- `GoldResolver.resolve_for_evaluation(run_manifest, evaluator_identity)` is the only runtime access method.
- Events expose Gold version/digest status but never labels; access attempts create high-priority audit records.

## Implementation requirements

1. Use separate database schema and least-privilege role for Gold; application/Agent role has no SELECT grant.
2. Encrypt Gold content using the platform's secret/key abstraction and rotateable key reference.
3. Keep Gold out of OpenAPI examples, normal event payloads, traces, errors, evidence manifests, and Agent tool schemas.
4. Seal Gold versions immutably and require provenance plus optional two-person review.
5. Validate referenced root-cause/symptom/check IDs against versioned catalogs without exposing descriptions to the Agent.
6. Expand suites deterministically and produce stable Episode IDs/digests.
7. Enforce train/tune/validation/certification split separation and detect duplicate underlying Episodes.
8. Seed at least 10 fault types × severity/load/seed combinations totaling ≥100 fault Episodes.
9. Seed ≥50 normal Episodes including legitimate transients that challenge false-positive behavior.
10. Create corpus coverage reports by fault, load, severity, mode, seed, and normal behavior.
11. Add log/trace/response scanning fixtures containing recognizable canary Gold tokens.
12. Protect sealed Gold and suite versions referenced by evaluations.

## Tests

- Unit: Gold schema, weights, order constraints, alternative steps, suite expansion, stable Episode IDs, duplicate/split detection.
- Database security: application/Agent connection cannot select Gold tables; evaluator role can resolve only authorized workspace/version.
- API contract: ordinary APIs reveal metadata only; authorized review endpoint enforces scope and redaction.
- Leakage: scan HTTP responses, logs, traces, event outbox, exported Scenario, error paths, and evidence for canary tokens.
- Corpus: validate ≥100 fault and ≥50 normal unique Episode manifests with complete coverage fields.
- Immutability: sealed versions cannot mutate/delete; unsealed drafts cannot be used for evaluation.
- Encryption: database/file inspection does not contain plaintext Gold content.
- Failure: missing catalog reference, bad weights, split collision, wrong key, and unauthorized access.

## Required evidence

- `docs/evidence/batch-09/manifest.json` containing only Gold digests/metadata, never labels.
- Database grants test and sanitized schema output.
- Gold encryption-at-rest assertion and key-rotation test log.
- Leakage scan report across APIs/logs/traces/events/files with zero canary matches.
- Scenario-suite expansion manifest and coverage matrix for ≥150 Episodes.
- Split deduplication report and sealed-version immutability tests.
- Audit records for allowed and denied Gold access with sensitive fields redacted.

## Definition of Done

- The benchmark expands deterministically to at least 100 fault and 50 normal Episodes.
- Every fault Episode has a sealed evaluator-only Gold version and every normal Episode is explicitly labeled normal.
- Application and Agent identities cannot read Gold at database, service, API, log, trace, or export boundaries.
- Sealed Gold and suite versions are immutable and content-addressed.
- Coverage and split reports identify all intended dimensions and no duplicate leakage across certification splits.
- Gold access attempts are audited without exposing the content.
- No later diagnostic implementation is smuggled into this batch.

## Out of scope

- Executing the suites, computing diagnostic metrics, root-cause algorithms, and report generation.
- Human labeling UI beyond the minimum protected review flow.

