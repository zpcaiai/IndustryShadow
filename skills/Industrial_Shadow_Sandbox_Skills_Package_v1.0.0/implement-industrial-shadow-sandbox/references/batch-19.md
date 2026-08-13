# Batch 19: Replay, experiments, and Champion/Challenger comparison

## Context

- Completed dependencies: immutable datasets/manifests, deterministic pipeline stages, diagnosis, planning, approvals, and simulation action results.
- Replay must compare algorithm versions without rerunning the simulator unless explicitly requested.
- Experimental variants never overwrite original Run results or bypass the same evidence and safety policies.

## Outcome

- Users can replay a frozen Run from selected stages at 1×/2×/10×/50× or maximum batch speed.
- Experiments compare detector, residual, graph, ranker, check-library, Prompt, or application variants through aligned Episode outputs.
- Champion/Challenger results expose metric deltas and per-Episode regressions while preserving full lineage.

## Inputs

- Raw event/Parquet dataset, Run Manifest, snapshots, and state transitions.
- Version registries for detectors, residuals, evidence mappings, graph, ranker, checks, Prompt, build, and config.
- Pipeline stage APIs from Batches 11–18.
- Scenario-suite Episode manifests; Gold is not used until Batch 20 evaluation.

## Code modules

- `backend/src/shadow_sandbox/replay/entities.py`: replay, stage selection, frozen input, lineage.
- `backend/src/shadow_sandbox/replay/clock.py`: event-time scheduler and speed.
- `backend/src/shadow_sandbox/replay/executor.py`: stage-specific replay.
- `backend/src/shadow_sandbox/experiments/entities.py`: experiment, variant, assignment, comparison.
- `backend/src/shadow_sandbox/experiments/registry.py`: version validation.
- `backend/src/shadow_sandbox/experiments/service.py`, `comparison.py`, `api.py`, and `events.py`.
- `migrations/*_replays_experiments.py`.
- `schemas/api/replay*.json`, `experiment*.json`, and event schemas.
- `web/src/features/experiments/`: builder, progress, aligned timeline, diff, and Episode explorer.
- `tests/replay/` and experiment integration fixtures.

## Interfaces

- Replay stages: quality, detect, residual, symptom/evidence, hypotheses, check plan, narrative, full diagnosis; simulation/action replay is a distinct explicit mode.
- `ReplayManifestV1`: source Run/dataset digest, selected stages, speed, input versions, override versions, build/config, seed policy, and output namespace.
- `ExperimentV1`: scenario suite/dataset, variants, stage overrides, resource budget, comparison policy, and status.
- `POST /api/v1/runs/{id}/replays`; `GET /replays/{id}`.
- `POST /api/v1/experiments`; `GET /experiments/{id}`, `/comparison`, `/episodes`.
- Events `replay.started/completed/failed.v1` and `experiment.started/variant_completed/completed.v1`.
- Results reference source Evidence but write new derived versions; original records are immutable.

## Implementation requirements

1. Verify dataset and source hashes before replay; fail on tampering or missing protected objects.
2. Reproduce event ordering using source timestamps/sequence policy and explicit handling of duplicates/reorder.
3. Make speed affect wall time only; results must be identical across replay speeds.
4. Allow stage-specific reruns while resolving required upstream frozen artifacts.
5. Create isolated output namespaces and lineage to source Run/variant.
6. Validate all override versions for API/schema/Domain Pack compatibility before scheduling.
7. Use consistent Episode assignments and resource limits across variants.
8. Align comparison by Episode, symptom, hypothesis, Evidence, check step, latency, and outcome.
9. Flag new/missing outputs, score/rank changes, inconclusive transitions, and safety-policy differences.
10. Keep Gold inaccessible to experiment execution; evaluator joins it later.
11. Support cancellation/restart/idempotency for long experiments.
12. UI filters changed/regressed Episodes and drills into side-by-side Evidence, not only aggregate numbers.

## Tests

- Unit: event-time scheduling, stage dependency, compatibility, lineage, isolation, comparison alignment, and cancellation.
- Determinism: 1×/2×/10×/50×/max replay yield identical structured output hashes.
- Stage replay: detector-only, ranker-only, plan-only, and full diagnosis use correct frozen upstream data.
- Experiment: two variants over a deterministic suite produce aligned per-Episode comparison.
- Immutability: original Run data/results never change.
- Failure: tampered/missing dataset, incompatible version, worker restart, quota, and partial variant failure.
- Security: no Gold access, cross-workspace source, or unregistered version override.
- Frontend E2E: create, monitor, cancel, compare, filter changed Episodes, and inspect evidence diff.

## Required evidence

- `docs/evidence/batch-19/manifest.json`.
- Replay speed output-hash comparison.
- Stage-dependency and source-lineage manifests.
- Sample Champion/Challenger experiment with aligned Episode diff.
- Original immutability/database assertion and output namespace inspection.
- Tamper/incompatibility/Gold-access denial reports.
- Restart/cancel trace, API/event schemas, migration, performance, and Playwright outputs.

## Definition of Done

- A completed Run replays through selected stages using frozen data without simulator rerun.
- Structured results are identical across supported speeds for identical versions.
- Variants remain isolated, source results immutable, and lineage complete.
- Comparison identifies per-Episode and aggregate changes with Evidence drill-down.
- Incompatible/tampered/missing inputs fail before execution.
- Experiments resume/cancel safely and respect quotas.
- Gold remains absent from replay/experiment execution contexts.

## Out of scope

- Computing Gold-based quality metrics, deciding release, online A/B against real control, and model training.
- Replacing the source dataset with regenerated approximations.

