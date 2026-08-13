# Batch 07: Scenario DSL, schema validation, and publishing

## Context

- Completed dependencies: versioned asset/process models, deterministic simulator, snapshots, and data collection.
- Scenarios must be data, not Python branches, so faults and operating conditions can be reviewed, versioned, migrated, and batch-generated.
- Gold answers are deliberately excluded here and delivered through the isolated Batch 09 boundary.

## Outcome

- Engineers can author, validate, preview, publish, import, and export immutable Scenario Specs.
- A Scenario references exact asset/process versions, initial state, operating profile, clock, seed, timeline, disturbances, and injections without exposing expected answers.
- Invalid target, units, ranges, times, conflicts, or incompatible versions are rejected with source-located errors.

## Inputs

- Asset and signal resolver from Batch 02.
- Process model parameters and simulator command schema from Batch 03.
- Snapshot references and clock speed/step policy from Batch 04.
- Fault operator registry interface; Batch 08 fills the concrete operators.
- YAML 1.2 parser capable of preserving useful line/column locations.

## Code modules

- `backend/src/shadow_sandbox/scenarios/entities.py`: draft, version, dependency, and publication entities.
- `backend/src/shadow_sandbox/scenarios/dsl.py`: Pydantic Scenario Spec v1.
- `backend/src/shadow_sandbox/scenarios/parser.py`: YAML/JSON parsing and location mapping.
- `backend/src/shadow_sandbox/scenarios/validation.py`: semantic validation and conflict checks.
- `backend/src/shadow_sandbox/scenarios/service.py`: draft, preview, publish, import, and export.
- `backend/src/shadow_sandbox/scenarios/repository.py`, `api.py`, and `events.py`.
- `migrations/*_scenario_registry.py`.
- `schemas/scenarios/scenario-spec-v1.json` and publication event schema.
- `web/src/features/scenarios/`: list, editor, timeline preview, dependency, validation, and version views.
- `domain-packs/pump-tank-v1/scenarios/normal/` and initial fault scenario drafts.

## Interfaces

- Scenario fields: schema version, stable ID/version, tags, model refs, seed, duration/warmup, initial state/snapshot, operating profile, clock, timeline, and metadata.
- Timeline item union: command, mode transition, disturbance, fault injection reference, annotation, and snapshot marker.
- `POST /api/v1/scenarios`, `GET/PATCH /api/v1/scenarios/{id}` with optimistic lock.
- `POST /api/v1/scenarios/{id}/validate` returns severity, code, JSON Pointer, YAML line/column, and remediation hint.
- `POST /api/v1/scenarios/{id}/preview` returns resolved timeline and affected signals without running.
- `POST /api/v1/scenarios/{id}/publish`; `GET /api/v1/scenario-versions/{id}`.
- Event `scenario.published.v1` includes dependency digests and Scenario digest.
- `ScenarioResolver.resolve(version_ref) -> ResolvedScenario` is consumed by the Run Orchestrator.

## Implementation requirements

1. Publish JSON Schema and generate it from the authoritative typed model or verify equivalence in CI.
2. Resolve all asset, signal, model, parameter, snapshot, and operator references at validation time.
3. Validate units, value type/range, warmup/duration, timeline order, overlap, and mode prerequisites.
4. Require an explicit merge policy for two timeline items that mutate the same target concurrently.
5. Canonicalize and digest resolved content; exclude authoring whitespace and timestamps.
6. Keep published versions immutable and protect versions referenced by Runs.
7. Support Schema v1 migration entry points and reject unsupported future versions.
8. Keep Gold fields forbidden in Scenario Spec at parser and database boundaries.
9. Preview the resolved timeline and virtual-time positions in the UI.
10. Seed normal startup, normal shutdown, load step, valve adjustment, heater cycle, and network-jitter-compatible scenarios.
11. Emit publication through the outbox.
12. Do not execute a Scenario in this batch; execution enters Batch 10 after faults exist.

## Tests

- Unit: parser locations, canonical digest, target/type/unit/range/time checks, overlap/merge, dependency resolution.
- Schema: valid examples accepted; Gold keys, unknown fields, invalid operators, and future versions rejected.
- Import/export: YAML and JSON round trip to the same digest.
- Repository/API: optimistic lock, immutability, ownership, publication event, referenced-version protection.
- Frontend: valid and invalid YAML, pointer/line errors, resolved timeline preview, version view.
- Security: large/deep YAML limits, unsafe YAML tags, alias bombs, and cross-workspace references.
- Compatibility: Scenario schema remains usable after non-breaking asset display-name changes but fails on deleted signal refs.
- Integration: publish all seeded normal scenarios against the real model registry.

## Required evidence

- `docs/evidence/batch-07/manifest.json`.
- Generated `scenario-spec-v1.json` digest and example-validation report.
- YAML security test report and parser-limit configuration.
- Round-trip digests and dependency-resolution matrix.
- API/event contract tests, migration log, and outbox payload.
- Playwright trace for author/validate/preview/publish.
- Published normal-scenario catalog with no Gold content.

## Definition of Done

- Seeded normal scenarios publish through the API and reference immutable compatible model versions.
- Invalid target, time, type, unit, range, conflict, unsafe YAML, and Gold key cases fail with actionable source locations.
- Canonical digest is stable across YAML formatting and import/export.
- Published scenarios are immutable and protected when referenced.
- UI preview and validation use live backend results.
- Scenario payloads, logs, evidence, and events contain no Gold fields.
- The operator extension port is typed and ready for Batch 08 without hard-coded fault branches.

## Out of scope

- Concrete fault mutation behavior, Gold labels, suite execution, diagnosis, and recovery actions.
- Arbitrary executable code embedded in YAML.

