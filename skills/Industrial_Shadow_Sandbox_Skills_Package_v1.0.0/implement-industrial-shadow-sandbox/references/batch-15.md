# Batch 15: Discriminative check library and safe plan ordering

## Context

- Completed dependency: evidence-backed Top-3 hypotheses or an explicit inconclusive result.
- Checks should maximize discrimination at low time/cost/risk while respecting safety ordering.
- Real-environment checks are advisory only; active tests in this product are simulation-only.

## Outcome

- The platform generates an ordered, typed Check Plan showing what each step distinguishes, expected outcomes by candidate, cost, risk, prerequisites, and rollback.
- Plans begin with data quality/non-invasive checks and route active/stopping actions to approval.
- Missing signals, unsafe combinations, circular prerequisites, and forbidden real actions are rejected.

## Inputs

- DiagnosisResult, Hypotheses, Evidence, and quality state from Batches 13–14.
- Asset model/topology and environment type.
- Versioned check catalog, candidate outcome matrix, safety policy, and cost model from the Domain Pack.
- Simulator capabilities from Batches 03–05; no real action executor is available.

## Code modules

- `backend/src/shadow_sandbox/planning/entities.py`: check definition, plan, step, expected result, risk.
- `backend/src/shadow_sandbox/planning/catalog.py`: versioned check registry and validation.
- `backend/src/shadow_sandbox/planning/information_gain.py`: discriminative utility.
- `backend/src/shadow_sandbox/planning/planner.py`: candidate-aware ordering.
- `backend/src/shadow_sandbox/planning/safety.py`: environment/action/prerequisite policies.
- `backend/src/shadow_sandbox/planning/service.py`, `api.py`, and `events.py`.
- `migrations/*_check_plans.py`.
- `domain-packs/pump-tank-v1/checks/check-library.yaml` and planning policy.
- `schemas/api/check-plan*.json` and event schema.
- `web/src/features/diagnosis/CheckPlanPanel.vue` and plan diff/editor components.

## Interfaces

- `CheckDefinitionV1`: check ID/version, asset applicability, required signals/tools, candidate outcome matrix, duration/cost/risk, invasiveness, environment support, preconditions, success/failure, and rollback.
- `CheckStepV1`: sequence, resolved target/parameters, rationale, hypotheses distinguished, expected results, evidence inputs, risk, approval requirement, and dependencies.
- `CheckPlanV1`: Run/diagnosis refs, plan version/hash, steps, rejected checks, coverage, estimated cost/time, safety summary, and status.
- `POST /api/v1/runs/{id}/check-plans`; `GET /check-plan`; `POST /check-plans/{id}/reorder-preview` validates an edited order without approving.
- Events `check_plan.ready.v1`, `check_plan.rejected.v1`, and `check_plan.superseded.v1`.
- Planner outputs a proposal only; execution does not exist until Batch 18.

## Implementation requirements

1. Seed checks for data quality, command/actual, pressure-flow curve, current/vibration, mass balance, heat response, virtual step response, isolation, and post-recovery verification.
2. Compute documented utility from candidate separation/information gain, candidate relevance, time, cost, and risk.
3. Enforce ordering: data quality → non-invasive comparison → residual → simulator active test → isolation/stop suggestion.
4. Mark any active, setpoint, stop, isolate, or recovery-related step approval-required.
5. Set `simulation_only=true` for active tools and reject them for real endpoint environments.
6. Validate required signals, asset capabilities, mode, prerequisites, conflicts, cycles, and rollback coverage.
7. Include expected observations per remaining hypothesis and define how a result updates discrimination.
8. Ensure critical post-action recovery verification cannot be optimized away.
9. Plan from `INCONCLUSIVE` by requesting safe information-gathering checks, not a recovery action.
10. Compute a canonical plan hash from all executable details and policy versions.
11. Treat user reorder/edit as a new proposed version requiring revalidation.
12. Instrument planning latency, candidate coverage, unavailable checks, risk distribution, and plan revisions.

## Tests

- Unit: utility, ordering, prerequisites, cycles, missing signals, conflicts, risk, plan hash, and supersession.
- Scenario: plans for F01–F10 include relevant discriminative checks and post-verification.
- Pair discrimination: F01/F08, F04/F07, F05/F06, and F10 prioritize checks that separate the pair.
- Safety: active/stop/isolate steps require approval and are rejected for real environment types.
- Inconclusive: only information-gathering checks are proposed under insufficient evidence.
- Contract: API/event schemas and edit/reorder preview errors.
- Frontend: render rationale/expected results/risk, edit order, display invalid edit and plan diff.
- Determinism: same diagnosis/catalog/policy yields the same plan/hash.

## Required evidence

- `docs/evidence/batch-15/manifest.json`.
- Published check-library digest and catalog-validation report.
- F01–F10 plan summary and pair-discrimination plan report.
- Safety matrix proving approval flags and real-environment rejection.
- Deterministic plan hashes and edit/supersession traces.
- API/event test, migration, latency, and OTel reports.
- Playwright evidence for plan inspection and valid/invalid reorder preview.

## Definition of Done

- Every ranked or inconclusive diagnosis produces a persisted, versioned plan or an explicit no-safe-check result.
- Plan steps include typed inputs, rationale, expected candidate outcomes, cost, risk, prerequisites, success/failure, and rollback where applicable.
- Safety ordering and required post-verification are enforced server-side.
- Simulation-only steps cannot be planned as executable against a real endpoint.
- Plan edits create a revalidated version and a new canonical hash.
- Tests demonstrate candidate-pair discrimination and inconclusive-safe behavior.
- No plan step executes in this batch.

## Out of scope

- Approval decisions, action execution, CMMS dispatch, learned policy optimization, and real equipment active tests.
- Free-form shell or arbitrary script checks.

