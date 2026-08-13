# Batch 12: Process residuals and cross-signal consistency

## Context

- Completed dependencies: trusted quality windows, anomaly observations, published process/asset models, and operating-mode context.
- Industrial diagnostic value comes primarily from physical and command-response consistency, not isolated thresholds.
- Residual definitions are versioned Domain Pack assets and execute through a registered function interface.

## Outcome

- The platform computes mass, heat, pump, valve/command, current/load, and vibration residuals over trusted data.
- Cross-signal rules detect physically inconsistent behavior and distinguish process/equipment faults from sensor/communication faults.
- Every result declares applicability, input quality, tolerance, formula version, and source evidence range.

## Inputs

- Raw/quality/anomaly query interfaces from Batches 06 and 11.
- Asset topology, units, signal semantics, process equations, and parameter sets from Batches 02–03.
- Mode timeline and Run Manifest from Batch 10.
- F01–F10 traces for validation; Gold labels remain unavailable to the runtime.

## Code modules

- `backend/src/shadow_sandbox/diagnosis/residuals/protocol.py`: registered residual contract.
- `backend/src/shadow_sandbox/diagnosis/residuals/mass_balance.py`.
- `backend/src/shadow_sandbox/diagnosis/residuals/thermal_balance.py`.
- `backend/src/shadow_sandbox/diagnosis/residuals/pump_performance.py`.
- `backend/src/shadow_sandbox/diagnosis/residuals/command_response.py`.
- `backend/src/shadow_sandbox/diagnosis/residuals/mechanical.py`.
- `backend/src/shadow_sandbox/diagnosis/consistency/rule_dsl.py` and `engine.py`.
- `backend/src/shadow_sandbox/diagnosis/residuals/service.py`.
- `migrations/*_residual_observations.py`.
- `domain-packs/pump-tank-v1/models/residuals.yaml` and `rules/cross-signal.yaml`.
- `web/src/features/runs/ResidualPanel.vue`.

## Interfaces

- `ResidualDefinitionV1`: ID/version, required signals/units, modes, window policy, parameters, formula implementation key, tolerance, and interpretation.
- `ResidualObservationV1`: Run/window, residual ref, observed/expected values, normalized magnitude/direction, applicability, input-quality refs, source-event refs, and digest.
- `ConsistencyRuleV1`: typed conditions over registered anomaly/residual/signal features, temporal relation, minimum quality, and emitted observation code.
- `POST /api/v1/runs/{id}/residuals-and-consistency`; `GET /residuals`, `/consistency-observations`.
- Events `residual.observed.v1` and `consistency.observed.v1`.
- Registered residual execution accepts typed arrays/metadata only; no arbitrary expression eval or user code.

## Implementation requirements

1. Implement mass residual using level derivative and inlet/outlet flows with unit-consistent tank area.
2. Implement heat residual using temperature derivative, heater power, ambient loss, and thermal capacity.
3. Implement pump expected-flow/performance residual from speed and pressure/flow curve.
4. Implement command-actual residual with delay/deadband tolerance for pump/valves/heater.
5. Implement current/load and vibration/mechanical residuals for F05/F06 discrimination.
6. Use robust derivative/filter windows and account for startup/transition non-applicability.
7. Propagate quality: missing or untrusted required input makes the result `NOT_APPLICABLE` or `UNTRUSTED`, not zero.
8. Validate units and required signals when publishing a Domain Pack.
9. Make thresholds and normalization mode/load aware and versioned.
10. Express cross-signal rules as a safe declarative DSL with bounded operators and temporal windows.
11. Reference raw/quality/anomaly inputs and formula/config digests in every observation.
12. Instrument runtime, non-applicability, threshold crossings, and rule firings.

## Tests

- Unit: each formula against hand-calculated fixtures, unit conversions, bounds, derivative/filter behavior, and quality propagation.
- Metamorphic: conservation residual remains near zero nominally; leak increases negative mass residual; blockage affects pressure/flow relation.
- Scenario: F01–F10 produce the expected residual/consistency signature without using Gold in execution.
- Discrimination: F05 efficiency loss versus F06 friction; F01 sensor bias versus F08 leak; F07 blockage versus valve stiction.
- Normal: startup, shutdown, setpoint changes, and noise remain within mode-aware behavior.
- Security: rule DSL rejects code execution, unbounded recursion, unknown fields, and cross-workspace data.
- Determinism: same frozen input yields identical observations.
- Performance: all MVP residuals complete within the detection latency budget.

## Required evidence

- `docs/evidence/batch-12/manifest.json`.
- Formula and unit-validation reference with hand-calculated expected values.
- Nominal residual tolerance report and F01–F10 signature matrix.
- Pairwise discrimination report for F05/F06, F01/F08, and F07/F04.
- Safe-rule-DSL adversarial test log.
- Deterministic rerun hashes, performance benchmark, schemas, migration, and OTel traces.
- UI trace showing observed/expected/residual/quality/source windows.

## Definition of Done

- Six residual families and cross-signal rules run on persisted Run data through registered implementations.
- Nominal conservation errors remain inside documented tolerances across normal modes where applicable.
- Target fault pairs produce distinguishable evidence signatures in automated scenarios.
- Untrusted/missing inputs never become normal residuals.
- Unit, mode, load, tolerance, formula, and source references accompany every result.
- Rule DSL cannot execute arbitrary code or access undeclared data.
- Outputs are deterministic and ready for conversion into first-class Evidence and Symptoms.

## Out of scope

- Root-cause candidate generation, score weighting, LLM narrative, and recovery planning.
- Model parameter identification from real factory data.

