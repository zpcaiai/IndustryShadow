# Batch 08: Fault runtime and ten fault operator families

## Context

- Completed dependencies: deterministic simulator/snapshots and published Scenario DSL.
- Faults must mutate declared physical, sensor, actuator, process, or communication surfaces without modifying scenario engine code.
- Fault runtime state must be snapshot-compatible and observable, while root-cause labels remain absent.

## Outcome

- Published scenarios can inject, ramp, pause, resume, clear, combine, and snapshot faults through a typed operator registry.
- Ten initial fault scenarios create the expected observable behaviors across sensors, actuators, mechanics, process, thermal, and communication layers.
- Fault lifecycle is deterministic and does not leak evaluator labels to Agent-facing data.

## Inputs

- `ResolvedScenario` and operator reference contract from Batch 07.
- True/observed state separation, command path, clock, and snapshot envelope from Batches 03–04.
- OPC UA publisher and Collector fault-simulation hooks from Batches 05–06.
- Published asset signals, parameter boundaries, and mutable-surface declarations.

## Code modules

- `services/simulator/src/shadow_simulator/faults/protocol.py`: operator interface and context.
- `services/simulator/src/shadow_simulator/faults/registry.py`: signed/declared operator registry.
- `services/simulator/src/shadow_simulator/faults/runtime.py`: lifecycle, ordering, combination, and state.
- `services/simulator/src/shadow_simulator/faults/operators/sensor.py`.
- `services/simulator/src/shadow_simulator/faults/operators/communication.py`.
- `services/simulator/src/shadow_simulator/faults/operators/actuator.py`.
- `services/simulator/src/shadow_simulator/faults/operators/mechanical.py`.
- `services/simulator/src/shadow_simulator/faults/operators/process.py`.
- `services/simulator/src/shadow_simulator/snapshot/codec.py`: active fault serialization.
- `domain-packs/pump-tank-v1/faults/catalog.yaml` and `scenarios/faults/F01..F10.yaml`.
- `schemas/scenarios/fault-spec-v1.json` and lifecycle event schema.

## Interfaces

- `FaultOperator.validate(spec, asset_model, process_model)`.
- `activate(context)`, `apply(step_context, state, observed_frame)`, `deactivate(context)`, `snapshot_state`, and `restore_state`.
- Operators: bias, drift, stuck_at, noise_increase, spike, delay, dropout, reorder, multiplier/ramp, intermittent; domain aliases implement stiction, blockage, leak, friction, and heater-stuck behavior.
- Combination policies: reject, ordered composition, additive, multiplicative, last-wins only when explicitly safe.
- Events `fault.activated.v1`, `fault.updated.v1`, `fault.cleared.v1`, and `fault.rejected.v1` contain target/operator/timing but not Gold root-cause labels.
- Fault scenarios F01–F10 map to LT bias, FT stuck, PT noise, inlet valve stiction, pump efficiency loss, bearing friction, outlet blockage, tank leak, heater stuck, and OPC UA delay/dropout.
- Runtime status API is internal and exposes active operator metadata needed for debugging, not evaluator truth.

## Implementation requirements

1. Separate mutation surfaces: sensor faults change observed values; physical faults change true process state/parameters; communication faults change delivery, not source state.
2. Execute operators at deterministic step boundaries using virtual time.
3. Validate target kind, units, parameter bounds, duration, severity, and combination policy before run start.
4. Serialize all active operator internal state and RNG state in snapshots.
5. Ensure clearing a fault returns control to the correct underlying state and does not reset unrelated process variables.
6. Communication delay/reorder/dropout must preserve traceability to the source frame.
7. Implement three severity profiles and nominal/high/low load variants for each F01–F10 scenario.
8. Provide operator metrics for activation, duration, rejected spec, and affected frames.
9. Prevent arbitrary Python import, expression evaluation, shell, network, or file access from fault specs.
10. Keep root-cause IDs, expected symptoms, and required checks outside Scenario and runtime events.
11. Maintain backward compatibility for pre-fault snapshots and reject incompatible operator codecs.
12. Generate deterministic expected-symptom traces for engineering validation, stored outside Agent inputs.

## Tests

- Unit: every operator's activation, progression, clearing, bounds, combination, serialization, and restore.
- Property: valid severities never produce NaN/inf or mutate undeclared signals.
- Determinism: same seed/scenario yields the same fault lifecycle and event/frame hashes.
- Snapshot: snapshot during every stateful operator, restore, and compare future output.
- Scenario: run F01–F10 across at least one load/severity/seed and assert physical symptom direction.
- Full matrix smoke: 10 faults × 3 severity × 3 load with deterministic seeds.
- Communication: prove delay, gap, reorder, and multiple-node stale behavior in Collector output.
- Security: reject unsafe target, operator, expression, path, import, and combination payloads.

## Required evidence

- `docs/evidence/batch-08/manifest.json`.
- Operator unit/property/snapshot test reports.
- F01–F10 scenario result table showing activated target, expected directional evidence, and pass/fail.
- Full matrix summary with scenario/seed/model/operator digests.
- Communication fault raw-event capture proving timestamps/gaps/reorder.
- Gold-leak scan of Scenario, runtime events, logs, traces, and Agent-visible APIs.
- Unsafe DSL payload rejection report and simulator stability metrics.

## Definition of Done

- All ten initial faults run through published Scenario Specs without editing simulator engine branches.
- Sensor, physical, actuator, process, thermal, and communication mutations affect only declared surfaces.
- Active faults survive snapshot/restore deterministically.
- Severity and load variations produce expected directional symptoms without numeric instability.
- Clearing faults and ending scenarios leave no leaked operator state.
- Agent-visible outputs contain no root-cause labels or Gold keys.
- Unsafe specifications are rejected before execution and backed by adversarial tests.

## Out of scope

- Gold scoring, automated diagnosis, arbitrary third-party fault plugins, and real equipment fault injection.
- Claims that simplified fault dynamics equal a certified real plant model.

