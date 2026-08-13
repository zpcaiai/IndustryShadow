# Batch 03: Deterministic pump–valve–tank–heater simulator

## Context

- Completed dependencies: Batch 01 runtime foundation and Batch 02 published asset model.
- The simulator must express real causal relationships but is not a safety-certified digital twin.
- It runs independently from the control API and exposes a typed internal control interface.
- Snapshot/restore and injected faults are delivered in later batches; leave explicit extension ports.

## Outcome

- A published Pump Tank asset model can instantiate an executable process with pump, valves, tank, heater, sensors, actuator response, noise, and operating modes.
- Command changes produce physically plausible downstream responses.
- The simulator can run in deterministic virtual time and stream typed state frames for future OPC UA publication.

## Inputs

- Published asset-model digest and signal registry from Batch 02.
- Parameter set containing tank area, pump gain/curve, valve coefficients, thermal capacity/loss, ambient temperature, actuator response, current and vibration coefficients.
- Initial state and operating commands.
- Seed and fixed integration step, default 100 ms.

## Code modules

- `services/simulator/src/shadow_simulator/model/state.py`: immutable state/frame types.
- `services/simulator/src/shadow_simulator/model/equipment.py`: pump, valve, tank, heater, sensor components.
- `services/simulator/src/shadow_simulator/model/process.py`: coupled differential/update equations.
- `services/simulator/src/shadow_simulator/model/integrator.py`: fixed-step numerical integration.
- `services/simulator/src/shadow_simulator/model/modes.py`: startup, steady, shutdown, maintenance transitions.
- `services/simulator/src/shadow_simulator/runtime/engine.py`: lifecycle and frame production.
- `services/simulator/src/shadow_simulator/runtime/commands.py`: typed simulation-only commands.
- `services/simulator/src/shadow_simulator/config.py`: parameter validation.
- `services/simulator/src/shadow_simulator/api.py`: internal lifecycle/command endpoints.
- `domain-packs/pump-tank-v1/models/process-model.yaml` and parameter presets.
- `tests/scenario/simulator/` and `deploy/compose` simulator service.

## Interfaces

- `SimulatorEngine.initialize(model_ref, parameter_set, initial_state, seed, step_ms)`.
- `step(command_frame) -> StateFrame`; `run_until(simulation_time)`; `pause`; `stop`.
- `StateFrame` contains simulation time, mode, every signal value, quality, and model digest.
- Internal endpoints: `POST /internal/v1/simulators`, `/start`, `/pause`, `/step`, `/stop`, and `GET /state`.
- Command schema accepts Pump.SpeedCommand, Valve PositionCommand, Heater.PowerCommand, and mode transition only within registered ranges.
- Event `simulator.frame.produced.v1` is an internal typed interface; do not persist every frame through the metadata outbox.
- Error codes include invalid model, invalid command, invalid transition, numeric divergence, and resource conflict.

## Implementation requirements

1. Resolve signal keys through the published asset registry; do not hard-code NodeIds in equation code.
2. Implement `qin`, `qout`, level balance, temperature balance, motor current, vibration, actuator lag, bounded sensor noise, and pressure approximation.
3. Separate true physical state from sensor-observed state so later sensor faults do not corrupt physics.
4. Enforce non-negative level/flow, tank capacity, actuator saturation, power limits, and finite numbers.
5. Validate parameter units and ranges before initialization.
6. Use a fixed-step deterministic integrator; avoid wall-clock dependence in the model kernel.
7. Define valid mode transitions and mode-specific command constraints.
8. Produce a frame at every simulation step; allow publishers to downsample later.
9. Surface numeric divergence as a failed run with last valid frame, not as NaN propagation.
10. Instrument step duration, simulation lag, frame count, saturation, and constraint violations.
11. Add three deterministic parameter presets: nominal, high load, and low load.
12. Document the model equations, assumptions, valid domain, and non-safety status.

## Tests

- Unit: each component response, actuator lag, saturation, unit/range validation, invalid transitions, and noise bounds.
- Numerical: mass-balance and energy-balance residuals under nominal conditions within declared tolerance.
- Metamorphic: increased pump speed increases inlet flow; increased outlet opening increases outlet flow; heater power increases temperature slope.
- Property: state remains finite and within physical bounds across generated valid command sequences.
- Determinism: same inputs and seed produce identical frame hashes for a fixed platform.
- Scenario: startup to steady, pump step, valve step, heater step, shutdown, and maintenance.
- Integration: create simulator through the internal API in Compose and stream at least five minutes of virtual time.
- Performance: sustain the MVP signal set at 100 ms steps faster than real time on the reference environment.

## Required evidence

- `docs/evidence/batch-03/manifest.json`.
- Equation/unit reference and published parameter-set digests.
- Unit, property, metamorphic, scenario, and integration test reports.
- `nominal-frame-hashes.txt` for repeated deterministic runs.
- CSV/Parquet traces for pump, valve, heater, and mode-transition scenarios.
- Mass/energy-balance tolerance report and performance benchmark JSON.
- OpenTelemetry trace showing simulator creation, initialization, stepping, and stop.

## Definition of Done

- The simulator starts through Compose and consumes the published asset-model version.
- All required physical and observed signals are produced with stable types and units.
- Command-response scenarios visibly and numerically satisfy the declared causal relations.
- Invalid commands, invalid transitions, parameter errors, and numeric divergence fail safely.
- Nominal model balance and state bounds pass automated thresholds.
- Determinism and performance reports are generated from real execution, not static fixtures.
- No snapshot, fault, OPC UA, or real endpoint control behavior is falsely claimed.

## Out of scope

- Snapshot/restore, fault injection, OPC UA publication, industrial HIL accuracy, and closed-loop optimization.
- Any connection from the simulator process to real OT networks.

