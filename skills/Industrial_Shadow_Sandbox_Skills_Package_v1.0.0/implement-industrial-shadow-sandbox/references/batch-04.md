# Batch 04: Snapshot, restore, deterministic clock, and reproducibility

## Context

- Completed dependencies: Batch 03 executable process model and typed simulator lifecycle.
- Reproducible snapshots are required before fault injection, virtual recovery, replay, or regression evaluation.
- Snapshot fidelity includes internal controller, event queue, and random generator state, not only visible signal values.

## Outcome

- Any running simulator can create an immutable snapshot, restore it, branch from it, and reproduce the same future frames for the same commands.
- Virtual time supports real-time, accelerated, paused, and manual-step modes without changing model results.
- Snapshot integrity, compatibility, lineage, and retention are explicit and tested.

## Inputs

- `SimulatorEngine`, state, modes, parameter set, command types, and model digest from Batch 03.
- Object/file storage abstraction from Batch 01; local filesystem implementation is acceptable for MVP.
- Snapshot policy: pre-run, pre-fault, pre-action, manual, and checkpoint reasons.
- Floating-point comparison policy and reference platform metadata.

## Code modules

- `services/simulator/src/shadow_simulator/runtime/clock.py`: deterministic virtual clock and speed policy.
- `services/simulator/src/shadow_simulator/snapshot/model.py`: versioned snapshot envelope.
- `services/simulator/src/shadow_simulator/snapshot/codec.py`: canonical serialization and hash.
- `services/simulator/src/shadow_simulator/snapshot/store.py`: storage port and local implementation.
- `services/simulator/src/shadow_simulator/snapshot/service.py`: create, validate, restore, branch, and retention.
- `services/simulator/src/shadow_simulator/runtime/engine.py`: snapshot hooks and state restoration.
- `backend/src/shadow_sandbox/runtime/snapshot_registry.py`: metadata and lineage registry.
- `migrations/*_snapshot_registry.py`.
- `schemas/api/snapshot*.json` and `schemas/events/snapshot-created-v1.json`.
- `web/src/features/simulator/SnapshotPanel.vue` and clock controls.

## Interfaces

- `SnapshotEnvelopeV1`: snapshot ID, simulator ID, reason, simulation time, model/parameter/asset digests, dynamic states, controller states, RNG state, active faults placeholder, pending events, codec version, platform, and content hash.
- `SnapshotService.create(simulator_id, reason) -> SnapshotRef`.
- `validate(snapshot_ref, target_model_ref) -> CompatibilityResult`.
- `restore(simulator_id, snapshot_ref)` and `branch(snapshot_ref) -> simulator_id`.
- Internal routes: `POST /internal/v1/simulators/{id}/snapshots`, `/restore`, `/branches`.
- User routes: `GET /api/v1/snapshots/{id}` exposes metadata but not arbitrary raw serialized state.
- Events `snapshot.created.v1`, `snapshot.restored.v1`, and `snapshot.rejected.v1`.
- Clock API: speed factors `0`, `1`, `2`, `10`, `50`, plus manual step; unsupported factors are rejected.

## Implementation requirements

1. Serialize every state that can influence future output, including pseudo-random generator and pending scheduled events.
2. Canonicalize serialization and compute SHA-256; verify before restore.
3. Reject incompatible model, parameter, codec, or asset-model versions unless an explicit migration exists.
4. Use copy-on-write or immutable snapshot objects; never mutate stored snapshots.
5. Record parent snapshot and branch lineage.
6. Pause at a deterministic step boundary before snapshot and restore.
7. Keep virtual-time results independent of host sleep, CPU scheduling, or requested speed factor.
8. On restore failure, preserve the existing running state and return an atomic failure.
9. Add storage quotas and retention hooks without deleting snapshots referenced by actions, replays, or reports.
10. Expose snapshot/restore spans and byte-size metrics.
11. UI must require confirmation before restoring and display compatibility errors.
12. Reserve `active_faults` in the envelope for Batch 08 and prove backward-compatible decoding.

## Tests

- Unit: clock modes, canonical encoding, hash verification, compatibility matrix, lineage, quota, and retention protection.
- Determinism: snapshot at time T, execute command sequence, restore, repeat, and compare all frame hashes.
- Speed invariance: 1×, 10×, 50×, and manual step generate the same virtual frames.
- Failure: corrupt bytes, wrong model digest, unsupported codec, full storage, restore interruption, and concurrent restore.
- API/event contract: schemas and stable error codes.
- Integration: create/restore/branch through real services and persistent snapshot metadata.
- Frontend: snapshot list, create, confirm restore, branch, loading/error/incompatible states.
- Performance: snapshot and restore complete within a declared MVP threshold for the Pump Tank state.

## Required evidence

- `docs/evidence/batch-04/manifest.json`.
- Repeated frame-hash comparison for snapshot round trip and all speed modes.
- Snapshot compatibility/failure matrix JSON.
- API/event schema validation and database migration logs.
- Integration logs and trace spans for create, restore, branch, and rejected restore.
- Snapshot size/time benchmark JSON.
- Playwright trace proving the UI performs real create/restore requests.

## Definition of Done

- A snapshot restored into the same compatible build reproduces future frames exactly or within the documented cross-platform tolerance.
- Speed factor changes wall-clock duration but not virtual results.
- Corruption and incompatible versions are rejected without altering the current simulator.
- Snapshot lineage and protected references persist in PostgreSQL.
- UI and APIs expose real operations with safe confirmation and stable errors.
- Evidence includes actual snapshot files/hashes and real replayed frame comparisons.
- No test marks a non-deterministic run as successful by widening tolerance without justification.

## Out of scope

- Fault-state serialization behavior beyond the reserved contract, Agent pipeline replay, and production object-store lifecycle.
- Snapshot of real industrial equipment or any attempt to restore a real endpoint.

