# Batch 18: Simulation-only actions, verification, and rollback

## Context

- Completed dependencies: simulator snapshots/fault runtime, Check Plans, Control Plane policy, and cryptographically bound approvals.
- This is the first side-effect batch; its network, identity, typing, idempotency, and evidence gates are safety-critical.
- The executor must be physically unable to reach real OT endpoints, not merely configured not to.

## Outcome

- Approved typed checks/recovery actions execute only against an attested simulator.
- Every action creates a pre-action snapshot, records exactly-once execution, observes a verification window, classifies outcome, and rolls back when required.
- Real, unknown, changed, or policy-incompatible targets are rejected and audited.

## Inputs

- Approved plan and `ApprovalVerifier` from Batch 17.
- Simulator identity, internal typed command/fault/snapshot interfaces from Batches 03–08.
- Evidence/residual/anomaly recomputation services from Batches 11–13.
- Action catalog matching approved Check Definitions.
- Sandbox network policy and simulator CA/identity allowlist.

## Code modules

- `backend/src/shadow_sandbox/actions/entities.py`: action definition/execution/outcome.
- `backend/src/shadow_sandbox/actions/catalog.py`: typed action registry.
- `backend/src/shadow_sandbox/actions/policy.py`: approval, environment, network, parameter, and state gates.
- `backend/src/shadow_sandbox/actions/executor.py`: orchestration and exactly-once action ledger.
- `backend/src/shadow_sandbox/actions/verification.py`: post-action observation and outcome.
- `backend/src/shadow_sandbox/actions/rollback.py`.
- `backend/src/shadow_sandbox/actions/repository.py`, `api.py`, and `events.py`.
- `migrations/*_action_executions.py`.
- `domain-packs/pump-tank-v1/checks/action-catalog.yaml`.
- `deploy/compose/compose.sandbox.yaml` and network reachability tests.
- `web/src/features/actions/ActionExecutionPanel.vue`.

## Interfaces

- Actions: clear_sensor_bias, release_valve_stiction, restore_pump_efficiency, clear_pipeline_blockage, restore_communication_profile, turn_off_stuck_heater, run_virtual_step_test, and restore_snapshot.
- `ActionRequestV1`: Run/action/check/approval IDs, plan hash, simulator identity digest, typed parameters, idempotency key, verification policy, and trace.
- `ActionExecutionV1`: claimed/started/completed/failed/rolled_back, pre/post snapshots, simulator responses, verification Evidence refs, outcome, and digests.
- `POST /api/v1/actions` accepts only an approved action request; `GET /actions/{id}` and `/runs/{id}/actions`.
- Events `virtual_action.claimed/started/completed/failed/rolled_back.v1` and `policy.violation.v1`.
- `SandboxAdapter` supports only the typed simulator operations; it has no generic URL, NodeId, script, or OPC UA client parameter.

## Implementation requirements

1. Run the executor in a separate Sandbox network with allowlist to simulator service only and no route/DNS/credentials for OT.
2. Attest endpoint type, CA/fingerprint, application identity, model/run binding, and simulator process identity immediately before action.
3. Verify approval, plan hash, step, parameters, policy, expiry, and unconsumed/idempotent state in one claim transaction.
4. Create and verify the pre-action snapshot before mutation.
5. Execute through typed adapters; never accept arbitrary endpoint, NodeId, code, command, or file path.
6. Persist action ledger before/after each external interaction and reconcile on restart.
7. Observe the configured 60–120 second virtual verification window and recompute quality/anomaly/residual Evidence.
8. Classify `RECOVERED`, `NO_EFFECT`, `WORSE`, `INCONCLUSIVE`, or `EXECUTION_FAILED` using versioned policy.
9. Roll back automatically for failure/worse or policy-defined conditions; verify rollback frame hashes/state.
10. Keep pre/post/rollback snapshots protected by Run/action/report retention.
11. Emit high-severity audit/alert for any real/unknown target or network-policy violation.
12. UI displays progress, snapshots, Evidence-based outcome, rollback, and immutable approval link.

## Tests

- Unit: catalog/type/range, approval binding, environment attestation, idempotent claim, outcome classification, rollback conditions.
- Integration: execute every action type against corresponding F01–F10 simulator state and verify expected recovery Evidence.
- Exactly once: kill executor before/after claim and external call; reconcile without duplicate logical action.
- Race: expiry/revocation/plan change/simulator restart/identity change during claim.
- Network safety: prove Sandbox cannot resolve/connect to configured real OT test subnet/endpoint while it can reach simulator.
- Negative: arbitrary URL/NodeId/script/unknown action and tampered approval all fail.
- Rollback: induce action failure/worse result and compare restored state/frame hash to pre-action snapshot.
- Frontend E2E: approved execution, no-effect, failure, rollback, and policy rejection.

## Required evidence

- `docs/evidence/batch-18/manifest.json`.
- Action-type recovery matrix for F01–F10 with pre/post Evidence refs.
- Network reachability/egress-denial report and executor dependency inventory.
- Approval/plan/simulator binding and tamper-denial logs.
- Kill/restart exactly-once trace and action ledger inspection.
- Snapshot/rollback hash comparison and outcome classification report.
- API/event schemas, migration, Playwright, and OTel evidence.

## Definition of Done

- Each registered action executes through a typed simulator-only adapter after a valid bound approval.
- Pre-action snapshot, action ledger, verification window, post Evidence, outcome, and rollback decision exist for every attempt.
- Kill/restart and duplicate request tests prove exactly-once logical behavior.
- Sandbox network and dependency tests prove no route or generic client to real OT.
- Real/unknown/tampered targets fail before side effects and produce policy violations.
- Recovery/no-effect/worse/inconclusive outcomes are Evidence-based and visible in UI/report-ready data.
- No real-device control path is added anywhere in the repository.

## Out of scope

- Real PLC/OPC UA writes, real maintenance execution, automatic approval, and unconstrained scripting.
- Claiming simulator recovery guarantees physical repair success.

