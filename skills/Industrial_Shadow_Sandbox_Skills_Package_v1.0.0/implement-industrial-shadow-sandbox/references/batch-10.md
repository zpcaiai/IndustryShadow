# Batch 10: Durable run orchestration and lifecycle state machine

## Context

- Completed dependencies: models, simulator, snapshots, OPC UA, Collector, scenarios/faults, Gold isolation, and suites.
- This batch creates the first complete execution path from Scenario selection through collected raw data, but stops before diagnostic interpretation.
- State and side effects must survive process restarts without duplicate simulator, Collector, fault, or snapshot operations.

## Outcome

- Users can start, monitor, pause, resume, cancel, retry, and batch-run Scenarios or Suites.
- Each Episode receives an immutable Run Manifest and progresses through a durable, auditable state machine.
- Restart and retry preserve exactly-once logical effects through idempotency and reconciliation.

## Inputs

- Scenario/Suite resolver and Episode manifests from Batch 09.
- Simulator, snapshot, OPC UA endpoint, and Collector lifecycle APIs from Batches 03–06.
- Transactional outbox, correlation, database, and problem details from Batch 01.
- Resource limits: maximum concurrent Episodes, duration, virtual-time steps, storage, and queue depth.

## Code modules

- `backend/src/shadow_sandbox/runtime/entities.py`: Run, Episode, manifest, transition, task, lease, idempotency.
- `backend/src/shadow_sandbox/runtime/state_machine.py`: allowed states and transitions.
- `backend/src/shadow_sandbox/runtime/orchestrator.py`: workflow coordination.
- `backend/src/shadow_sandbox/runtime/tasks.py`: resumable worker tasks and reconciliation.
- `backend/src/shadow_sandbox/runtime/resource_manager.py`: concurrency and quota.
- `backend/src/shadow_sandbox/runtime/repository.py`, `api.py`, and `events.py`.
- `backend/src/shadow_sandbox/runtime/adapters/`: simulator, Collector, snapshot, and scenario ports.
- `migrations/*_run_orchestration.py`.
- `schemas/api/run*.json` and `schemas/events/run-*-v1.json`.
- `web/src/features/runs/`: launch form, queue, details, progress, timeline, pause/cancel.

## Interfaces

- States: `REQUESTED`, `VALIDATING`, `QUEUED`, `PROVISIONING`, `WARMING_UP`, `RUNNING`, `COLLECTING_FINAL`, `COMPLETED`; side states `PAUSED`, `CANCELLING`, `CANCELLED`, `FAILED_RETRYABLE`, `FAILED_FINAL`.
- `RunManifestV1`: scenario/suite/episode, asset/process/parameter/snapshot/operator/build/config digests, seed, clock, endpoint identity, collector policy, and requested stages.
- `POST /api/v1/runs` and `/scenario-suites/{id}/runs` require Idempotency-Key.
- `GET /api/v1/runs/{id}`, `/timeline`, `/tasks`; command routes `/pause`, `/resume`, `/cancel`, `/retry`.
- Events `run.requested/started/state_changed/completed/failed/cancelled.v1`.
- Adapter operations carry run/task/idempotency IDs and expose reconcile/status methods.
- SSE or WebSocket progress stream may be used, with polling fallback.

## Implementation requirements

1. Persist state before and after every external effect; use leases and idempotency records.
2. Validate immutable dependency digests and resource budgets before queueing.
3. Provision a simulator, bind Collector to run context, create pre-run snapshot, warm up, inject timeline, finalize collection, and release resources.
4. Keep Gold entirely outside the orchestration context; only store its opaque sealed version/digest for later evaluator lookup.
5. Define legal transitions and reject stale/concurrent commands using version numbers.
6. Pause only at safe step boundaries; resume from persisted state.
7. Cancellation must stop simulator/Collector, flush data, release leases, and record partial dataset status.
8. Retry only retryable tasks and reconcile actual external state before repeating a command.
9. Suite execution respects concurrency and storage quotas and exposes per-Episode plus aggregate progress.
10. Capture failure code, failing task, retry count, last safe state, and remediation.
11. Instrument queue wait, stage duration, retries, cancellation latency, and resource use.
12. UI must show real timeline and distinguish waiting, running, paused, failed, cancelled, and completed states.

## Tests

- Unit: every legal/illegal transition, optimistic concurrency, lease expiry, quota, retry classification, cancellation cleanup.
- Contract: Run APIs/events/manifest schemas and idempotency behavior.
- Integration: execute one normal and one fault Scenario through real simulator, OPC UA, Collector, PostgreSQL, and Parquet.
- Suite: run a small deterministic subset with concurrency cap and stable Episode IDs.
- Restart: kill worker at provisioning, warmup, running, and finalization; restart and prove no duplicate logical effect.
- Failure: simulator unavailable, Collector disconnect, storage error, invalid digest, timeout, and resource exhaustion.
- Security: cross-workspace run access, untrusted endpoint override, and Gold canary scan.
- Frontend E2E: launch, follow progress, pause/resume, cancel, retry, and inspect timeline.

## Required evidence

- `docs/evidence/batch-10/manifest.json`.
- State-transition coverage report and schema digests.
- End-to-end Run Manifests for normal and fault cases with sanitized identifiers.
- Restart/reconciliation matrix proving no duplicate simulator/Collector/snapshot effects.
- Cancellation resource-leak report and partial-dataset status.
- Suite concurrency/queue metrics and OTel trace waterfall.
- Playwright trace of launch, live progress, pause/resume, cancel, and retry.

## Definition of Done

- Real end-to-end Scenario execution produces collected raw data and a completed immutable Run Manifest.
- Every state transition persists, emits a schema-valid event, and appears in the timeline.
- Worker restart at each critical stage reconciles and completes/fails safely without duplicate logical effects.
- Pause/resume/cancel/retry and suite quotas behave as specified.
- Gold never enters Run task payloads, logs, traces, or user-visible responses.
- Failed/cancelled runs release resources and preserve diagnostic evidence about the failure.
- The UI operates against live APIs, not simulated progress.

## Out of scope

- Anomaly detection, root causes, approval, recovery, replay, evaluation, and real endpoint execution.
- Cross-day durable workflow engines unless already present in the Control Plane.

