# Batch 23: Edge read-only connector and real Shadow pilot

## Context

- Completed dependencies: S0/S1 platform, historical mapping, endpoint policies, Collector, security/RBAC/audit, and Release Gate.
- This batch advances to S2: live real-device data is observed read-only in an industrial DMZ/edge deployment.
- It does not enable real active checks, setpoint changes, stop/isolate operations, or recovery.

## Outcome

- An Edge Shadow Gateway connects outbound from a controlled OT/DMZ zone, reads allowlisted OPC UA Nodes, and forwards signed/batched events to the platform.
- Connection assessment, silent Shadow, visible advisory, drift, freshness, and incident-feedback workflows support a limited pilot.
- Technical and network controls prove the real connector cannot Write or Call methods.

## Inputs

- Real endpoint inventory, read-only account/certificate, Application URI/fingerprint, namespace/Node allowlist, and approved network architecture.
- Asset/signal mapping and data-quality policy from Batches 02/22.
- Collector normalization/event Schema and platform ingestion authentication.
- Site retention, egress, offline buffering, bandwidth, maintenance-window, and change-management policies.

## Code modules

- `services/edge-gateway/src/shadow_edge/config.py`: signed site bundle and typed settings.
- `services/edge-gateway/src/shadow_edge/opcua_readonly.py`: Browse/Read/Subscribe-only adapter.
- `services/edge-gateway/src/shadow_edge/identity.py`: device/service identity and certificate rotation.
- `services/edge-gateway/src/shadow_edge/buffer.py`: encrypted bounded offline spool.
- `services/edge-gateway/src/shadow_edge/uplink.py`: outbound authenticated batch transport.
- `services/edge-gateway/src/shadow_edge/health.py`, `updates.py`, and `audit.py`.
- `backend/src/shadow_sandbox/integrations/edge/registration.py`, `ingestion.py`, `policy.py`, and `api.py`.
- `backend/src/shadow_sandbox/shadow_pilot/modes.py`, `drift.py`, `feedback.py`, and `service.py`.
- `migrations/*_edge_shadow_pilot.py`.
- `deploy/edge/`: container/system service, hardened config, SBOM, and deployment checks.
- `web/src/features/edge/` and `shadow-pilot/`.

## Interfaces

- Gateway configuration is signed and includes site/workspace, environment `real_readonly`, endpoint identity, security mode, namespace/Node allowlist, sampling, budgets, uplink, retention, and expiry.
- Edge operations are limited to Browse, Read, CreateSubscription/MonitoredItem, Publish, and session lifecycle.
- Uplink `EdgeEventBatchV1`: gateway/site, sequence range, source batch hash, compressed canonical events, mapping version, clock/health summary, and signature.
- `POST /api/v1/edge-gateways/register`, `/rotate`, `/event-batches`, `/heartbeats`; `GET /edge-gateways/{id}/health`.
- Pilot modes: `CONNECTION_ASSESSMENT`, `SILENT_SHADOW`, `ADVISORY`, `PAUSED`, `OFFBOARDED`.
- Advisory outputs contain Evidence/diagnosis/check suggestions only; action/approval/executor APIs are not reachable from real Runs.
- Feedback interface records acknowledged/incorrect/investigated/confirmed outcomes as human provenance.

## Implementation requirements

1. Build a separate read-only OPC UA adapter without Write/Call symbols in its exposed dependency/interface; enforce process/container policy too.
2. Require signed, expiring, allowlisted configuration and fail closed on identity/namespace/security mismatch.
3. Use outbound-only authenticated transport; no platform-initiated arbitrary command channel to the Edge.
4. Encrypt offline spool, bound disk/time size, preserve ordering/gap metadata, and surface data loss risk.
5. Verify batch signature/hash/sequence and idempotently ingest at the platform.
6. Detect endpoint, Node metadata, unit, sampling, time/clock, quality, distribution, mode, and baseline drift.
7. Start in connection assessment, then silent Shadow; advisory requires explicit pilot Gate and site approval.
8. In real mode, strip/deny active/stop/isolate/recovery execution fields and hide action controls.
9. Add maintenance windows, pause/offboard, credential rotation, safe update/rollback, and remote health without remote shell.
10. Minimize data egress and implement site-configurable retention/redaction.
11. Correlate Edge, platform ingestion, diagnosis, advisory, feedback, and audit Trace without exporting secrets/Gold.
12. Produce site runbook, network/data-flow diagram, threat model, and incident/offboarding procedure.

## Tests

- Static/dependency: Edge binary/interface has no OPC UA Write/Call or generic method invoke path.
- Network: outbound-only topology; platform cannot initiate OT/Edge sessions; Edge cannot reach non-allowlisted endpoints.
- Identity/config: signature, expiry, fingerprint, Application URI, namespace, Node, and rotation failures.
- Offline: disconnect uplink, spool, restart, reconnect, deduplicate, preserve gaps, hit bounded capacity safely.
- Ingestion: signature/hash/sequence, replayed batch, corruption, mapping mismatch, clock skew, and backpressure.
- Pilot: connection assessment → silent → advisory; action proposal/executor paths denied for real Runs.
- Drift: known metadata/sampling/unit/baseline changes trigger review without silent remapping.
- E2E: use a hardened real-endpoint test profile or OT-compatible lab server under read-only credentials; never production writes.

## Required evidence

- `docs/evidence/batch-23/manifest.json`.
- Edge SBOM, dependency/symbol scan, and read-only operation capture.
- Network reachability/flow test and signed config validation matrix.
- Offline spool/reconnect/dedup/gap report.
- End-to-end signed batch, ingestion, diagnosis, and advisory trace.
- Real-Run action/approval/executor denial report and UI capture.
- Drift, credential rotation, update/rollback, pause/offboard, and runbook test results.

## Definition of Done

- Edge Gateway reads only allowlisted real/lab OPC UA data and sends authenticated outbound batches.
- Binary, interface, network, credential, and policy evidence all demonstrate no Write/Call/control channel.
- Offline buffering/reconnect preserves traceable sequence/gap semantics within declared bounds.
- Pilot modes and advisory Gate prevent immediate user-visible or actionable rollout.
- Real Runs cannot call virtual action/approval executor paths and show no action controls.
- Drift and configuration changes require explicit review.
- Operational/security/offboarding documentation and evidence are complete for a controlled pilot.

## Out of scope

- Real-device writes, closed-loop control, remote shell, automatic remediation, and plant-wide production rollout.
- Claiming lab OPC UA compatibility proves every vendor/server combination.

