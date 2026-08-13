# Batch 17: Human approval, plan binding, and durable interruption

## Context

- Completed dependencies: versioned Check Plans and Control Plane proposal/tool policy.
- Approval is a server-side authorization artifact, not a chat confirmation or UI flag.
- Approvals unlock only simulator-supported steps; they never grant real OPC UA/PLC write permissions.

## Outcome

- Approvers can approve all/part, edit, reject, request re-analysis, transfer, expire, or revoke a proposed plan.
- A decision is immutably bound to the exact plan hash, allowed steps/parameters, simulator identity, risk, and validity window.
- Workflows persist at `WAITING_APPROVAL` and safely resume after external input or process restart.

## Inputs

- CheckPlan, plan hash, risk, environment, and supersession behavior from Batch 15.
- Tool context/policy and `request_virtual_action` proposal from Batch 16.
- Run state machine, identity placeholder, idempotency, outbox, and audit foundations.
- Simulator endpoint identity metadata; no real endpoint is an approvable action target.

## Code modules

- `backend/src/shadow_sandbox/approvals/entities.py`: request, decision, scope, validity, revision.
- `backend/src/shadow_sandbox/approvals/policy.py`: role, separation, risk, environment, and plan binding.
- `backend/src/shadow_sandbox/approvals/service.py`: request, decide, revoke, expire, transfer, and reconcile.
- `backend/src/shadow_sandbox/approvals/repository.py`, `api.py`, and `events.py`.
- `backend/src/shadow_sandbox/runtime/state_machine.py`: `PLAN_READY`, `WAITING_APPROVAL`, `APPROVED`, `REJECTED`, `EDITED`.
- `backend/src/shadow_sandbox/runtime/approval_wait.py`: durable pause/resume adapter.
- `migrations/*_approvals.py`.
- `schemas/api/approval*.json` and event schemas.
- `web/src/features/approvals/`: inbox, detail, plan diff, partial approval, reject, transfer, and history.

## Interfaces

- `ApprovalRequestV1`: Run, diagnosis, plan ID/hash, exact steps/parameters, simulator ID/digest, risk, requester, required roles/count, requested expiry, and evidence summary refs.
- `ApprovalDecisionV1`: approve-all/approve-subset/edit/reject/reanalyze/transfer/revoke, actor, reason code/text, allowed step IDs/parameter bounds, expiry, prior revision, and decision digest.
- `POST /api/v1/approval-requests`; `GET /api/v1/approvals/inbox` and `/{id}`.
- Command routes `/{id}/decide`, `/transfer`, `/revoke`; all use Idempotency-Key and version precondition.
- Events `approval.requested/decided/expired/revoked/transferred.v1`.
- `ApprovalVerifier.verify(approval_id, plan_hash, action, simulator_identity, now) -> PolicyDecision`.
- Workflow checkpoint contains approval request reference but no untrusted serialized executable callback.

## Implementation requirements

1. Calculate request/decision digests from canonical executable scope and policy versions.
2. Invalidate approval when plan hash, parameters, step order where material, simulator identity, risk, policy, or expiry changes.
3. Partial approval can only narrow scope; it cannot add tools, targets, parameter range, time, or steps.
4. Edited plans become new Plan versions and new approval requests.
5. Enforce role and optional maker-checker separation server-side; admin bypass is disallowed for safety red lines.
6. Verify environment type is simulator at request, decision, and execution-verification time.
7. Persist workflow state before waiting and resume idempotently after a valid decision.
8. Support expiration/revocation while queued and prevent race with execution through transactional claim/verification.
9. Record human observations separately from system Evidence and label their provenance.
10. UI must display Evidence limitations, Top-3, contradictions, each step's risk/expected result/rollback, exact target, and plan diff.
11. Require structured rejection/reanalysis reasons for later evaluation.
12. Audit every view of sensitive approval details and every decision transition.

## Tests

- Unit: canonical hash, subset/narrowing, expiry, revocation, transfer, separation of duties, stale version, invalidation.
- API/event contract and idempotent duplicate decisions.
- Workflow: pause at approval, restart services, decide, and resume exactly once.
- Race: approval expires/revokes/plan supersedes as execution attempts to claim it; execution must lose safely.
- Safety: real endpoint or changed simulator identity is never approvable; admin cannot override.
- Permission: requester, approver, viewer, auditor, cross-workspace actor.
- Frontend E2E: approve all/subset, edit/revalidate, reject, reanalyze, transfer, expire, and view audit.
- Accessibility: keyboard flow, focus, confirmation, risk labels, and non-color-only states.

## Required evidence

- `docs/evidence/batch-17/manifest.json`.
- Approval policy matrix and canonical hash/invalidation tests.
- Durable wait/restart/resume and race-condition traces.
- Real-endpoint/admin-bypass denial records.
- API/event schema, migration, audit, and idempotency reports.
- Playwright traces for all decision paths and plan diff.
- Sanitized approval request/decision examples with Evidence refs and simulator digest.

## Definition of Done

- A real Check Plan enters durable `WAITING_APPROVAL` and resumes only from a valid persisted decision.
- Approvals are bound to unchanged plan/simulator/policy details and expire/revoke atomically.
- Partial/edit decisions narrow or reversion the plan correctly.
- Real environment targets and policy overrides cannot be approved.
- Restart/race tests prove no duplicate resume or post-revocation execution authorization.
- UI and audit expose every decision and relevant plan difference.
- No action is executed in this batch.

## Out of scope

- Virtual action implementation, automatic approval, real maintenance dispatch, and real-device control.
- Treating chat text as an approval artifact.

