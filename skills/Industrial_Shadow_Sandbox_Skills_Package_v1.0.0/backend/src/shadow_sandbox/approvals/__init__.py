from __future__ import annotations

import datetime as dt
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace

from shadow_sandbox.common import ActorContext, DomainError, Store
from shadow_sandbox.common.models import canonical_digest, canonical_json, new_id, utc_now
from shadow_sandbox.planning import CheckPlan


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    approval_id: str
    run_id: str
    plan_id: str
    plan_hash: str
    allowed_steps: tuple[str, ...]
    parameter_bounds: Mapping[str, Mapping[str, float]]
    simulator_digest: str
    environment_type: str
    risk: int
    requester_id: str
    required_roles: tuple[str, ...]
    expires_at: str
    policy_digest: str
    assigned_approver_id: str | None = None

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    kind: str
    actor_id: str
    allowed_steps: tuple[str, ...]
    parameter_bounds: Mapping[str, Mapping[str, float]]
    reason_code: str
    reason_text: str
    decided_at: str
    request_digest: str

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


class ApprovalService:
    POLICY_DIGEST = canonical_digest(["simulator-only", "maker-checker", "plan-bound", "v1"])

    def __init__(self, store: Store) -> None:
        self.store = store

    def request(
        self,
        actor: ActorContext,
        plan: CheckPlan,
        simulator_digest: str,
        expires_at: str,
        parameter_bounds: Mapping[str, Mapping[str, float]] | None = None,
    ) -> ApprovalRequest:
        actor.require_role("Engineer", "Admin")
        if plan.environment_type != "simulator":
            raise DomainError(
                "REAL_APPROVAL_DENIED", "real endpoint actions are never approvable", status=403
            )
        active = tuple(step.step_id for step in plan.steps if step.approval_required)
        if not active:
            raise DomainError("NO_APPROVABLE_STEPS", "plan contains no approval-required steps")
        expiry = dt.datetime.fromisoformat(expires_at)
        if expiry <= dt.datetime.now(dt.UTC):
            raise DomainError("INVALID_EXPIRY", "approval expiry must be in the future")
        request = ApprovalRequest(
            new_id("approval"),
            plan.run_id,
            plan.plan_id,
            plan.plan_hash,
            active,
            dict(parameter_bounds or {}),
            simulator_digest,
            "simulator",
            max(step.risk for step in plan.steps),
            actor.actor_id,
            ("Approver",),
            expires_at,
            self.POLICY_DIGEST,
        )
        now = utc_now()
        self.store.execute(
            """INSERT INTO approvals
               (approval_id, run_id, workspace_id, plan_hash, simulator_digest,
                request_json, state, version, expires_at, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, 'PENDING', 1, ?, ?, ?)""",
            (
                request.approval_id,
                request.run_id,
                actor.workspace_id,
                request.plan_hash,
                simulator_digest,
                canonical_json(asdict(request)),
                expires_at,
                now,
                now,
            ),
        )
        return request

    def decide(
        self,
        actor: ActorContext,
        approval_id: str,
        kind: str,
        allowed_steps: Sequence[str],
        reason_code: str,
        reason_text: str,
        expected_version: int,
        parameter_bounds: Mapping[str, Mapping[str, float]] | None = None,
    ) -> ApprovalDecision:
        actor.require_role("Approver")
        if kind not in {"approve_all", "approve_subset", "reject", "reanalyze"}:
            raise DomainError("INVALID_DECISION", "unsupported approval decision")
        with self.store.transaction() as tx:
            row = tx.execute(
                "SELECT * FROM approvals WHERE approval_id=? AND workspace_id=?",
                (approval_id, actor.workspace_id),
            ).fetchone()
            if not row:
                raise DomainError("APPROVAL_NOT_FOUND", "approval not found", status=404)
            request = ApprovalRequest(**json.loads(row["request_json"]))
            if row["version"] != expected_version or row["state"] != "PENDING":
                raise DomainError(
                    "STALE_APPROVAL", "approval is not pending at expected version", status=409
                )
            if request.requester_id == actor.actor_id:
                raise DomainError(
                    "MAKER_CHECKER_VIOLATION", "requester cannot approve own action", status=403
                )
            if request.assigned_approver_id and request.assigned_approver_id != actor.actor_id:
                raise DomainError(
                    "APPROVAL_ASSIGNEE_MISMATCH",
                    "approval is assigned to another actor",
                    status=403,
                )
            expiry = dt.datetime.fromisoformat(request.expires_at)
            if expiry <= dt.datetime.now(dt.UTC):
                raise DomainError("APPROVAL_EXPIRED", "approval request has expired", status=409)
            narrowed = tuple(allowed_steps)
            if kind == "approve_all":
                narrowed = request.allowed_steps
            if not set(narrowed).issubset(request.allowed_steps):
                raise DomainError(
                    "APPROVAL_SCOPE_EXPANSION", "decision may only narrow request scope"
                )
            proposed_bounds = dict(parameter_bounds or request.parameter_bounds)
            for key, limits in proposed_bounds.items():
                original = request.parameter_bounds.get(key)
                if (
                    not original
                    or limits.get("min", 0) < original.get("min", 0)
                    or limits.get("max", 0) > original.get("max", 0)
                ):
                    raise DomainError(
                        "APPROVAL_SCOPE_EXPANSION", "parameter bounds may only narrow"
                    )
            decision = ApprovalDecision(
                kind,
                actor.actor_id,
                narrowed if kind.startswith("approve") else (),
                proposed_bounds if kind.startswith("approve") else {},
                reason_code,
                reason_text,
                utc_now(),
                request.digest,
            )
            state = "APPROVED" if kind.startswith("approve") else "REJECTED"
            tx.execute(
                """UPDATE approvals SET decision_json=?, state=?, version=version+1,
                   updated_at=? WHERE approval_id=?""",
                (canonical_json(asdict(decision)), state, utc_now(), approval_id),
            )
        return decision

    def transfer(
        self,
        actor: ActorContext,
        approval_id: str,
        target_actor_id: str,
        expected_version: int,
    ) -> ApprovalRequest:
        actor.require_role("Approver")
        with self.store.transaction() as tx:
            row = tx.execute(
                "SELECT * FROM approvals WHERE approval_id=? AND workspace_id=?",
                (approval_id, actor.workspace_id),
            ).fetchone()
            if not row or row["state"] != "PENDING" or row["version"] != expected_version:
                raise DomainError(
                    "STALE_APPROVAL", "only the current pending approval can transfer", status=409
                )
            request = ApprovalRequest(**json.loads(row["request_json"]))
            transferred = replace(request, assigned_approver_id=target_actor_id)
            tx.execute(
                """UPDATE approvals SET request_json=?, version=version+1, updated_at=?
                   WHERE approval_id=?""",
                (canonical_json(asdict(transferred)), utc_now(), approval_id),
            )
        return transferred

    def expire_due(self, now: dt.datetime | None = None) -> int:
        current = (now or dt.datetime.now(dt.UTC)).isoformat().replace("+00:00", "Z")
        cursor = self.store.execute(
            """UPDATE approvals SET state='EXPIRED', version=version+1, updated_at=?
               WHERE state IN ('PENDING', 'APPROVED') AND expires_at<=?""",
            (current, current),
        )
        return cursor.rowcount

    def revoke(self, actor: ActorContext, approval_id: str, reason: str) -> None:
        actor.require_role("Approver")
        cursor = self.store.execute(
            """UPDATE approvals SET state='REVOKED', version=version+1, updated_at=?
               WHERE approval_id=? AND workspace_id=? AND state='APPROVED'""",
            (utc_now(), approval_id, actor.workspace_id),
        )
        if cursor.rowcount != 1:
            raise DomainError("APPROVAL_NOT_REVOCABLE", "approval is not active", status=409)

    def verify(
        self,
        *,
        approval_id: str,
        workspace_id: str,
        plan_hash: str,
        step_id: str,
        simulator_digest: str,
        parameters: Mapping[str, float],
    ) -> ApprovalDecision:
        rows = self.store.query(
            "SELECT * FROM approvals WHERE approval_id=? AND workspace_id=?",
            (approval_id, workspace_id),
        )
        if not rows:
            raise DomainError("APPROVAL_NOT_FOUND", "approval not found", status=404)
        row = rows[0]
        if row["state"] != "APPROVED" or not row["decision_json"]:
            raise DomainError("APPROVAL_INVALID", "approval is not active", status=403)
        request = ApprovalRequest(**json.loads(row["request_json"]))
        decision = ApprovalDecision(**json.loads(row["decision_json"]))
        if dt.datetime.fromisoformat(request.expires_at) <= dt.datetime.now(
            dt.UTC
        ):
            raise DomainError("APPROVAL_EXPIRED", "approval expired", status=403)
        if request.plan_hash != plan_hash or request.simulator_digest != simulator_digest:
            raise DomainError(
                "APPROVAL_BINDING_MISMATCH", "plan or simulator identity changed", status=403
            )
        if step_id not in decision.allowed_steps:
            raise DomainError("STEP_NOT_APPROVED", "step is outside approved scope", status=403)
        for name, value in parameters.items():
            limits = decision.parameter_bounds.get(name)
            if limits and not limits["min"] <= value <= limits["max"]:
                raise DomainError(
                    "PARAMETER_NOT_APPROVED", f"{name} outside approved bounds", status=403
                )
        return decision
