from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from shadow_sandbox.common import ActorContext, DomainError, EventEnvelope, Store
from shadow_sandbox.common.models import canonical_digest, new_id, utc_now


class RunState(StrEnum):
    REQUESTED = "REQUESTED"
    VALIDATING = "VALIDATING"
    QUEUED = "QUEUED"
    PROVISIONING = "PROVISIONING"
    WARMING_UP = "WARMING_UP"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COLLECTING_FINAL = "COLLECTING_FINAL"
    COMPLETED = "COMPLETED"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    FAILED_FINAL = "FAILED_FINAL"
    DATA_UNTRUSTED = "DATA_UNTRUSTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    PLAN_READY = "PLAN_READY"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    SANDBOX_EXECUTING = "SANDBOX_EXECUTING"
    ROLLED_BACK = "ROLLED_BACK"
    REPLAYED = "REPLAYED"
    EVALUATED = "EVALUATED"
    REPORTED = "REPORTED"


TRANSITIONS: dict[RunState, frozenset[RunState]] = {
    RunState.REQUESTED: frozenset({RunState.VALIDATING, RunState.CANCELLED}),
    RunState.VALIDATING: frozenset({RunState.QUEUED, RunState.FAILED_FINAL}),
    RunState.QUEUED: frozenset({RunState.PROVISIONING, RunState.CANCELLING}),
    RunState.PROVISIONING: frozenset(
        {RunState.WARMING_UP, RunState.FAILED_RETRYABLE, RunState.CANCELLING}
    ),
    RunState.WARMING_UP: frozenset(
        {RunState.RUNNING, RunState.FAILED_RETRYABLE, RunState.CANCELLING}
    ),
    RunState.RUNNING: frozenset(
        {RunState.PAUSED, RunState.COLLECTING_FINAL, RunState.CANCELLING, RunState.FAILED_RETRYABLE}
    ),
    RunState.PAUSED: frozenset({RunState.RUNNING, RunState.CANCELLING}),
    RunState.COLLECTING_FINAL: frozenset({RunState.COMPLETED, RunState.FAILED_RETRYABLE}),
    RunState.CANCELLING: frozenset({RunState.CANCELLED, RunState.FAILED_RETRYABLE}),
    RunState.FAILED_RETRYABLE: frozenset(
        {RunState.QUEUED, RunState.FAILED_FINAL, RunState.CANCELLED}
    ),
    RunState.COMPLETED: frozenset(
        {RunState.DATA_UNTRUSTED, RunState.INCONCLUSIVE, RunState.PLAN_READY, RunState.REPLAYED}
    ),
    RunState.DATA_UNTRUSTED: frozenset({RunState.PLAN_READY, RunState.REPLAYED, RunState.REPORTED}),
    RunState.INCONCLUSIVE: frozenset({RunState.PLAN_READY, RunState.REPLAYED, RunState.REPORTED}),
    RunState.PLAN_READY: frozenset(
        {RunState.WAITING_APPROVAL, RunState.REPLAYED, RunState.REPORTED}
    ),
    RunState.WAITING_APPROVAL: frozenset(
        {RunState.APPROVED, RunState.REJECTED, RunState.CANCELLED}
    ),
    RunState.APPROVED: frozenset({RunState.SANDBOX_EXECUTING, RunState.REJECTED}),
    RunState.SANDBOX_EXECUTING: frozenset(
        {RunState.REPLAYED, RunState.ROLLED_BACK, RunState.FAILED_RETRYABLE}
    ),
    RunState.ROLLED_BACK: frozenset({RunState.REPLAYED, RunState.REPORTED}),
    RunState.REPLAYED: frozenset({RunState.EVALUATED, RunState.REPORTED}),
    RunState.EVALUATED: frozenset({RunState.REPORTED}),
    RunState.REPORTED: frozenset(),
    RunState.REJECTED: frozenset({RunState.REPLAYED, RunState.REPORTED}),
    RunState.CANCELLED: frozenset(),
    RunState.FAILED_FINAL: frozenset(),
}


@dataclass(frozen=True, slots=True)
class RunManifest:
    scenario_digest: str
    process_model_digest: str
    asset_model_digest: str
    parameter_digest: str
    operator_digest: str
    detector_bundle_digest: str
    causal_graph_digest: str
    check_library_digest: str
    application_build: str
    configuration_digest: str
    seed: int
    clock_policy: str
    endpoint_identity: str
    environment_type: str = "simulator"
    opaque_gold_digest: str | None = None

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


class RunOrchestrator:
    def __init__(self, store: Store) -> None:
        self.store = store

    def create(
        self,
        actor: ActorContext,
        manifest: RunManifest,
        idempotency_key: str,
    ) -> dict[str, Any]:
        actor.require_role("Engineer", "Admin")
        request_digest = canonical_digest([actor.workspace_id, asdict(manifest)])
        existing = self.store.idempotent_result(actor.workspace_id, "run.create", idempotency_key)
        if existing:
            return existing
        run_id = new_id("run")
        now = utc_now()
        with self.store.transaction() as tx:
            tx.execute(
                """INSERT INTO runs
                   (run_id, tenant_id, workspace_id, manifest, manifest_digest, state,
                    version, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                (
                    run_id,
                    actor.tenant_id,
                    actor.workspace_id,
                    json.dumps(asdict(manifest), sort_keys=True, separators=(",", ":")),
                    manifest.digest,
                    RunState.REQUESTED,
                    now,
                    now,
                ),
            )
            tx.execute(
                """INSERT INTO run_transitions
                   (transition_id, run_id, from_state, to_state, reason, actor_id,
                    trace_id, occurred_at) VALUES (?, ?, NULL, ?, ?, ?, ?, ?)""",
                (
                    new_id("transition"),
                    run_id,
                    RunState.REQUESTED,
                    "created",
                    actor.actor_id,
                    actor.trace_id,
                    now,
                ),
            )
        result = {"run_id": run_id, "state": RunState.REQUESTED, "manifest_digest": manifest.digest}
        self.store.record_idempotent_result(
            actor.workspace_id,
            "run.create",
            idempotency_key,
            request_digest,
            result,
        )
        self.store.append_event(
            EventEnvelope(
                "run.requested.v1",
                result,
                actor.tenant_id,
                actor.workspace_id,
                run_id,
                actor.trace_id,
            )
        )
        return result

    def get(self, actor: ActorContext, run_id: str) -> dict[str, Any]:
        rows = self.store.query(
            "SELECT * FROM runs WHERE run_id=? AND workspace_id=?", (run_id, actor.workspace_id)
        )
        if not rows:
            raise DomainError("RUN_NOT_FOUND", "run not found", status=404)
        row = rows[0]
        row["manifest"] = json.loads(row["manifest"])
        return row

    def transition(
        self,
        actor: ActorContext,
        run_id: str,
        target: RunState,
        reason: str,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        with self.store.transaction() as tx:
            row = tx.execute(
                "SELECT state, version, tenant_id, workspace_id FROM runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if not row or row["workspace_id"] != actor.workspace_id:
                raise DomainError("RUN_NOT_FOUND", "run not found", status=404)
            source = RunState(row["state"])
            if expected_version is not None and row["version"] != expected_version:
                raise DomainError("STALE_VERSION", "run version changed", status=409)
            if target not in TRANSITIONS.get(source, frozenset()):
                raise DomainError(
                    "ILLEGAL_TRANSITION",
                    f"cannot transition from {source} to {target}",
                    status=409,
                )
            now = utc_now()
            new_version = int(row["version"]) + 1
            tx.execute(
                "UPDATE runs SET state=?, version=?, updated_at=? WHERE run_id=?",
                (target, new_version, now, run_id),
            )
            tx.execute(
                """INSERT INTO run_transitions
                   (transition_id, run_id, from_state, to_state, reason, actor_id,
                    trace_id, occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    new_id("transition"),
                    run_id,
                    source,
                    target,
                    reason,
                    actor.actor_id,
                    actor.trace_id,
                    now,
                ),
            )
        payload = {"run_id": run_id, "from": source, "to": target, "version": new_version}
        self.store.append_event(
            EventEnvelope(
                "run.state_changed.v1",
                payload,
                row["tenant_id"],
                row["workspace_id"],
                run_id,
                actor.trace_id,
            )
        )
        return payload

    def timeline(self, actor: ActorContext, run_id: str) -> list[dict[str, Any]]:
        self.get(actor, run_id)
        return self.store.query(
            "SELECT * FROM run_transitions WHERE run_id=? ORDER BY occurred_at, transition_id",
            (run_id,),
        )
