from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass

from shadow_simulator.model import ProcessCommand, SimulatorEngine
from shadow_simulator.snapshot import SnapshotService

from shadow_sandbox.approvals import ApprovalService
from shadow_sandbox.common import DomainError, Store
from shadow_sandbox.common.models import canonical_digest, canonical_json, new_id, utc_now

ACTION_NAMES = frozenset(
    {
        "clear_sensor_bias",
        "release_valve_stiction",
        "restore_pump_efficiency",
        "clear_pipeline_blockage",
        "restore_communication_profile",
        "turn_off_stuck_heater",
        "run_virtual_step_test",
        "restore_snapshot",
    }
)


@dataclass(frozen=True, slots=True)
class ActionRequest:
    run_id: str
    step_id: str
    action_name: str
    approval_id: str
    plan_hash: str
    simulator_digest: str
    parameters: Mapping[str, float | str]
    idempotency_key: str

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class ActionResult:
    action_id: str
    state: str
    outcome: str
    pre_snapshot_id: str
    post_snapshot_id: str | None
    rollback_snapshot_id: str | None
    evidence_refs: tuple[str, ...]
    result_digest: str


class SimulatorActionAdapter:
    def __init__(self, engine: SimulatorEngine, simulator_id: str, identity_digest: str) -> None:
        self.engine = engine
        self.simulator_id = simulator_id
        self.identity_digest = identity_digest
        self.environment_type = "simulator"

    def execute(self, name: str, parameters: Mapping[str, float | str]) -> None:
        if name not in ACTION_NAMES:
            raise DomainError("ACTION_DENIED", "action is not registered", status=403)
        with self.engine.synchronized():
            fault_by_action = {
                "clear_sensor_bias": "sensor_bias",
                "release_valve_stiction": "valve_stiction",
                "restore_pump_efficiency": "pump_efficiency",
                "clear_pipeline_blockage": "pipeline_blockage",
                "restore_communication_profile": "communication",
                "turn_off_stuck_heater": "heater_stuck",
            }
            if name in fault_by_action:
                if not self.engine.fault_runtime:
                    raise DomainError("NO_FAULT_RUNTIME", "simulator has no fault runtime")
                target_id = str(parameters.get("fault_id", fault_by_action[name]))
                self.engine.fault_runtime.clear(target_id)
            elif name == "run_virtual_step_test":
                delta = float(parameters.get("pump_delta_rpm", 100.0))
                current = self.engine.last_command
                self.engine.last_command = ProcessCommand(
                    min(3600.0, max(0.0, current.pump_speed_rpm + delta)),
                    current.inlet_valve_percent,
                    current.outlet_valve_percent,
                    current.heater_power_kw,
                )
            elif name == "restore_snapshot":
                raise DomainError(
                    "USE_ROLLBACK_PATH", "snapshot restore is handled by the executor"
                )


class ActionExecutor:
    def __init__(
        self,
        store: Store,
        approvals: ApprovalService,
        snapshots: SnapshotService,
        adapter: SimulatorActionAdapter,
    ) -> None:
        self.store = store
        self.approvals = approvals
        self.snapshots = snapshots
        self.adapter = adapter

    def execute(
        self,
        request: ActionRequest,
        workspace_id: str,
        verifier: Callable[[SimulatorEngine], tuple[str, tuple[str, ...]]],
    ) -> ActionResult:
        if (
            self.adapter.environment_type != "simulator"
            or self.adapter.identity_digest != request.simulator_digest
        ):
            raise DomainError(
                "SIMULATOR_ATTESTATION_FAILED", "target is not the approved simulator", status=403
            )
        numeric_parameters = {
            key: float(value)
            for key, value in request.parameters.items()
            if isinstance(value, (int, float))
        }
        self.approvals.verify(
            approval_id=request.approval_id,
            workspace_id=workspace_id,
            plan_hash=request.plan_hash,
            step_id=request.step_id,
            simulator_digest=request.simulator_digest,
            parameters=numeric_parameters,
        )
        existing = self.store.query(
            "SELECT * FROM action_executions WHERE idempotency_key=?",
            (request.idempotency_key,),
        )
        if existing and existing[0]["result_json"]:
            data = json.loads(existing[0]["result_json"])
            data["evidence_refs"] = tuple(data["evidence_refs"])
            return ActionResult(**data)
        if existing:
            interrupted = existing[0]
            if interrupted["pre_snapshot_id"]:
                self.snapshots.restore(self.adapter.engine, interrupted["pre_snapshot_id"])
            provisional = {
                "action_id": interrupted["action_id"],
                "state": "ROLLED_BACK",
                "outcome": "EXECUTION_FAILED",
                "pre_snapshot_id": interrupted["pre_snapshot_id"],
                "post_snapshot_id": interrupted["post_snapshot_id"],
                "rollback_snapshot_id": interrupted["pre_snapshot_id"],
                "evidence_refs": (),
                "result_digest": "",
            }
            recovered = ActionResult(
                **{**provisional, "result_digest": canonical_digest(provisional)}
            )
            self.store.execute(
                """UPDATE action_executions SET state='ROLLED_BACK', result_json=?,
                   rollback_snapshot_id=?, updated_at=? WHERE action_id=?""",
                (
                    canonical_json(asdict(recovered)),
                    interrupted["pre_snapshot_id"],
                    utc_now(),
                    interrupted["action_id"],
                ),
            )
            return recovered
        action_id = new_id("action")
        pre = self.snapshots.create(
            self.adapter.simulator_id,
            self.adapter.engine,
            "pre-action",
            request.run_id,
            protected=True,
        )
        now = utc_now()
        self.store.execute(
            """INSERT INTO action_executions
               (action_id, run_id, approval_id, plan_hash, idempotency_key, state,
                request_json, pre_snapshot_id, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 'CLAIMED', ?, ?, ?, ?)""",
            (
                action_id,
                request.run_id,
                request.approval_id,
                request.plan_hash,
                request.idempotency_key,
                canonical_json(asdict(request)),
                pre.snapshot_id,
                now,
                now,
            ),
        )
        post_id: str | None = None
        rollback_id: str | None = None
        evidence: tuple[str, ...] = ()
        try:
            self.adapter.execute(request.action_name, request.parameters)
            outcome, evidence = verifier(self.adapter.engine)
            post = self.snapshots.create(
                self.adapter.simulator_id,
                self.adapter.engine,
                "post-action",
                request.run_id,
                parent_snapshot_id=pre.snapshot_id,
                protected=True,
            )
            post_id = post.snapshot_id
            if outcome in {"WORSE", "EXECUTION_FAILED"}:
                self.snapshots.restore(self.adapter.engine, pre.snapshot_id)
                rollback = self.snapshots.create(
                    self.adapter.simulator_id,
                    self.adapter.engine,
                    "rollback-verified",
                    request.run_id,
                    parent_snapshot_id=pre.snapshot_id,
                    protected=True,
                )
                rollback_id = rollback.snapshot_id
                state = "ROLLED_BACK"
            else:
                state = "COMPLETED"
        except Exception:  # noqa: BLE001 - every action failure must trigger rollback
            self.snapshots.restore(self.adapter.engine, pre.snapshot_id)
            rollback = self.snapshots.create(
                self.adapter.simulator_id,
                self.adapter.engine,
                "rollback-after-failure",
                request.run_id,
                parent_snapshot_id=pre.snapshot_id,
                protected=True,
            )
            rollback_id = rollback.snapshot_id
            outcome = "EXECUTION_FAILED"
            state = "ROLLED_BACK"
            evidence = ()
        provisional = {
            "action_id": action_id,
            "state": state,
            "outcome": outcome,
            "pre_snapshot_id": pre.snapshot_id,
            "post_snapshot_id": post_id,
            "rollback_snapshot_id": rollback_id,
            "evidence_refs": evidence,
            "result_digest": "",
        }
        result = ActionResult(**{**provisional, "result_digest": canonical_digest(provisional)})
        self.store.execute(
            """UPDATE action_executions SET state=?, result_json=?, post_snapshot_id=?,
               rollback_snapshot_id=?, updated_at=? WHERE action_id=?""",
            (state, canonical_json(asdict(result)), post_id, rollback_id, utc_now(), action_id),
        )
        return result
