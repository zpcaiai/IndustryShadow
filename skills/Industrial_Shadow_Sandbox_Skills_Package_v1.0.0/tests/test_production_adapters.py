from __future__ import annotations

import datetime as dt
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from shadow_sandbox.actions import ActionRequest
from shadow_sandbox.actions.remote import FixedJsonClient, RemoteActionExecutor
from shadow_sandbox.approvals import ApprovalService
from shadow_sandbox.common import ActorContext, DomainError
from shadow_sandbox.diagnosis.hypotheses import DiagnosisResult, Hypothesis
from shadow_sandbox.planning import CheckPlanner
from shadow_sandbox.runtime import RunOrchestrator
from shadow_simulator.api import create_app as create_simulator_app
from test_foundation import actor, manifest, store


class FakeSimulatorClient:
    def __init__(self, digest: str, *, fail: bool = False) -> None:
        self.digest = digest
        self.fail = fail
        self.snapshots: list[str] = []
        self.restored: list[str] = []
        self.actions = 0

    def identity(self) -> dict[str, str]:
        return {"environment_type": "simulator", "identity_digest": self.digest}

    def snapshot(
        self, reason: str, _run_id: str, *, protected: bool = True
    ) -> dict[str, str]:
        snapshot_id = f"snapshot-{len(self.snapshots) + 1}"
        self.snapshots.append(snapshot_id)
        return {
            "snapshot_id": snapshot_id,
            "reason": reason,
            "protected": str(protected),
        }

    def restore(self, snapshot_id: str) -> dict[str, str]:
        self.restored.append(snapshot_id)
        return {"snapshot_id": snapshot_id}

    def execute_action(self, _name: str, _parameters: object) -> dict[str, object]:
        self.actions += 1
        if self.fail:
            raise DomainError(
                "SIMULATED_FAILURE", "simulated dependency failure", status=503
            )
        return {"outcome": "RECOVERED", "evidence_refs": ["state:after"]}


def diagnosis() -> DiagnosisResult:
    return DiagnosisResult(
        "RANKED",
        (
            Hypothesis(
                "pump_efficiency_loss",
                1,
                0.9,
                {"rule_match": 1.0},
                ("ev-1",),
                (),
                (),
                (("pump_efficiency_loss", "flow-response-low"),),
                ("catalog",),
                "ranker",
            ),
        ),
        "TRUSTED",
        1.0,
    )


class ProductionAdapterTests(unittest.IsolatedAsyncioTestCase):
    def test_production_simulator_rejects_placeholders_before_creating_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "simulator.db"
            for environment, code in (
                (
                    {
                        "SHADOW_ENVIRONMENT": "production",
                        "SHADOW_SIMULATOR_BUILD_DIGEST": "0" * 64,
                    },
                    "SIMULATOR_BUILD_DIGEST_INVALID",
                ),
                (
                    {
                        "SHADOW_ENVIRONMENT": "production",
                        "SHADOW_SIMULATOR_BUILD_DIGEST": "a" * 64,
                        "SHADOW_OBJECT_STORAGE_BACKEND": "s3",
                        "SHADOW_OBJECT_STORAGE_KMS_KEY_ID": "replace-with-approved-kms-key",
                    },
                    "PRODUCTION_KMS_KEY_REQUIRED",
                ),
            ):
                with (
                    patch.dict("os.environ", environment, clear=True),
                    self.assertRaises(DomainError) as caught,
                ):
                    create_simulator_app(str(database))
                self.assertEqual(code, caught.exception.code)
                self.assertFalse(database.exists())

    def approved_action(
        self, fail: bool = False
    ) -> tuple[RemoteActionExecutor, ActionRequest, FakeSimulatorClient]:
        database = store()
        run = RunOrchestrator(database).create(
            actor("Engineer"), manifest(), "remote-action-run"
        )
        plan = CheckPlanner().plan(run["run_id"], diagnosis(), "simulator")
        step = next(item for item in plan.steps if item.approval_required)
        approvals = ApprovalService(database)
        digest = "a" * 64
        expiry = (
            (dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5))
            .isoformat()
            .replace("+00:00", "Z")
        )
        pending = approvals.request(actor("Engineer"), plan, digest, expiry)
        approvals.decide(
            ActorContext("approver-remote", "t1", "w1", frozenset({"Approver"})),
            pending.approval_id,
            "approve_subset",
            [step.step_id],
            "reviewed",
            "approved",
            1,
        )
        simulator = FakeSimulatorClient(digest, fail=fail)
        executor = RemoteActionExecutor(database, approvals, simulator, digest)  # type: ignore[arg-type]
        request = ActionRequest(
            run["run_id"],
            step.step_id,
            "restore_pump_efficiency",
            pending.approval_id,
            plan.plan_hash,
            digest,
            {"fault_id": "pump_efficiency"},
            "remote-action-key",
        )
        return executor, request, simulator

    def test_remote_executor_is_snapshot_first_and_exactly_once(self) -> None:
        executor, request, simulator = self.approved_action()
        first = executor.execute(request, "w1", lambda _engine: ("UNCHANGED", ()))
        second = executor.execute(request, "w1", lambda _engine: ("WORSE", ()))
        self.assertEqual(first, second)
        self.assertEqual("RECOVERED", first.outcome)
        self.assertEqual(1, simulator.actions)
        self.assertEqual(2, len(simulator.snapshots))

    def test_remote_executor_rolls_back_dependency_failure(self) -> None:
        executor, request, simulator = self.approved_action(fail=True)
        result = executor.execute(request, "w1", lambda _engine: ("UNCHANGED", ()))
        self.assertEqual("ROLLED_BACK", result.state)
        self.assertEqual("EXECUTION_FAILED", result.outcome)
        self.assertEqual([result.pre_snapshot_id], simulator.restored)

    def test_fixed_client_rejects_unsafe_authority(self) -> None:
        with self.assertRaises(DomainError):
            FixedJsonClient("file:///etc/passwd", "x" * 32)
        with self.assertRaises(DomainError):
            FixedJsonClient("https://user:pass@example.invalid", "x" * 32)

    async def test_simulator_http_action_is_typed_and_internally_authenticated(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(
                "os.environ", {"SHADOW_INTERNAL_SERVICE_TOKEN": "z" * 32}, clear=False
            ),
        ):
            app = create_simulator_app(f"{directory}/simulator.db")
            transport = httpx.ASGITransport(app=app)
            async with app.router.lifespan_context(app), httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                unauthorized = await client.get("/internal/v1/simulators/default/identity")
                self.assertEqual(401, unauthorized.status_code)
                headers = {"X-Internal-Token": "z" * 32}
                configured = await client.post(
                    "/internal/v1/simulators/default/faults",
                    headers=headers,
                    json={
                        "faults": [
                            {
                                "fault_id": "pump_efficiency",
                                "target": "Process.PumpEfficiency",
                                "operator": "multiplier",
                                "start": 0,
                                "duration": None,
                                "parameters": {"value": 0.5},
                            }
                        ]
                    },
                )
                self.assertEqual(201, configured.status_code)
                action = await client.post(
                    "/internal/v1/simulators/default/actions/restore_pump_efficiency",
                    headers=headers,
                    json={"parameters": {"fault_id": "pump_efficiency"}},
                )
                self.assertEqual(200, action.status_code)
                self.assertEqual("RECOVERED", action.json()["outcome"])


if __name__ == "__main__":
    unittest.main()
