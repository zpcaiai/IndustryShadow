from __future__ import annotations

import datetime as dt
import tempfile
import unittest

from shadow_sandbox.actions import ActionExecutor, ActionRequest, SimulatorActionAdapter
from shadow_sandbox.approvals import ApprovalService
from shadow_sandbox.asset_registry import pump_tank_model
from shadow_sandbox.common import ActorContext, DomainError
from shadow_sandbox.diagnosis.hypotheses import DiagnosisResult, Hypothesis
from shadow_sandbox.evaluation.metrics import (
    EpisodeEvaluationInput,
    Evaluator,
    ReleaseGate,
)
from shadow_sandbox.integrations.control_plane import ControlPlaneAdapter, ToolContext
from shadow_sandbox.planning import CheckPlanner
from shadow_sandbox.reports import Report, ReportRenderer
from shadow_sandbox.runtime import RunOrchestrator
from shadow_simulator import SimulatorEngine
from shadow_simulator.faults import FaultRuntime, FaultSpec
from shadow_simulator.snapshot import SnapshotService
from test_foundation import actor, manifest, store


class SafetyTests(unittest.TestCase):
    def _diagnosis(self) -> DiagnosisResult:
        hypothesis = Hypothesis(
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
        )
        return DiagnosisResult("RANKED", (hypothesis,), "TRUSTED", 1.0)

    def test_control_plane_denies_unregistered_scope_and_real_action(self) -> None:
        database = store()
        engineer = actor("Engineer")
        context = ToolContext(
            engineer,
            "run",
            "real_readonly",
            frozenset({"Tank101.Level"}),
            "2026-01-01T00:00:00Z",
            "2026-01-01T01:00:00Z",
        )
        adapter = ControlPlaneAdapter(
            database, {"get_data_quality": lambda **_: {"state": "TRUSTED"}}
        )
        result = adapter.invoke(context, "get_data_quality", {})
        self.assertEqual("TRUSTED", result.data["state"])
        with self.assertRaises(DomainError):
            adapter.invoke(context, "request_virtual_action", {"step_id": "x"})
        with self.assertRaises(DomainError):
            adapter.invoke(context, "query_events", {"sql": "select * from gold"})

    def test_approval_is_maker_checker_bound_and_action_is_exactly_once(self) -> None:
        database = store()
        run = RunOrchestrator(database).create(
            actor("Engineer"), manifest(), "action-run"
        )
        plan = CheckPlanner().plan(run["run_id"], self._diagnosis(), "simulator")
        active = next(step for step in plan.steps if step.approval_required)
        model = pump_tank_model()
        faults = FaultRuntime(
            [
                FaultSpec(
                    "pump_efficiency",
                    "Process.PumpEfficiency",
                    "multiplier",
                    0,
                    None,
                    {"value": 0.5},
                )
            ]
        )
        engine = SimulatorEngine(asset_model_digest=model.digest, fault_runtime=faults)
        simulator_digest = "simulator-attested"
        approvals = ApprovalService(database)
        expiry = (
            (dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5))
            .isoformat()
            .replace("+00:00", "Z")
        )
        request = approvals.request(
            actor("Engineer"),
            plan,
            simulator_digest,
            expiry,
            {"pump_delta_rpm": {"min": -200.0, "max": 200.0}},
        )
        with self.assertRaises(DomainError) as caught:
            approvals.decide(
                actor("Approver"),
                request.approval_id,
                "approve_subset",
                [active.step_id],
                "reviewed",
                "approved",
                1,
            )
        self.assertEqual("MAKER_CHECKER_VIOLATION", caught.exception.code)
        approver = ActorContext("approver-2", "t1", "w1", frozenset({"Approver"}))
        approvals.decide(
            approver,
            request.approval_id,
            "approve_subset",
            [active.step_id],
            "reviewed",
            "approved",
            1,
            {"pump_delta_rpm": {"min": -100.0, "max": 100.0}},
        )
        with tempfile.TemporaryDirectory() as directory:
            snapshots = SnapshotService(database, directory)
            adapter = SimulatorActionAdapter(engine, "sim-1", simulator_digest)
            executor = ActionExecutor(database, approvals, snapshots, adapter)
            action = ActionRequest(
                run["run_id"],
                active.step_id,
                "restore_pump_efficiency",
                request.approval_id,
                plan.plan_hash,
                simulator_digest,
                {"fault_id": "pump_efficiency"},
                "action-key",
            )
            first = executor.execute(
                action, "w1", lambda _engine: ("RECOVERED", ("ev-after",))
            )
            second = executor.execute(action, "w1", lambda _engine: ("WORSE", ()))
        self.assertEqual(first, second)
        self.assertEqual("RECOVERED", first.outcome)
        self.assertIsNotNone(engine.fault_runtime)
        assert engine.fault_runtime is not None
        self.assertNotIn(
            "pump_efficiency", [item.fault_id for item in engine.fault_runtime.specs]
        )

    def test_release_gate_red_lines_are_non_compensable(self) -> None:
        episodes = []
        for index in range(150):
            normal = index >= 100
            episodes.append(
                EpisodeEvaluationInput(
                    str(index),
                    normal,
                    () if normal else ("cause",),
                    () if normal else ("cause",),
                    not normal,
                    1.0,
                    False,
                    0,
                    0,
                    1 if index == 0 else 0,
                    0,
                    True,
                    True,
                    True,
                    {"fault": "normal" if normal else "F01"},
                )
            )
        evaluation = Evaluator().evaluate("eval", episodes)
        for invalid_digest in ("", "not-a-digest", "0" * 64, "A" * 64):
            with self.subTest(invalid_digest=invalid_digest):
                with self.assertRaises(DomainError) as caught:
                    ReleaseGate().evaluate("gate", invalid_digest, evaluation)
                self.assertEqual("BUNDLE_DIGEST_INVALID", caught.exception.code)
        gate = ReleaseGate().evaluate("gate", "b" * 64, evaluation)
        self.assertFalse(gate.passed)
        self.assertTrue(any("real_write_attempts" in reason for reason in gate.reasons))

    def test_approval_transfer_binds_the_new_assignee(self) -> None:
        database = store()
        run = RunOrchestrator(database).create(
            actor("Engineer"), manifest(), "transfer-run"
        )
        plan = CheckPlanner().plan(run["run_id"], self._diagnosis(), "simulator")
        active = next(step for step in plan.steps if step.approval_required)
        approvals = ApprovalService(database)
        expiry = (
            (dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5))
            .isoformat()
            .replace("+00:00", "Z")
        )
        request = approvals.request(actor("Engineer"), plan, "sim", expiry)
        first_approver = ActorContext("approver-1", "t1", "w1", frozenset({"Approver"}))
        second_approver = ActorContext(
            "approver-2", "t1", "w1", frozenset({"Approver"})
        )
        approvals.transfer(
            first_approver, request.approval_id, second_approver.actor_id, 1
        )
        with self.assertRaises(DomainError) as caught:
            approvals.decide(
                first_approver,
                request.approval_id,
                "approve_subset",
                [active.step_id],
                "reviewed",
                "wrong assignee",
                2,
            )
        self.assertEqual("APPROVAL_ASSIGNEE_MISMATCH", caught.exception.code)
        decision = approvals.decide(
            second_approver,
            request.approval_id,
            "approve_subset",
            [active.step_id],
            "reviewed",
            "correct assignee",
            2,
        )
        self.assertEqual(second_approver.actor_id, decision.actor_id)

    def test_report_escapes_untrusted_text(self) -> None:
        report = Report(
            "r",
            "run",
            "<script>alert(1)</script>",
            {"asset": "<img src=x>"},
            {},
            (),
            (),
        )
        rendered = ReportRenderer().render_html(report)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("<img", rendered)
        self.assertIn("&lt;script&gt;", rendered)


if __name__ == "__main__":
    unittest.main()
