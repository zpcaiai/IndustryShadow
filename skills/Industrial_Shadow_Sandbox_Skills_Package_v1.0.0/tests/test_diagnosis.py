from __future__ import annotations

import unittest

from shadow_collector.models import RawSignalEvent
from shadow_sandbox.diagnosis.evidence import Claim, EvidenceService, EvidenceValidator
from shadow_sandbox.diagnosis.hypotheses import HypothesisRanker
from shadow_sandbox.diagnosis.residuals import ResidualEngine
from shadow_sandbox.planning import CheckPlanner
from shadow_sandbox.quality import QualityService, QualityState, UnivariateDetector


def events(values: list[float], flags: tuple[str, ...] = ()) -> list[RawSignalEvent]:
    return [
        RawSignalEvent(
            "t",
            "w",
            "run",
            "scenario",
            "endpoint",
            "node",
            "Tank101.Level",
            "Double",
            value,
            f"2026-01-01T00:00:{index:02d}Z",
            f"2026-01-01T00:00:{index:02d}Z",
            f"2026-01-01T00:00:{index:02d}Z",
            "Good",
            index + 1,
            flags,
        )
        for index, value in enumerate(values)
    ]


class DiagnosisTests(unittest.TestCase):
    def test_quality_gates_untrusted_and_detector_is_bounded(self) -> None:
        quality = QualityService().assess(events([1, 2, 3]), expected_count=10)
        self.assertEqual(QualityState.UNTRUSTED, quality.state)
        self.assertEqual((), UnivariateDetector().detect(quality, [1, 2, 3], [1, 1, 1]))
        trusted = QualityService().assess(events([10, 10.1, 9.9, 10.0, 10.2]), 5)
        observed = UnivariateDetector().detect(
            trusted, [20, 21, 22], [10, 10.1, 9.9, 10]
        )
        self.assertTrue(observed)
        self.assertTrue(all(0 <= item.severity <= 1 for item in observed))

    def test_residual_evidence_hypothesis_and_safe_plan(self) -> None:
        residual = ResidualEngine().mass_balance(
            "run",
            [4.0, 3.9, 3.8],
            [0.05, 0.05, 0.05],
            [0.04, 0.04, 0.04],
            1.0,
            6.0,
            "TRUSTED",
            ("raw-1", "raw-2"),
        )
        self.assertLess(residual.residual or 0, 0)
        service = EvidenceService()
        evidence, symptom = service.materialize(
            run_id="run",
            workspace_id="w",
            observation_type="mass_balance",
            observation=residual.residual,
            baseline=0,
            threshold=0.01,
            quality_state="TRUSTED",
            source_refs=residual.source_event_refs,
            source_hashes=("hash",),
            related_signals=("Tank101.Level",),
            transformation_ref=residual.formula_digest,
            units="m3/s",
        )
        self.assertIsNotNone(symptom)
        claim = Claim(
            "run",
            "w",
            "Tank101",
            "mass deficit",
            -0.1,
            "m3/s",
            {},
            (evidence.evidence_id,),
            "system",
        )
        EvidenceValidator(service.evidence).validate_claim(claim)
        diagnosis = HypothesisRanker().rank([symptom], service.evidence, "TRUSTED")  # type: ignore[list-item]
        self.assertTrue(diagnosis.hypotheses)
        plan = CheckPlanner().plan("run", diagnosis, "simulator")
        self.assertTrue(plan.plan_hash)
        self.assertEqual("verify_data_quality", plan.steps[0].check_id)
        real_plan = CheckPlanner().plan("run", diagnosis, "real_readonly")
        self.assertTrue(all(not step.simulation_only for step in real_plan.steps))


if __name__ == "__main__":
    unittest.main()
