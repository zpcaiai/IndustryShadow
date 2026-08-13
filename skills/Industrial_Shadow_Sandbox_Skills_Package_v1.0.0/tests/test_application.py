from __future__ import annotations

import datetime as dt
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from shadow_collector.models import RawSignalEvent
from shadow_collector.writer import RawEventWriter
from shadow_sandbox.application import ApplicationService
from shadow_sandbox.asset_registry import pump_tank_model
from shadow_sandbox.common import ActorContext, DomainError, SqliteStore
from shadow_sandbox.runtime import RunManifest

ROOT = Path(__file__).resolve().parents[1]


def context(actor_id: str = "engineer", *roles: str) -> ActorContext:
    return ActorContext(
        actor_id, "tenant", "workspace", frozenset(roles or ("Engineer",))
    )


def run_manifest(environment: str = "simulator") -> dict[str, object]:
    return asdict(
        RunManifest(
            *(value * 64 for value in "abcdefghij"),
            seed=11,
            clock_policy="deterministic-v1",
            endpoint_identity="simulator-1",
            environment_type=environment,
        )
    )


class ApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = SqliteStore(":memory:")
        self.assertEqual(3, self.store.migrate_all(ROOT / "migrations"))
        self.application = ApplicationService(
            self.store, import_directory=Path(self.temporary.name) / "imports"
        )
        self.engineer = context("engineer", "Engineer", "PackAuthor", "Admin")

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def test_resource_lifecycle_is_versioned_scoped_and_sealable(self) -> None:
        model = asdict(pump_tank_model())
        created = self.application.create_asset_model(self.engineer, model)
        self.assertEqual(1, created["version"])
        self.assertTrue(
            self.application.validate_asset_model(self.engineer, model["model_id"])[
                "valid"
            ]
        )
        model["metadata"] = {"revision": 2}
        updated = self.application.update_asset_model(
            self.engineer, str(model["model_id"]), model, expected_version=1
        )
        self.assertEqual(2, updated["version"])
        published = self.application.publish_asset_model(
            self.engineer, str(model["model_id"])
        )
        self.assertTrue(published["sealed"])
        history = self.store.query(
            "SELECT version FROM domain_resource_versions WHERE resource_type='asset_model_draft' ORDER BY version"
        )
        self.assertEqual([1, 2], [row["version"] for row in history])
        outsider = ActorContext(
            "other", "tenant", "other-workspace", frozenset({"Viewer"})
        )
        with self.assertRaises(DomainError) as caught:
            self.application.resources.get(
                outsider, "asset_model_draft", str(model["model_id"])
            )
        self.assertEqual("RESOURCE_NOT_FOUND", caught.exception.code)

    def test_scenario_draft_preview_publish_reconstructs_nested_fault(self) -> None:
        signal_keys = [item.key for item in pump_tank_model().signals]
        body = {
            "schema_version": 1,
            "scenario_id": "fault-test",
            "scenario_version": 1,
            "process_model_ref": "pump-tank@1",
            "asset_model_ref": "pump-tank-v1@1",
            "seed": 7,
            "clock": {
                "duration_seconds": 20,
                "warmup_seconds": 2,
                "step_ms": 100,
                "speed": 1,
            },
            "operating_profile": {"mode": "steady"},
            "timeline": [
                {
                    "at": 5,
                    "inject": {
                        "target": "Tank101.Level",
                        "operator": "bias",
                        "parameters": {"amount": 1},
                    },
                }
            ],
        }
        self.application.create_scenario(self.engineer, body)
        self.assertTrue(
            self.application.validate_scenario(
                self.engineer, "fault-test", signal_keys
            )["valid"]
        )
        preview = self.application.preview_scenario(self.engineer, "fault-test")
        self.assertEqual(["Tank101.Level"], preview["affected_signals"])
        published = self.application.publish_scenario(
            self.engineer, "fault-test", signal_keys
        )
        self.assertEqual("PUBLISHED", published["state"])

    def test_diagnosis_pipeline_persists_queryable_versioned_products(self) -> None:
        run = self.application.create_run(
            self.engineer, run_manifest(), "application-pipeline"
        )
        run_id = run["run_id"]
        now = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
        events = []
        for index, value in enumerate((1.0, 1.0, 1.0, 8.0, 9.0, 10.0), 1):
            timestamp = (
                (now + dt.timedelta(seconds=index)).isoformat().replace("+00:00", "Z")
            )
            events.append(
                RawSignalEvent(
                    "tenant",
                    "workspace",
                    run_id,
                    "scenario",
                    "simulator-1",
                    "node:level",
                    "Tank101.Level",
                    "Double",
                    value,
                    timestamp,
                    timestamp,
                    timestamp,
                    "Good",
                    index,
                )
            )
        self.assertEqual(len(events), RawEventWriter(self.store).persist(events))
        quality = self.application.quality_and_detect(
            self.engineer, run_id, {"baselines": {"Tank101.Level": [1, 1, 1]}}
        )
        self.assertEqual("quality_detection", quality["resource_type"])
        residuals = self.application.residuals_and_consistency(
            self.engineer,
            run_id,
            {
                "series": {"level": [1, 0.5], "qin": [0.1, 0.1], "qout": [0.1, 0.1]},
                "step_s": 1,
                "area_m2": 1,
                "quality_state": "TRUSTED",
            },
        )
        observation = residuals["payload"]["residuals"][0]
        evidence = self.application.materialize_evidence(
            self.engineer,
            run_id,
            {
                "observations": [
                    {
                        "observation_type": observation["residual_ref"],
                        "observation": observation["residual"],
                        "baseline": 0,
                        "threshold": 0.01,
                        "quality_state": "TRUSTED",
                        "source_refs": ["event-1"],
                        "source_hashes": ["a" * 64],
                        "related_signals": ["Tank101.Level"],
                        "transformation_ref": "mass-balance@1",
                        "units": "m3/s",
                    }
                ]
            },
        )
        self.assertEqual(1, len(evidence["payload"]["symptoms"]))
        diagnosis = self.application.generate_hypotheses(self.engineer, run_id, {})
        self.assertIn(diagnosis["payload"]["status"], {"RANKED", "INCONCLUSIVE"})
        plan = self.application.create_check_plan(self.engineer, run_id, {})
        self.assertEqual(run_id, plan["payload"]["run_id"])

    def test_import_edge_evaluation_gate_and_report_have_real_state(self) -> None:
        import_dir = self.application.import_directory
        source_path = import_dir / "sample.csv"
        source_path.write_text(
            "tag,time,value,quality\nlevel,2026-01-01T00:00:00Z,100,good\n",
            encoding="utf-8",
        )
        source = self.application.register_import_source(
            self.engineer, {"path": str(source_path)}
        )
        profile = self.application.profile_import_source(
            self.engineer, source["resource_id"]
        )
        self.assertEqual(1, profile["payload"]["row_count"])
        mapping = {
            "source_tag": "level",
            "signal_key": "Tank101.Level",
            "source_unit": "C",
            "target_unit": "degC",
            "timestamp_field": "time",
            "value_field": "value",
            "quality_field": "quality",
            "timezone": "UTC",
            "confidence": 1.0,
            "reviewer": "engineer",
        }
        job = self.application.create_import_job(
            self.engineer, {"source_id": source["resource_id"], "mappings": [mapping]}
        )
        self.assertEqual(1, job["payload"]["accepted_rows"])

        gateway = self.application.register_edge_gateway(
            self.engineer,
            {
                "environment_type": "real_readonly",
                "site_id": "site-1",
                "public_key": "pk",
                "endpoint": "opc.tcp://site:4840",
                "certificate_fingerprint": "a" * 64,
            },
        )
        accepted = self.application.ingest_edge_batch(
            self.engineer,
            {
                "gateway_id": gateway["gateway_id"],
                "sequence_start": 1,
                "sequence_end": 1,
                "events": [{"read": True}],
            },
        )
        self.assertTrue(accepted["accepted"])

        evaluator = context("evaluator", "EvaluatorService")
        episodes = []
        for index in range(150):
            normal = index >= 100
            episodes.append(
                {
                    "episode_id": f"episode-{index}",
                    "is_normal": normal,
                    "gold_causes": [] if normal else ["cause"],
                    "ranked_causes": [] if normal else ["cause"],
                    "detected": not normal,
                    "plan_score": 1,
                    "replay_match": True,
                    "report_success": True,
                    "trace_success": True,
                    "slice_labels": {"kind": "normal" if normal else "fault"},
                }
            )
        evaluation = self.application.create_evaluation(
            evaluator, {"episodes": episodes}
        )
        gate = self.application.evaluate_release_gate(
            evaluator,
            {"evaluation_id": evaluation["resource_id"], "bundle_digest": "f" * 64},
        )
        self.assertTrue(gate["payload"]["passed"])
        promotion = self.application.promote_release_gate(
            self.engineer,
            gate["resource_id"],
            {"bundle_digest": "f" * 64, "reason": "test"},
        )
        self.assertEqual(
            gate["payload"]["certification_digest"], promotion["certification_digest"]
        )

        run = self.application.create_run(self.engineer, run_manifest(), "report-run")
        report = self.application.generate_report(
            self.engineer,
            {"run_id": run["run_id"], "sections": {"gate": gate["payload"]}},
        )
        rendered, media_type = self.application.render_report(
            self.engineer, report["resource_id"], "text/html"
        )
        self.assertEqual("text/html", media_type)
        self.assertIn("Report digest", rendered)


if __name__ == "__main__":
    unittest.main()
