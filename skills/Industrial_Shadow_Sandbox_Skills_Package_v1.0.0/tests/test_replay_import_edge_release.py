from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from shadow_edge.readonly import ReadonlyOpcUaAdapter
from shadow_sandbox.common import DomainError
from shadow_sandbox.integrations.imports import HistoricalImporter, SignalMapping
from shadow_sandbox.release import ClosureService, ReleaseManifest
from shadow_sandbox.replay import ReplayExecutor, ReplayManifest, compare_variants
from shadow_sandbox.shadow_pilot import PilotMode, assert_no_action_surface, transition


class ReplayImportEdgeReleaseTests(unittest.TestCase):
    def test_replay_speed_changes_no_structured_output(self) -> None:
        source = {"events": [1, 2, 3]}
        digest = __import__(
            "shadow_sandbox.common.models", fromlist=["canonical_digest"]
        ).canonical_digest(source)
        executor = ReplayExecutor(
            {"quality": lambda value: {**value, "quality": "TRUSTED"}}
        )
        outputs = []
        for speed in ("1x", "2x", "10x", "50x", "max"):
            manifest = ReplayManifest(
                "replay-" + speed,
                "run",
                digest,
                ("quality",),
                speed,
                {"quality": "v1"},
                {},
                "variant-" + speed,
            )
            outputs.append(executor.execute(manifest, source, digest).output_digest)
        self.assertEqual(1, len(set(outputs)))
        comparisons = compare_variants({"e": {"rank": 1}}, {"e": {"rank": 2}})
        self.assertTrue(comparisons[0].changed)

    def test_csv_import_profiles_normalizes_and_rejects_formula(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = root / "valid.csv"
            valid.write_text(
                "tag,time,value,quality\nLT101,2026-01-01T00:00:00Z,1000,Good\n",
                encoding="utf-8",
            )
            importer = HistoricalImporter(root)
            profile = importer.profile(valid)
            self.assertEqual(1, profile.row_count)
            mapping = SignalMapping(
                "LT101",
                "Tank101.Level",
                "m",
                "m",
                "time",
                "value",
                "quality",
                "UTC",
                0.9,
                None,
            )
            rows = list(importer.normalize(valid, [mapping]))
            self.assertEqual(1000.0, rows[0].value)
            malicious = root / "bad.csv"
            malicious.write_text(
                "tag,time,value\nLT101,2026-01-01T00:00:00Z,=CMD()\n", encoding="utf-8"
            )
            with self.assertRaises(DomainError):
                list(importer.rows(malicious))
            outside = root.parent / "outside.csv"
            with self.assertRaises(DomainError):
                importer.profile(outside)

    def test_edge_surface_is_read_only_and_pilot_is_gated(self) -> None:
        public = {
            name for name in dir(ReadonlyOpcUaAdapter) if not name.startswith("_")
        }
        self.assertFalse(public.intersection({"write", "call", "invoke", "execute"}))
        self.assertEqual(
            PilotMode.SILENT_SHADOW,
            transition(PilotMode.CONNECTION_ASSESSMENT, PilotMode.SILENT_SHADOW),
        )
        with self.assertRaises(DomainError):
            transition(PilotMode.SILENT_SHADOW, PilotMode.ADVISORY)
        with self.assertRaises(DomainError):
            assert_no_action_surface("real_readonly")

    def test_closure_certificate_is_scope_limited_and_verifiable(self) -> None:
        manifest = ReleaseManifest(
            "a" * 64,
            "b" * 64,
            "c" * 64,
            "d" * 64,
            "e" * 64,
            "f" * 64,
            "1" * 64,
            "2" * 64,
            "3" * 64,
            ("0.0.9",),
        )
        key = b"closure-signing-key-for-tests-32b"
        service = ClosureService()
        certificate = service.issue(
            certificate_id="cert-1",
            manifest=manifest,
            gate_passed=True,
            evidence_digests=("4" * 64,),
            residual_risks=("lab OPC UA only",),
            rollback_target="0.0.9",
            signer="release-service",
            signing_key=key,
        )
        self.assertTrue(service.verify(certificate, key))
        self.assertIn("real control", certificate.exclusions)
        with self.assertRaises(DomainError):
            service.issue(
                certificate_id="cert-2",
                manifest=manifest,
                gate_passed=False,
                evidence_digests=("4" * 64,),
                residual_risks=(),
                rollback_target="0.0.9",
                signer="release-service",
                signing_key=key,
            )


if __name__ == "__main__":
    unittest.main()
