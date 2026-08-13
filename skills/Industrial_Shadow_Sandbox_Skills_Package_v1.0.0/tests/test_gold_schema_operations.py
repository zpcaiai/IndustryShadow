from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from shadow_sandbox.common import ActorContext, DomainError
from shadow_sandbox.evaluation.gold import GoldSpec, GoldVault
from shadow_sandbox.operations import BackupService, RecertificationPolicy
from test_foundation import ROOT, actor, store


class TestCipher:
    key_ref = "test-only-not-production"

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> tuple[bytes, bytes]:
        return b"test-nonce12", plaintext[::-1] + associated_data[:0]

    def decrypt(self, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
        if nonce != b"test-nonce12":
            raise ValueError("nonce")
        return ciphertext[::-1]


class GoldSchemaOperationsTests(unittest.TestCase):
    def test_gold_vault_denies_ordinary_identity_and_stores_no_plaintext(self) -> None:
        database = store()
        vault = GoldVault(database, TestCipher())
        evaluator = ActorContext(
            "eval", "t1", "w1", frozenset({"EvaluatorService"}), True
        )
        gold = GoldSpec(
            "gold-F05",
            1,
            "F05@1",
            ("pump_efficiency_loss",),
            ("flow-response-low",),
            ({"id": "pressure_flow_curve", "weight": 1},),
            ("post_recovery_verification",),
            ("write_real_endpoint",),
            {"labeler": "engineer-1"},
        )
        vault.seal(evaluator, gold)
        row = database.query("SELECT ciphertext FROM gold_vault")[0]
        self.assertNotIn(b"pump_efficiency_loss", row["ciphertext"])
        with self.assertRaises(DomainError):
            vault.resolve(actor("Engineer"), gold.gold_id, 1)
        self.assertEqual(gold, vault.resolve(evaluator, gold.gold_id, 1))

    def test_generated_schemas_are_objects_and_scenario_forbids_gold(self) -> None:
        for path in (ROOT / "schemas").rglob("*.json"):
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertIsInstance(value, dict, path)
        scenario = json.loads(
            (ROOT / "schemas/scenarios/scenario-spec-v1.json").read_text()
        )
        self.assertIn("not", scenario)

    def test_backup_restore_and_recertification_change_detection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.db"
            database = __import__(
                "shadow_sandbox.common", fromlist=["SqliteStore"]
            ).SqliteStore(source)
            database.migrate(ROOT / "migrations/0001_core.sql")
            database.close()
            backup = Path(directory) / "backup.db"
            result = BackupService().backup_sqlite(source, backup)
            self.assertTrue(result["sha256"])
            self.assertEqual("ok", BackupService().verify_restore(backup)["integrity"])
        changed = RecertificationPolicy().requires_recertification(
            {"build": "a", "policy": "p1"}, {"build": "b", "policy": "p1"}
        )
        self.assertEqual(("build",), changed)


if __name__ == "__main__":
    unittest.main()
