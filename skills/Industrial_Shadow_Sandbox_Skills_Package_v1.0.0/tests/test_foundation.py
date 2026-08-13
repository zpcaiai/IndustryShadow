from __future__ import annotations

import sqlite3
import unittest
from pathlib import Path

from shadow_sandbox.asset_registry import (
    AssetRegistryService,
    pump_tank_model,
    validate_model,
)
from shadow_sandbox.common import ActorContext, DomainError, SqliteStore
from shadow_sandbox.runtime import RunManifest, RunOrchestrator, RunState
from shadow_sandbox.scenarios import (
    ClockSpec,
    ScenarioService,
    ScenarioSpec,
    expand_mvp_benchmark,
    parse_document,
)

ROOT = Path(__file__).resolve().parents[1]


def store() -> SqliteStore:
    result = SqliteStore(":memory:")
    result.migrate_all(ROOT / "migrations")
    return result


def actor(*roles: str, workspace: str = "w1") -> ActorContext:
    return ActorContext("u1", "t1", workspace, frozenset(roles))


def manifest(environment: str = "simulator") -> RunManifest:
    return RunManifest(
        *(["a" * 64] * 10),
        seed=42,
        clock_policy="deterministic-v1",
        endpoint_identity="sim-1",
        environment_type=environment,
    )


class FoundationTests(unittest.TestCase):
    def test_asset_model_is_valid_publishable_and_immutable(self) -> None:
        database = store()
        model = pump_tank_model()
        self.assertEqual([], validate_model(model))
        digest = AssetRegistryService(database).publish(actor("Engineer"), model)
        self.assertEqual(model.digest, digest)
        with self.assertRaises(sqlite3.IntegrityError):
            AssetRegistryService(database).publish(actor("Engineer"), model)
        resolved = AssetRegistryService(database).resolve_signal(
            actor("Viewer"), model.model_id, 1, "Tank101.Level"
        )
        self.assertEqual("read_only", resolved.access_mode)

    def test_scenario_rejects_gold_and_benchmark_has_required_coverage(self) -> None:
        with self.assertRaises(DomainError) as caught:
            parse_document('{"scenario_id":"x","gold":{"root_causes":["secret"]}}')
        self.assertEqual("GOLD_FIELD_FORBIDDEN", caught.exception.code)
        episodes = expand_mvp_benchmark()
        faults = [item for item in episodes if item.fault_type]
        normals = [item for item in episodes if not item.fault_type]
        self.assertEqual(120, len(faults))
        self.assertEqual(54, len(normals))
        self.assertEqual(174, len(episodes))
        fault_cells = {
            (item.fault_type, item.severity, item.load) for item in faults
        }
        self.assertEqual(
            {
                (f"F{number:02d}", severity, load)
                for number in range(1, 11)
                for severity in ("low", "medium", "high")
                for load in ("low", "nominal", "high")
            },
            fault_cells,
        )
        self.assertEqual(len(episodes), len({item.episode_id for item in episodes}))

    def test_empty_scenario_publishes_and_digest_is_stable(self) -> None:
        database = store()
        model = pump_tank_model()
        spec = ScenarioSpec(
            "normal-startup",
            1,
            "pump-tank-process@1",
            "pump-tank-v1@1",
            42,
            ClockSpec(60, 10),
            {"mode": "startup"},
            (),
        )
        digest = ScenarioService(database).publish(
            actor("Engineer"), spec, {signal.key for signal in model.signals}
        )
        self.assertEqual(spec.digest, digest)

    def test_run_state_machine_is_durable_idempotent_and_optimistic(self) -> None:
        database = store()
        service = RunOrchestrator(database)
        created = service.create(actor("Engineer"), manifest(), "same-key")
        self.assertEqual(
            created, service.create(actor("Engineer"), manifest(), "same-key")
        )
        run_id = created["run_id"]
        transition = service.transition(
            actor("Engineer"), run_id, RunState.VALIDATING, "validate", 1
        )
        self.assertEqual(RunState.VALIDATING, transition["to"])
        with self.assertRaises(DomainError) as caught:
            service.transition(
                actor("Engineer"), run_id, RunState.RUNNING, "skip stages", 2
            )
        self.assertEqual("ILLEGAL_TRANSITION", caught.exception.code)
        with self.assertRaises(DomainError):
            service.get(actor("Viewer", workspace="w2"), run_id)
        self.assertEqual(2, len(service.timeline(actor("Viewer"), run_id)))

    def test_run_idempotency_keys_are_workspace_scoped(self) -> None:
        database = store()
        service = RunOrchestrator(database)
        first = service.create(
            actor("Engineer", workspace="w1"), manifest(), "shared-key"
        )
        second = service.create(
            actor("Engineer", workspace="w2"), manifest(), "shared-key"
        )
        self.assertNotEqual(first["run_id"], second["run_id"])
        self.assertEqual(
            first,
            service.create(actor("Engineer", workspace="w1"), manifest(), "shared-key"),
        )


if __name__ == "__main__":
    unittest.main()
