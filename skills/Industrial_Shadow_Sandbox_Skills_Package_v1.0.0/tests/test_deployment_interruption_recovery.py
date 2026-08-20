from __future__ import annotations

import datetime as dt
import unittest
from types import SimpleNamespace
from typing import Any, cast

from shadow_sandbox.common.models import DomainError
from shadow_sandbox.operations.production_deployment import ProductionDeploymentPlan

from tools.deploy_production_kubernetes import PUBLISH_RBAC, _validate_journal


class DeploymentInterruptionRecoveryTests(unittest.TestCase):
    cluster_digest = "a" * 64
    api_ca_digest = "b" * 64

    @staticmethod
    def _plan() -> ProductionDeploymentPlan:
        return cast(
            ProductionDeploymentPlan,
            SimpleNamespace(
                plan_id="release-20260809",
                digest="c" * 64,
                namespace="industrial-shadow",
                migration_job="shadow-migrate-release-20260809",
                bootstrap_manifest=SimpleNamespace(sha256="d" * 64),
                migration_manifest=SimpleNamespace(sha256="e" * 64),
                runtime_manifest=SimpleNamespace(sha256="f" * 64),
                rollback_manifest=SimpleNamespace(sha256="1" * 64),
                workloads=(),
            ),
        )

    def _entry(self, offset: int, phase: str, **details: Any) -> dict[str, Any]:
        timestamp = dt.datetime(2026, 8, 14, tzinfo=dt.timezone.utc) + dt.timedelta(
            seconds=offset
        )
        return {
            "at": timestamp.isoformat().replace("+00:00", "Z"),
            "phase": phase,
            "plan_id": "release-20260809",
            "plan_digest": "c" * 64,
            "namespace": "industrial-shadow",
            "cluster_uid_digest": self.cluster_digest,
            **details,
        }

    def _preflight(self) -> list[dict[str, Any]]:
        return [
            self._entry(
                0,
                "cluster_identity_verified",
                kubernetes_api_ca_digest=self.api_ca_digest,
            ),
            self._entry(1, "rbac_verified", permission_count=len(PUBLISH_RBAC)),
            self._entry(2, "server_dry_run_completed"),
        ]

    def test_preflight_only_is_a_verified_noop(self) -> None:
        state = _validate_journal(
            self._preflight(),
            plan=self._plan(),
            cluster_uid_digest=self.cluster_digest,
            api_ca_digest=self.api_ca_digest,
        )
        self.assertEqual("no_mutation", state.state)
        self.assertEqual(0, state.rollback_attempts)

    def test_marker_before_apply_proves_interrupted_mutation(self) -> None:
        journal = self._preflight() + [self._entry(3, "candidate_mutation_started")]
        state = _validate_journal(
            journal,
            plan=self._plan(),
            cluster_uid_digest=self.cluster_digest,
            api_ca_digest=self.api_ca_digest,
        )
        self.assertEqual("unfinished", state.state)
        self.assertEqual(0, state.rollback_attempts)

    def test_apply_without_durable_marker_is_rejected(self) -> None:
        journal = self._preflight() + [
            self._entry(3, "manifest_applied", artifact_sha256="d" * 64)
        ]
        with self.assertRaises(DomainError):
            _validate_journal(
                journal,
                plan=self._plan(),
                cluster_uid_digest=self.cluster_digest,
                api_ca_digest=self.api_ca_digest,
            )

    def test_completed_rollback_is_not_reported_as_unfinished(self) -> None:
        journal = self._preflight() + [
            self._entry(3, "candidate_mutation_started"),
            self._entry(4, "rollback_attempted", attempted=True, succeeded=False),
            self._entry(
                5,
                "migration_stop_attempted",
                resource="job/shadow-migrate-release-20260809",
            ),
            self._entry(
                6,
                "migration_stopped",
                resource="job/shadow-migrate-release-20260809",
            ),
            self._entry(7, "manifest_applied", artifact_sha256="1" * 64),
            self._entry(8, "candidate_inventory_pruned", resources=[]),
            self._entry(
                9,
                "rollback_succeeded",
                attempted=True,
                succeeded=True,
                revisions={},
                resources=[],
            ),
        ]
        state = _validate_journal(
            journal,
            plan=self._plan(),
            cluster_uid_digest=self.cluster_digest,
            api_ca_digest=self.api_ca_digest,
        )
        self.assertEqual("restored", state.state)
        self.assertEqual(1, state.rollback_attempts)


if __name__ == "__main__":
    unittest.main()
