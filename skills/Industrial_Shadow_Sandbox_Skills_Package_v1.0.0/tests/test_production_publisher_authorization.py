from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import cast

from shadow_sandbox.common.models import DomainError
from shadow_sandbox.operations.production_deployment import (
    KubernetesProductionPublisher,
    ProductionDeploymentPlan,
)


class ProductionPublisherAuthorizationTests(unittest.TestCase):
    def test_production_tools_support_the_direct_workflow_entrypoints(self) -> None:
        root = Path(__file__).resolve().parents[1]
        cases = (
            ("check_release_evidence.py", (), 1, "RELEASE_BLOCKED: missing"),
            ("deploy_production_kubernetes.py", ("--help",), 0, "usage:"),
            ("sign_production_approval.py", ("--help",), 0, "usage:"),
        )
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        for script, arguments, expected_code, expected_output in cases:
            with self.subTest(script=script):
                completed = subprocess.run(
                    [sys.executable, str(root / "tools" / script), *arguments],
                    cwd=root,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(expected_code, completed.returncode, completed.stderr)
                self.assertIn(expected_output, completed.stdout)

    @staticmethod
    def _plan() -> ProductionDeploymentPlan:
        return cast(
            ProductionDeploymentPlan,
            SimpleNamespace(namespace="industrial-shadow", plan_id="release-20260809"),
        )

    def _publisher(
        self, *, operation: str, confirmation: str
    ) -> KubernetesProductionPublisher:
        return KubernetesProductionPublisher(
            self._plan(),
            operation=operation,
            confirmation=confirmation,
            context="production-test",
            expected_cluster_uid_digest="a" * 64,
            expected_kubernetes_api_ca_digest="b" * 64,
        )

    def test_deploy_authorization_cannot_resume_rollback(self) -> None:
        publisher = self._publisher(
            operation="deploy",
            confirmation="industrial-shadow:release-20260809:deploy",
        )
        with self.assertRaises(DomainError) as raised:
            publisher.resume_rollback()
        self.assertEqual(
            "PRODUCTION_ROLLBACK_CONFIRMATION_REQUIRED", raised.exception.code
        )
        with self.assertRaises(DomainError) as noop:
            publisher.verify_no_mutation()
        self.assertEqual(
            "PRODUCTION_ROLLBACK_CONFIRMATION_REQUIRED", noop.exception.code
        )
        with self.assertRaises(DomainError) as verification:
            publisher.verify_restored_bundle()
        self.assertEqual(
            "PRODUCTION_ROLLBACK_CONFIRMATION_REQUIRED", verification.exception.code
        )

    def test_restore_authorization_cannot_publish_candidate(self) -> None:
        publisher = self._publisher(
            operation="restore-prior-bundle",
            confirmation="industrial-shadow:release-20260809:rollback",
        )
        with self.assertRaises(DomainError) as raised:
            publisher.run()
        self.assertEqual(
            "PRODUCTION_DEPLOY_CONFIRMATION_REQUIRED", raised.exception.code
        )

    def test_operation_specific_confirmations_are_not_interchangeable(self) -> None:
        for operation, confirmation in (
            ("deploy", "industrial-shadow:release-20260809:rollback"),
            ("restore-prior-bundle", "industrial-shadow:release-20260809:deploy"),
        ):
            with self.subTest(operation=operation), self.assertRaises(DomainError):
                self._publisher(operation=operation, confirmation=confirmation)


if __name__ == "__main__":
    unittest.main()
