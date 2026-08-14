from __future__ import annotations

import unittest
from dataclasses import dataclass, replace

from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now
from shadow_sandbox.evaluation.formal_benchmark import (
    S3_CLOSURE_REQUIRED_CHECKS,
    S3_CLOSURE_REQUIRED_METRICS,
    production_storage_binding_digest,
    validate_production_storage_target,
    validate_s3_closure_evidence,
)
from shadow_sandbox.operations.evidence import (
    GateCheck,
    bind_to_acceptance_run,
    complete,
)


@dataclass(frozen=True)
class StoragePlanFixture:
    digest: str
    backend_image: str
    snapshot_object_storage_prefix: str
    backup_object_storage_prefix: str
    backup_workload_identity_arn_digest: str
    snapshot_workload_identity_arn_digest: str


class StorageClosureBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = {
            "schema_version": 1,
            "candidate_image": f"registry.example/industrial-shadow@sha256:{'a' * 64}",
            "cluster_uid_digest": "b" * 64,
            "kubernetes_api_ca_digest": "c" * 64,
            "aws_account_id": "123456789012",
            "aws_region": "us-east-1",
            "s3_bucket": "industrial-shadow-production",
            "s3_probe_prefix": "industrial-shadow/acceptance",
            "snapshot_object_storage_prefix": "industrial-shadow/snapshots",
            "backup_object_storage_prefix": "industrial-shadow/backups",
            "kms_key_id_digest": "d" * 64,
            "backup_workload_identity_arn_digest": "e" * 64,
            "snapshot_workload_identity_arn_digest": "f" * 64,
            "deployment_plan_digest": "1" * 64,
        }
        self.plan = StoragePlanFixture(
            digest="1" * 64,
            backend_image=str(self.profile["candidate_image"]),
            snapshot_object_storage_prefix=str(
                self.profile["snapshot_object_storage_prefix"]
            ),
            backup_object_storage_prefix=str(
                self.profile["backup_object_storage_prefix"]
            ),
            backup_workload_identity_arn_digest=str(
                self.profile["backup_workload_identity_arn_digest"]
            ),
            snapshot_workload_identity_arn_digest=str(
                self.profile["snapshot_workload_identity_arn_digest"]
            ),
        )

    def _evidence(
        self,
        *,
        metric_overrides: dict[str, float | int | str] | None = None,
        missing_check: str | None = None,
    ):
        binding = production_storage_binding_digest(self.profile, self.plan)
        sentinel_digests = {"backup": "2" * 64, "snapshot": "3" * 64}
        metrics: dict[str, float | int | str] = {
            **S3_CLOSURE_REQUIRED_METRICS,
            "storage_binding_digest": binding,
            "backup_sentinel_binding_digest": sentinel_digests["backup"],
            "snapshot_sentinel_binding_digest": sentinel_digests["snapshot"],
            "sentinel_binding_digest": canonical_digest(sentinel_digests),
        }
        metrics.update(metric_overrides or {})
        required_checks = set(S3_CLOSURE_REQUIRED_CHECKS)
        if missing_check is not None:
            required_checks.discard(missing_check)
        evidence = complete(
            "s3",
            started_at=utc_now(),
            coordinates={"storage_binding_digest": binding},
            checks=tuple(
                GateCheck(name, True)
                for name in sorted(required_checks)
            ),
            metrics=metrics,
        )
        return bind_to_acceptance_run(
            evidence,
            run_id="acceptance-storage-binding-1",
            release_digest="4" * 64,
        )

    def test_storage_binding_is_recomputed_from_profile_and_plan(self) -> None:
        evidence = self._evidence()
        expected = production_storage_binding_digest(self.profile, self.plan)
        self.assertEqual(
            expected,
            validate_s3_closure_evidence(evidence, self.profile, self.plan),
        )

    def test_target_rejects_nested_prefixes_and_reused_workload_role(self) -> None:
        nested = {**self.profile, "s3_probe_prefix": "industrial-shadow"}
        with self.assertRaises(DomainError):
            validate_production_storage_target(nested)
        shared_role = {
            **self.profile,
            "snapshot_workload_identity_arn_digest": self.profile[
                "backup_workload_identity_arn_digest"
            ],
        }
        with self.assertRaises(DomainError):
            validate_production_storage_target(shared_role)

    def test_plan_drift_is_rejected(self) -> None:
        changed_plan = replace(
            self.plan,
            backup_object_storage_prefix="industrial-shadow/other-backups",
        )
        with self.assertRaises(DomainError):
            production_storage_binding_digest(self.profile, changed_plan)

    def test_evidence_requires_exact_metrics_checks_and_sentinel_digest(self) -> None:
        with self.assertRaises(DomainError):
            validate_s3_closure_evidence(
                self._evidence(metric_overrides={"workload_identities_verified": True}),
                self.profile,
                self.plan,
            )
        with self.assertRaises(DomainError):
            validate_s3_closure_evidence(
                self._evidence(missing_check="control_lifecycle_backup_prefix"),
                self.profile,
                self.plan,
            )
        with self.assertRaises(DomainError):
            validate_s3_closure_evidence(
                self._evidence(metric_overrides={"sentinel_binding_digest": "5" * 64}),
                self.profile,
                self.plan,
            )


if __name__ == "__main__":
    unittest.main()
