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
from shadow_sandbox.operations.storage_probe import (
    AWS_STORAGE_POLICY_DIGEST_FIELDS,
    aws_storage_policy_bundle_digest,
    github_actions_caller_trust_contract,
)


@dataclass(frozen=True)
class StorageEgressFixture:
    partition: str
    region: str
    digest: str


@dataclass(frozen=True)
class StoragePlanFixture:
    digest: str
    backend_image: str
    snapshot_object_storage_prefix: str
    backup_object_storage_prefix: str
    object_storage_region: str
    object_storage_account_id: str
    backup_workload_identity_arn_digest: str
    snapshot_workload_identity_arn_digest: str
    storage_egress_contract: StorageEgressFixture


class StorageClosureBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        policy_digests = {
            name: canonical_digest({"fixture": name})
            for name in AWS_STORAGE_POLICY_DIGEST_FIELDS
        }
        caller_trust_contract = github_actions_caller_trust_contract(
            account_id="123456789012",
            region="us-east-1",
            repository="industrial-shadow/industry-shadow",
            repository_owner_id="214596190",
            repository_id="24681012",
            ref="refs/heads/main",
            environment="production-acceptance",
            workflow="production-acceptance",
        )
        policy_digests["s3_control_plane_caller_trust_contract_digest"] = (
            canonical_digest(caller_trust_contract)
        )
        self.profile = {
            "schema_version": 1,
            "candidate_image": f"registry.example/industrial-shadow@sha256:{'a' * 64}",
            "cluster_uid_digest": "b" * 64,
            "kubernetes_api_ca_digest": "c" * 64,
            "aws_account_id": "123456789012",
            "aws_partition": "aws",
            "aws_region": "us-east-1",
            "s3_bucket": "industrial-shadow-production",
            "s3_probe_prefix": "industrial-shadow/acceptance",
            "s3_control_plane_caller_trust_contract": caller_trust_contract,
            "snapshot_object_storage_prefix": "industrial-shadow/snapshots",
            "backup_object_storage_prefix": "industrial-shadow/backups",
            "kms_key_id_digest": "d" * 64,
            "backup_workload_identity_arn_digest": "e" * 64,
            "snapshot_workload_identity_arn_digest": "f" * 64,
            **policy_digests,
            "aws_storage_policy_bundle_digest": aws_storage_policy_bundle_digest(
                policy_digests
            ),
            "deployment_plan_digest": "1" * 64,
            "storage_egress_contract_digest": "9" * 64,
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
            object_storage_region="us-east-1",
            object_storage_account_id="123456789012",
            backup_workload_identity_arn_digest=str(
                self.profile["backup_workload_identity_arn_digest"]
            ),
            snapshot_workload_identity_arn_digest=str(
                self.profile["snapshot_workload_identity_arn_digest"]
            ),
            storage_egress_contract=StorageEgressFixture(
                partition="aws",
                region="us-east-1",
                digest="9" * 64,
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
            **{
                name: str(self.profile[name])
                for name in AWS_STORAGE_POLICY_DIGEST_FIELDS
            },
            "aws_storage_policy_bundle_digest": str(
                self.profile["aws_storage_policy_bundle_digest"]
            ),
        }
        metrics.update(metric_overrides or {})
        required_checks = set(S3_CLOSURE_REQUIRED_CHECKS)
        if missing_check is not None:
            required_checks.discard(missing_check)
        evidence = complete(
            "s3",
            started_at=utc_now(),
            coordinates={"storage_binding_digest": binding},
            checks=tuple(GateCheck(name, True) for name in sorted(required_checks)),
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
        with self.assertRaises(DomainError):
            production_storage_binding_digest(
                self.profile,
                replace(self.plan, object_storage_account_id="210987654321"),
            )
        for changed_egress in (
            replace(self.plan.storage_egress_contract, region="us-west-2"),
            replace(self.plan.storage_egress_contract, partition="aws-cn"),
            replace(self.plan.storage_egress_contract, digest="8" * 64),
        ):
            with self.assertRaises(DomainError):
                production_storage_binding_digest(
                    self.profile,
                    replace(self.plan, storage_egress_contract=changed_egress),
                )

    def test_evidence_requires_exact_metrics_checks_and_sentinel_digest(self) -> None:
        with self.assertRaises(DomainError):
            validate_s3_closure_evidence(
                self._evidence(metric_overrides={"workload_identities_verified": True}),
                self.profile,
                self.plan,
            )
        for required_check in (
            "control_lifecycle_backup_prefix",
            "control_s3_control_plane_caller_trust_contract_exact",
            "control_s3_control_plane_caller_iam_role_trust_policy_signed",
            "control_s3_control_plane_caller_iam_role_permissions_least_privilege",
        ):
            with self.assertRaises(DomainError):
                validate_s3_closure_evidence(
                    self._evidence(missing_check=required_check),
                    self.profile,
                    self.plan,
                )
        with self.assertRaises(DomainError):
            validate_s3_closure_evidence(
                self._evidence(metric_overrides={"sentinel_binding_digest": "5" * 64}),
                self.profile,
                self.plan,
            )

    def test_policy_and_caller_digests_are_independently_recomputed(self) -> None:
        for field in (
            "s3_control_plane_caller_arn_digest",
            "s3_control_plane_caller_iam_role_trust_policy_digest",
            "s3_control_plane_caller_iam_role_permissions_digest",
            "kms_admin_role_arn_digest",
            "kms_admin_iam_role_trust_policy_digest",
            "aws_irsa_oidc_provider_arn_digest",
            "aws_irsa_oidc_provider_configuration_digest",
            "kms_key_policy_digest",
            "aws_storage_policy_bundle_digest",
        ):
            with self.assertRaises(DomainError):
                validate_s3_closure_evidence(
                    self._evidence(metric_overrides={field: "0" * 64}),
                    self.profile,
                    self.plan,
                )
        target_drift = {
            **self.profile,
            "kms_grants_digest": "0" * 64,
        }
        with self.assertRaises(DomainError):
            validate_production_storage_target(target_drift)
        with self.assertRaises(DomainError):
            validate_production_storage_target(
                {**self.profile, "aws_partition": "aws-cn"}
            )


if __name__ == "__main__":
    unittest.main()
