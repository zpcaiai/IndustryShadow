from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import unittest
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from typing import Any
from unittest.mock import patch

from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json
from shadow_sandbox.operations.evidence import GateCheck, complete
from shadow_sandbox.operations.kubernetes_storage_probe import (
    IRSA_MOUNT_PATH,
    IRSA_TOKEN_DEFAULT_MODE,
    IRSA_TOKEN_PATH,
    SERVICE_ACCOUNTS,
    STORAGE_PROBE_RBAC,
    WORKLOAD_CHECKS,
    run_inside_pod,
    run_kubernetes_storage_identity_probe,
    workload_target_coordinates,
)
from shadow_sandbox.operations.production_deployment import (
    STORAGE_EGRESS_POD_LABEL_KEY,
    STORAGE_EGRESS_POD_LABEL_VALUE,
)
from shadow_sandbox.operations.storage_probe import S3SentinelBinding


class FakeKubectlRunner:
    def __init__(
        self,
        fixture: Mapping[str, Any],
        *,
        service_account_mismatch: bool = False,
        wrong_image_id: bool = False,
        invalid_evidence: bool = False,
        cleanup_failure: bool = False,
        rbac_mismatch: bool = False,
        irsa_projection_mismatch: bool = False,
        irsa_environment_mismatch: bool = False,
        storage_egress_label_mismatch: bool = False,
    ) -> None:
        self.fixture = fixture
        self.service_account_mismatch = service_account_mismatch
        self.wrong_image_id = wrong_image_id
        self.invalid_evidence = invalid_evidence
        self.cleanup_failure = cleanup_failure
        self.rbac_mismatch = rbac_mismatch
        self.irsa_projection_mismatch = irsa_projection_mismatch
        self.irsa_environment_mismatch = irsa_environment_mismatch
        self.storage_egress_label_mismatch = storage_egress_label_mismatch
        self.commands: list[tuple[str, ...]] = []
        self.created_manifests: list[dict[str, Any]] = []
        self.jobs: dict[str, dict[str, Any]] = {}
        self.deleted_probe_ids: set[str] = set()

    @staticmethod
    def _argument(arguments: Sequence[str], name: str) -> str:
        index = arguments.index(name)
        return arguments[index + 1]

    def _identity_for_manifest(self, manifest: Mapping[str, Any]) -> str:
        return str(
            manifest["metadata"]["labels"]["shadow-sandbox.io/storage-probe-identity"]
        )

    def _pod(self, manifest: Mapping[str, Any], job_uid: str) -> Mapping[str, Any]:
        identity = self._identity_for_manifest(manifest)
        metadata = manifest["metadata"]
        template = manifest["spec"]["template"]
        pod_spec = copy.deepcopy(template["spec"])
        container = pod_spec["containers"][0]
        if self.irsa_projection_mismatch and identity == "backup":
            pod_spec["volumes"][0]["projected"]["sources"][0]["serviceAccountToken"][
                "audience"
            ] = "forbidden.invalid"
        if self.irsa_environment_mismatch and identity == "backup":
            next(
                item
                for item in container["env"]
                if item["name"] == "AWS_STS_REGIONAL_ENDPOINTS"
            )["value"] = "legacy"
        image_digest = str(container["image"]).rsplit("sha256:", 1)[1]
        if self.wrong_image_id and identity == "backup":
            image_digest = "0" * 64
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": f"{metadata['name']}-pod",
                "namespace": self.fixture["namespace"],
                "uid": f"pod-uid-{identity}-0001",
                "labels": copy.deepcopy(metadata["labels"]),
                "ownerReferences": [
                    {
                        "apiVersion": "batch/v1",
                        "kind": "Job",
                        "name": metadata["name"],
                        "uid": job_uid,
                        "controller": True,
                    }
                ],
            },
            "spec": pod_spec,
            "status": {
                "phase": "Succeeded",
                "containerStatuses": [
                    {
                        "name": "storage-identity-probe",
                        "imageID": f"containerd://sha256:{image_digest}",
                        "state": {"terminated": {"exitCode": 0}},
                    }
                ],
            },
        }
        if self.storage_egress_label_mismatch and identity == "backup":
            pod["metadata"]["labels"].pop(STORAGE_EGRESS_POD_LABEL_KEY)
        return pod

    def _evidence(self, manifest: Mapping[str, Any]) -> str:
        identity = self._identity_for_manifest(manifest)
        coordinates = workload_target_coordinates(
            identity=identity,
            bucket=self.fixture["bucket"],
            region=self.fixture["region"],
            prefixes=self.fixture["prefixes"],
            kms_key_arn=self.fixture["kms_key_arn"],
            account_id=self.fixture["account_id"],
            expected_role_arn=self.fixture["roles"][identity],
            forbidden_sentinel=self.fixture["sentinels"][identity],
            cluster_uid_digest=self.fixture["cluster_uid_digest"],
            kubernetes_api_ca_digest=self.fixture["api_ca_digest"],
            candidate_image=self.fixture["candidate_image"],
        )
        evidence = complete(
            f"kubernetes_s3_{identity}_identity",
            started_at="2026-08-14T00:00:00Z",
            completed_at="2026-08-14T00:00:01Z",
            coordinates=coordinates,
            checks=tuple(GateCheck(name, True) for name in sorted(WORKLOAD_CHECKS)),
            metrics={
                "probe_bytes": 4096,
                "kms_denial_observed": 0,
                "workload_retention_api_calls": 0,
                "sentinel_binding_digest": self.fixture["sentinels"][
                    identity
                ].binding_digest,
                "identity": identity,
                "role_arn_digest": coordinates["role_arn_digest"],
                "cluster_uid_digest": self.fixture["cluster_uid_digest"],
                "kubernetes_api_ca_digest": self.fixture["api_ca_digest"],
                "prefix_contract_digest": coordinates["prefix_contract_digest"],
                "candidate_image_reference_digest": coordinates[
                    "candidate_image_reference_digest"
                ],
                "inner_evidence_digest": ("e" if identity == "backup" else "f") * 64,
            },
        )
        payload = asdict(evidence)
        if self.invalid_evidence and identity == "backup":
            payload["digest"] = "0" * 64
        return canonical_json(payload)

    def __call__(
        self, command: Sequence[str], _timeout: int, stdin: str | None = None
    ) -> str:
        values = tuple(command)
        self.commands.append(values)
        if values[:3] != ("kubectl", "--context", self.fixture["context"]):
            raise AssertionError(f"unexpected context command: {values!r}")
        if values[3:6] == ("get", "namespace", "kube-system"):
            return canonical_json(
                {"metadata": {"uid": self.fixture["kube_system_uid"]}}
            )
        if values[3:6] == ("config", "view", "--raw"):
            return canonical_json(
                {
                    "clusters": [
                        {
                            "cluster": {
                                "server": "https://production-api.internal",
                                "certificate-authority-data": base64.b64encode(
                                    self.fixture["api_ca"]
                                ).decode("ascii"),
                            }
                        }
                    ]
                }
            )
        if values[3:5] != ("-n", self.fixture["namespace"]):
            raise AssertionError(f"namespace was not explicit: {values!r}")
        arguments = values[5:]
        if arguments == ("auth", "can-i", "--list", "-o", "json"):
            rules = set(STORAGE_PROBE_RBAC)
            if self.rbac_mismatch:
                rules.remove(("batch", "jobs", "delete"))
            return canonical_json(
                {
                    "resourceRules": [
                        {
                            "apiGroups": [group],
                            "resources": [resource],
                            "verbs": [verb],
                        }
                        for group, resource, verb in sorted(rules)
                    ]
                }
            )
        if arguments[:2] == ("get", "serviceaccount"):
            service_account = arguments[2]
            identity = next(
                name
                for name, value in SERVICE_ACCOUNTS.items()
                if value == service_account
            )
            role = self.fixture["roles"][identity]
            if self.service_account_mismatch and identity == "backup":
                role = self.fixture["roles"]["snapshot"]
            return canonical_json(
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {
                        "name": service_account,
                        "namespace": self.fixture["namespace"],
                        "annotations": {"eks.amazonaws.com/role-arn": role},
                    },
                }
            )
        if arguments[:4] == ("create", "-f", "-", "-o"):
            if stdin is None:
                raise AssertionError("Job create requires a canonical stdin manifest")
            manifest = json.loads(stdin)
            self.created_manifests.append(manifest)
            name = manifest["metadata"]["name"]
            identity = self._identity_for_manifest(manifest)
            job_uid = f"job-uid-{identity}-0001"
            self.jobs[name] = {"manifest": manifest, "uid": job_uid}
            return canonical_json(
                {
                    "apiVersion": "batch/v1",
                    "kind": "Job",
                    "metadata": {
                        "name": name,
                        "namespace": self.fixture["namespace"],
                        "uid": job_uid,
                    },
                }
            )
        if arguments and arguments[0] == "wait":
            return "job completed\n"
        if arguments[:2] == ("get", "pods"):
            selector = arguments[arguments.index("-l") + 1]
            probe_id = selector.split("=", 1)[1]
            if probe_id in self.deleted_probe_ids:
                return canonical_json({"items": []})
            for record in self.jobs.values():
                manifest = record["manifest"]
                labels = manifest["metadata"]["labels"]
                if labels["shadow-sandbox.io/storage-probe-id"] == probe_id:
                    return canonical_json(
                        {"items": [self._pod(manifest, record["uid"])]}
                    )
            return canonical_json({"items": []})
        if arguments and arguments[0] == "logs":
            pod_name = arguments[1].removeprefix("pod/")
            for record in self.jobs.values():
                manifest = record["manifest"]
                if pod_name == f"{manifest['metadata']['name']}-pod":
                    return self._evidence(manifest)
            raise AssertionError(f"unknown probe Pod: {pod_name}")
        if arguments[:2] == ("delete", "job"):
            if self.cleanup_failure:
                raise DomainError("TEST_DELETE_FAILED", "injected cleanup failure")
            name = arguments[2]
            manifest = self.jobs[name]["manifest"]
            self.deleted_probe_ids.add(
                manifest["metadata"]["labels"]["shadow-sandbox.io/storage-probe-id"]
            )
            return f"job.batch/{name} deleted\n"
        raise AssertionError(f"unexpected kubectl command: {values!r}")


class KubernetesStorageIdentityProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        account_id = "123456789012"
        region = "us-east-1"
        kms_key_arn = f"arn:aws:kms:{region}:{account_id}:key/12345678-1234-1234-1234-123456789abc"
        bucket = "industrial-shadow-production"
        prefixes = {
            "acceptance": "industrial-shadow/acceptance",
            "backup": "industrial-shadow/backup",
            "snapshot": "industrial-shadow/snapshot",
        }
        retained_until = (dt.datetime.now(dt.UTC) + dt.timedelta(days=365)).isoformat()
        sentinels = {
            "backup": S3SentinelBinding(
                schema_version=1,
                bucket=bucket,
                key=f"{prefixes['snapshot']}/immutable/forbidden-to-backup.bin",
                version_id="forbidden-to-backup-version-0001",
                sha256="b" * 64,
                content_length=128,
                kms_key_id=kms_key_arn,
                etag="forbidden-to-backup-etag",
                retention_mode="COMPLIANCE",
                retain_until=retained_until,
            ),
            "snapshot": S3SentinelBinding(
                schema_version=1,
                bucket=bucket,
                key=f"{prefixes['backup']}/immutable/forbidden-to-snapshot.bin",
                version_id="forbidden-to-snapshot-version-0001",
                sha256="c" * 64,
                content_length=128,
                kms_key_id=kms_key_arn,
                etag="forbidden-to-snapshot-etag",
                retention_mode="COMPLIANCE",
                retain_until=retained_until,
            ),
        }
        api_ca = b"production-kubernetes-api-ca"
        api_ca_digest = hashlib.sha256(api_ca).hexdigest()
        kube_system_uid = "kube-system-production-uid"
        cluster_uid_digest = canonical_digest(
            {
                "api_server_ca_sha256": api_ca_digest,
                "kube_system_namespace_uid": kube_system_uid,
            }
        )
        self.fixture: dict[str, Any] = {
            "namespace": "industrial-shadow-prod",
            "context": "production-target",
            "account_id": account_id,
            "region": region,
            "kms_key_arn": kms_key_arn,
            "bucket": bucket,
            "prefixes": prefixes,
            "sentinels": sentinels,
            "roles": {
                "backup": f"arn:aws:iam::{account_id}:role/industrial-shadow-backup",
                "snapshot": f"arn:aws:iam::{account_id}:role/industrial-shadow-snapshot",
            },
            "candidate_image": "registry.example/industrial-shadow/backend@sha256:"
            + "a" * 64,
            "api_ca": api_ca,
            "api_ca_digest": api_ca_digest,
            "kube_system_uid": kube_system_uid,
            "cluster_uid_digest": cluster_uid_digest,
        }

    def _run(self, runner: FakeKubectlRunner, **overrides: Any) -> Any:
        arguments = {
            "namespace": self.fixture["namespace"],
            "context": self.fixture["context"],
            "candidate_image": self.fixture["candidate_image"],
            "bucket": self.fixture["bucket"],
            "region": self.fixture["region"],
            "prefixes": self.fixture["prefixes"],
            "kms_key_arn": self.fixture["kms_key_arn"],
            "account_id": self.fixture["account_id"],
            "expected_role_arns": self.fixture["roles"],
            "immutable_sentinel_bindings": {
                name: binding.to_mapping()
                for name, binding in self.fixture["sentinels"].items()
            },
            "expected_cluster_uid_digest": self.fixture["cluster_uid_digest"],
            "expected_kubernetes_api_ca_digest": self.fixture["api_ca_digest"],
            "confirmation": (f"{self.fixture['namespace']}:s3-workload-identity-probe"),
            "require_object_lock": True,
            "runner": runner,
            "timeout_seconds": 60,
        }
        arguments.update(overrides)
        return run_kubernetes_storage_identity_probe(**arguments)

    def test_two_target_jobs_prove_irsa_and_are_foreground_deleted(self) -> None:
        runner = FakeKubectlRunner(self.fixture)
        evidence = self._run(runner)

        evidence.verify()
        self.assertEqual("PASSED", evidence.status)
        self.assertEqual("kubernetes_s3_workload_identity", evidence.gate)
        self.assertEqual(2, evidence.metrics["jobs"])
        self.assertTrue(
            next(
                check.passed
                for check in evidence.checks
                if check.name == "storage_probe_rbac_exact"
            )
        )
        self.assertEqual(2, len(runner.created_manifests))
        names = {manifest["metadata"]["name"] for manifest in runner.created_manifests}
        self.assertEqual(2, len(names))
        service_accounts = set()
        for manifest in runner.created_manifests:
            identity = manifest["metadata"]["labels"][
                "shadow-sandbox.io/storage-probe-identity"
            ]
            self.assertEqual(
                STORAGE_EGRESS_POD_LABEL_VALUE,
                manifest["metadata"]["labels"][STORAGE_EGRESS_POD_LABEL_KEY],
            )
            self.assertEqual(
                STORAGE_EGRESS_POD_LABEL_VALUE,
                manifest["spec"]["template"]["metadata"]["labels"][
                    STORAGE_EGRESS_POD_LABEL_KEY
                ],
            )
            self.assertEqual("batch/v1", manifest["apiVersion"])
            self.assertEqual("Job", manifest["kind"])
            self.assertEqual(0, manifest["spec"]["backoffLimit"])
            self.assertEqual(60, manifest["spec"]["activeDeadlineSeconds"])
            self.assertEqual(300, manifest["spec"]["ttlSecondsAfterFinished"])
            pod_spec = manifest["spec"]["template"]["spec"]
            service_accounts.add(pod_spec["serviceAccountName"])
            self.assertIs(False, pod_spec["automountServiceAccountToken"])
            self.assertIs(True, pod_spec["securityContext"]["runAsNonRoot"])
            self.assertEqual(
                {"type": "RuntimeDefault"},
                pod_spec["securityContext"]["seccompProfile"],
            )
            container = pod_spec["containers"][0]
            self.assertEqual(self.fixture["candidate_image"], container["image"])
            self.assertEqual(
                {
                    "AWS_ROLE_ARN": self.fixture["roles"][identity],
                    "AWS_WEB_IDENTITY_TOKEN_FILE": IRSA_TOKEN_PATH,
                    "AWS_REGION": self.fixture["region"],
                    "AWS_DEFAULT_REGION": self.fixture["region"],
                    "AWS_CONFIG_FILE": "/dev/null",
                    "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
                    "AWS_STS_REGIONAL_ENDPOINTS": "regional",
                    "AWS_EC2_METADATA_DISABLED": "true",
                    "AWS_S3_US_EAST_1_REGIONAL_ENDPOINT": "regional",
                },
                {item["name"]: item["value"] for item in container["env"]},
            )
            self.assertNotIn("envFrom", container)
            self.assertEqual(
                [
                    {
                        "name": "aws-iam-token",
                        "readOnly": True,
                        "mountPath": IRSA_MOUNT_PATH,
                    }
                ],
                container["volumeMounts"],
            )
            self.assertEqual(
                {
                    "name": "aws-iam-token",
                    "projected": {
                        "defaultMode": IRSA_TOKEN_DEFAULT_MODE,
                        "sources": [
                            {
                                "serviceAccountToken": {
                                    "audience": "sts.amazonaws.com",
                                    "expirationSeconds": 3600,
                                    "path": "token",
                                }
                            }
                        ],
                    },
                },
                pod_spec["volumes"][0],
            )
            self.assertEqual(1, len(pod_spec["volumes"]))
            self.assertNotIn("imagePullSecrets", pod_spec)
            self.assertTrue(all("secret" not in volume for volume in pod_spec["volumes"]))
            self.assertIs(True, container["securityContext"]["readOnlyRootFilesystem"])
            self.assertEqual(
                {"drop": ["ALL"]}, container["securityContext"]["capabilities"]
            )
            self.assertEqual(
                [
                    "python",
                    "-B",
                    "-m",
                    "shadow_sandbox.operations.kubernetes_storage_probe",
                ],
                container["command"],
            )
            self.assertIn("--inside-pod", container["args"])
            self.assertIn("--require-object-lock", container["args"])
            sentinel_index = container["args"].index("--forbidden-sentinel-json")
            sentinel = json.loads(container["args"][sentinel_index + 1])
            self.assertEqual(
                self.fixture["sentinels"][identity].binding_digest,
                sentinel["binding_digest"],
            )
            opposite_prefix = "snapshot" if identity == "backup" else "backup"
            self.assertTrue(
                sentinel["key"].startswith(
                    self.fixture["prefixes"][opposite_prefix] + "/"
                )
            )
        self.assertEqual(set(SERVICE_ACCOUNTS.values()), service_accounts)
        delete_commands = [values for values in runner.commands if "delete" in values]
        self.assertEqual(2, len(delete_commands))
        self.assertTrue(
            all("--cascade=foreground" in values for values in delete_commands)
        )
        self.assertTrue(all("--wait=true" in values for values in delete_commands))
        self.assertFalse(
            any(
                token in {">", ">>", "|", ";", "&&"}
                for command in runner.commands
                for token in command
            )
        )

    def test_inside_pod_binds_workload_kms_context_and_object_lock(self) -> None:
        class Credentials:
            method = "assume-role-with-web-identity"

        class AwsClient:
            def __init__(self, service: str, region: str) -> None:
                suffix = "amazonaws.com"
                self.meta = type(
                    "Meta",
                    (),
                    {
                        "endpoint_url": f"https://{service}.{region}.{suffix}",
                        "region_name": region,
                    },
                )()

        class Session:
            def __init__(self, *, region_name: str) -> None:
                self.region = region_name

            def get_credentials(self) -> Credentials:
                return Credentials()

            def client(self, service: str, *, region_name: str) -> AwsClient:
                self.assert_region(region_name)
                return AwsClient(service, region_name)

            def assert_region(self, region: str) -> None:
                if region != self.region:
                    raise AssertionError("AWS client region drifted")

        class Boto3:
            @staticmethod
            def Session(*, region_name: str) -> Session:
                return Session(region_name=region_name)

        for identity in ("backup", "snapshot"):
            inner = complete(
                f"s3_{identity}_identity",
                started_at="2026-08-14T00:00:00Z",
                completed_at="2026-08-14T00:00:01Z",
                coordinates={"identity": identity},
                checks=tuple(GateCheck(name, True) for name in sorted(WORKLOAD_CHECKS)),
            )
            with (
                patch(
                    "shadow_sandbox.operations.kubernetes_storage_probe.S3ObjectStorage"
                ) as storage_constructor,
                patch(
                    "shadow_sandbox.operations.kubernetes_storage_probe.S3WorkloadIdentityProbe"
                ) as probe_constructor,
            ):
                probe_constructor.return_value.run.return_value = inner
                evidence = run_inside_pod(
                    identity=identity,
                    bucket=self.fixture["bucket"],
                    region=self.fixture["region"],
                    prefixes=self.fixture["prefixes"],
                    kms_key_arn=self.fixture["kms_key_arn"],
                    account_id=self.fixture["account_id"],
                    expected_role_arn=self.fixture["roles"][identity],
                    forbidden_sentinel=self.fixture["sentinels"][identity],
                    cluster_uid_digest=self.fixture["cluster_uid_digest"],
                    kubernetes_api_ca_digest=self.fixture["api_ca_digest"],
                    candidate_image=self.fixture["candidate_image"],
                    require_object_lock=True,
                    boto3_module=Boto3,
                )
            self.assertEqual("PASSED", evidence.status)
            self.assertEqual(
                {
                    "application": "industrial-shadow",
                    "purpose": identity,
                },
                storage_constructor.call_args.kwargs["kms_encryption_context"],
            )
            self.assertIs(
                True,
                probe_constructor.call_args.kwargs["require_object_lock"],
            )

    def test_object_lock_cannot_be_disabled_before_job_creation(self) -> None:
        runner = FakeKubectlRunner(self.fixture)
        with self.assertRaises(DomainError) as raised:
            self._run(runner, require_object_lock=False)
        self.assertEqual(
            "KUBERNETES_STORAGE_PROBE_CONFIG_INVALID", raised.exception.code
        )
        self.assertFalse(runner.created_manifests)

    def test_wrong_signed_cluster_stops_before_first_mutation(self) -> None:
        runner = FakeKubectlRunner(self.fixture)
        with self.assertRaises(DomainError) as raised:
            self._run(runner, expected_cluster_uid_digest="0" * 64)
        self.assertEqual("KUBERNETES_CLUSTER_IDENTITY_MISMATCH", raised.exception.code)
        self.assertFalse(runner.created_manifests)

    def test_wrong_service_account_role_stops_before_first_mutation(self) -> None:
        runner = FakeKubectlRunner(self.fixture, service_account_mismatch=True)
        with self.assertRaises(DomainError) as raised:
            self._run(runner)
        self.assertEqual(
            "KUBERNETES_STORAGE_PROBE_SERVICE_ACCOUNT_MISMATCH",
            raised.exception.code,
        )
        self.assertFalse(runner.created_manifests)

    def test_storage_probe_rbac_is_exact_and_checked_before_first_mutation(
        self,
    ) -> None:
        runner = FakeKubectlRunner(self.fixture, rbac_mismatch=True)
        with self.assertRaises(DomainError) as raised:
            self._run(runner)
        self.assertEqual("KUBERNETES_STORAGE_PROBE_RBAC_INVALID", raised.exception.code)
        self.assertFalse(runner.created_manifests)

    def test_irsa_projection_admission_drift_fails_closed_and_cleans_up(self) -> None:
        runner = FakeKubectlRunner(self.fixture, irsa_projection_mismatch=True)
        with self.assertRaises(DomainError) as raised:
            self._run(runner)
        self.assertEqual("KUBERNETES_STORAGE_PROBE_POD_INVALID", raised.exception.code)
        self.assertTrue(runner.created_manifests)
        self.assertTrue(runner.deleted_probe_ids)

    def test_storage_egress_label_admission_drift_fails_closed_and_cleans_up(self) -> None:
        runner = FakeKubectlRunner(self.fixture, storage_egress_label_mismatch=True)
        with self.assertRaises(DomainError) as raised:
            self._run(runner)
        self.assertEqual("KUBERNETES_STORAGE_PROBE_POD_INVALID", raised.exception.code)
        self.assertTrue(runner.created_manifests)
        self.assertTrue(runner.deleted_probe_ids)

    def test_regional_sts_environment_drift_fails_closed_and_cleans_up(self) -> None:
        runner = FakeKubectlRunner(self.fixture, irsa_environment_mismatch=True)
        with self.assertRaises(DomainError) as raised:
            self._run(runner)
        self.assertEqual("KUBERNETES_STORAGE_PROBE_POD_INVALID", raised.exception.code)
        self.assertTrue(runner.created_manifests)
        self.assertTrue(runner.deleted_probe_ids)

    def test_runtime_image_id_drift_fails_closed_and_cleans_up(self) -> None:
        runner = FakeKubectlRunner(self.fixture, wrong_image_id=True)
        with self.assertRaises(DomainError) as raised:
            self._run(runner)
        self.assertEqual(
            "KUBERNETES_STORAGE_PROBE_IMAGE_INVALID", raised.exception.code
        )
        self.assertTrue(runner.created_manifests)
        self.assertTrue(runner.deleted_probe_ids)

    def test_tampered_pod_evidence_fails_closed_and_cleans_up(self) -> None:
        runner = FakeKubectlRunner(self.fixture, invalid_evidence=True)
        with self.assertRaises(DomainError) as raised:
            self._run(runner)
        self.assertEqual(
            "KUBERNETES_STORAGE_PROBE_EVIDENCE_INVALID", raised.exception.code
        )
        self.assertTrue(runner.created_manifests)
        self.assertTrue(runner.deleted_probe_ids)

    def test_cleanup_failure_overrides_success(self) -> None:
        runner = FakeKubectlRunner(self.fixture, cleanup_failure=True)
        with self.assertRaises(DomainError) as raised:
            self._run(runner)
        self.assertEqual(
            "KUBERNETES_STORAGE_PROBE_CLEANUP_FAILED", raised.exception.code
        )
        delete_commands = [values for values in runner.commands if "delete" in values]
        self.assertEqual(2, len(delete_commands))

    def test_confirmation_is_independent_and_exact(self) -> None:
        runner = FakeKubectlRunner(self.fixture)
        with self.assertRaises(DomainError) as raised:
            self._run(runner, confirmation=f"{self.fixture['namespace']}:deploy")
        self.assertEqual(
            "KUBERNETES_STORAGE_PROBE_CONFIRMATION_REQUIRED", raised.exception.code
        )
        self.assertFalse(runner.commands)


if __name__ == "__main__":
    unittest.main()
