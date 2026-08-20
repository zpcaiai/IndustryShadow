from __future__ import annotations

import base64
import copy
import hashlib
import json
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

import yaml  # type: ignore[import-untyped]
from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json
from shadow_sandbox.operations.network_probe import validate_live_policy_contract
from shadow_sandbox.operations.production_deployment import (
    AWS_WEB_IDENTITY_MOUNT_CONTRACT,
    AWS_WEB_IDENTITY_PROJECTION,
    AWS_WEB_IDENTITY_TOKEN_FILE,
    PUBLISH_RBAC,
    STORAGE_EGRESS_CONTRACT_ANNOTATION,
    STORAGE_EGRESS_CONTRACT_DIGEST_ANNOTATION,
    StorageEgressContract,
    cluster_identity,
    legacy_storage_https_egress_absent,
    resolve_storage_egress_contract,
    storage_probe_network_policy_exact,
    validate_exact_rbac,
)


def rules_review(rules: frozenset[tuple[str, str, str]]) -> dict[str, object]:
    return {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SelfSubjectRulesReview",
        "status": {
            "resourceRules": [
                {
                    "apiGroups": [group],
                    "resources": [resource],
                    "verbs": [verb],
                    "resourceNames": [],
                }
                for group, resource, verb in sorted(rules)
            ],
            "nonResourceRules": [],
            "incomplete": False,
            "evaluationError": "",
        },
    }


class KubernetesProductionHardeningTests(unittest.TestCase):
    def test_long_running_storage_workloads_use_only_the_sealed_irsa_projection(
        self,
    ) -> None:
        production = Path(__file__).resolve().parents[1] / "deploy" / "production"
        objects = [
            item
            for filename in (
                "config.yaml",
                "workloads.yaml",
                "backup-cronjob.yaml",
                "service-accounts.yaml",
            )
            for item in yaml.safe_load_all(
                (production / filename).read_text(encoding="utf-8")
            )
            if item
        ]

        def pod_template(value: dict[str, object]) -> dict[str, object]:
            spec = value["spec"]
            assert isinstance(spec, dict)
            if value["kind"] == "CronJob":
                return spec["jobTemplate"]["spec"]["template"]  # type: ignore[index,return-value]
            return spec["template"]  # type: ignore[return-value]

        storage_objects = {
            item["metadata"]["name"]: item  # type: ignore[index]
            for item in objects
            if item.get("kind") in {"StatefulSet", "CronJob"}
            and item.get("metadata", {}).get("name")
            in {"simulator", "shadow-postgres-backup"}
        }
        self.assertEqual({"simulator", "shadow-postgres-backup"}, set(storage_objects))
        expected_accounts = {
            "simulator": "shadow-simulator-storage",
            "shadow-postgres-backup": "shadow-backup-storage",
        }
        service_accounts = {
            item["metadata"]["name"]: item  # type: ignore[index]
            for item in objects
            if item.get("kind") == "ServiceAccount"
        }
        config_maps = {
            item["metadata"]["name"]: item["data"]  # type: ignore[index]
            for item in objects
            if item.get("kind") == "ConfigMap"
        }
        for name, value in storage_objects.items():
            template = pod_template(value)
            self.assertEqual(
                "regional-s3-sts",
                template["metadata"]["labels"][  # type: ignore[index]
                    "shadow-sandbox.io/storage-egress"
                ],
            )
            spec = template["spec"]
            assert isinstance(spec, dict)
            self.assertIs(False, spec["automountServiceAccountToken"])
            self.assertEqual(expected_accounts[name], spec["serviceAccountName"])
            projected = [
                volume
                for volume in spec["volumes"]  # type: ignore[union-attr]
                if "projected" in volume
            ]
            self.assertEqual([AWS_WEB_IDENTITY_PROJECTION], projected)
            container = spec["containers"][0]  # type: ignore[index]
            self.assertEqual(
                [AWS_WEB_IDENTITY_MOUNT_CONTRACT],
                [
                    mount
                    for mount in container["volumeMounts"]
                    if mount["name"] == AWS_WEB_IDENTITY_PROJECTION["name"]
                ],
            )
            environment = {item["name"]: item.get("value") for item in container["env"]}
            if name == "shadow-postgres-backup":
                self.assertNotIn("envFrom", container)
                self.assertEqual("production", environment["SHADOW_ENVIRONMENT"])
                self.assertEqual(
                    "replace-with-approved-aws-account-id",
                    environment["SHADOW_AWS_ACCOUNT_ID"],
                )
                self.assertEqual("s3", environment["SHADOW_OBJECT_STORAGE_BACKEND"])
                self.assertEqual(
                    "industrial-shadow/production/backups",
                    environment["SHADOW_BACKUP_OBJECT_STORAGE_PREFIX"],
                )
                self.assertEqual(
                    "shadow_backup", environment["SHADOW_DATABASE_BACKUP_ROLE"]
                )
                for variable in (
                    "SHADOW_ENVIRONMENT",
                    "SHADOW_OBJECT_STORAGE_BACKEND",
                    "SHADOW_OBJECT_STORAGE_BUCKET",
                    "SHADOW_OBJECT_STORAGE_REGION",
                    "SHADOW_OBJECT_STORAGE_KMS_KEY_ID",
                    "SHADOW_BACKUP_OBJECT_STORAGE_PREFIX",
                ):
                    self.assertEqual(
                        config_maps["shadow-runtime"][variable], environment[variable]
                    )
                self.assertEqual(
                    config_maps["shadow-database-roles"]["SHADOW_DATABASE_BACKUP_ROLE"],
                    environment["SHADOW_DATABASE_BACKUP_ROLE"],
                )
                self.assertFalse(
                    any(
                        "configMapKeyRef" in item.get("valueFrom", {})
                        for item in container["env"]
                    )
                )
            account = service_accounts[expected_accounts[name]]
            self.assertIs(False, account["automountServiceAccountToken"])
            self.assertEqual(
                account["metadata"]["annotations"][  # type: ignore[index]
                    "eks.amazonaws.com/role-arn"
                ],
                environment["AWS_ROLE_ARN"],
            )
            self.assertEqual("regional", environment["AWS_STS_REGIONAL_ENDPOINTS"])
            self.assertEqual(
                "regional", environment["AWS_S3_US_EAST_1_REGIONAL_ENDPOINT"]
            )
            self.assertEqual("true", environment["AWS_EC2_METADATA_DISABLED"])
            self.assertEqual("/dev/null", environment["AWS_CONFIG_FILE"])
            self.assertEqual("/dev/null", environment["AWS_SHARED_CREDENTIALS_FILE"])
            self.assertEqual(
                AWS_WEB_IDENTITY_TOKEN_FILE,
                environment["AWS_WEB_IDENTITY_TOKEN_FILE"],
            )

    @staticmethod
    def _storage_policy() -> dict[str, object]:
        contract = {
            "schema_version": 1,
            "partition": "aws",
            "region": "us-east-1",
            "s3_endpoint": "s3.us-east-1.amazonaws.com",
            "s3_cidrs": ["10.0.0.30/32"],
            "sts_endpoint": "sts.us-east-1.amazonaws.com",
            "sts_cidrs": ["10.0.0.31/32"],
        }
        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "storage-identity-probe-egress",
                "namespace": "industrial-shadow",
                "annotations": {
                    STORAGE_EGRESS_CONTRACT_ANNOTATION: canonical_json(contract),
                    STORAGE_EGRESS_CONTRACT_DIGEST_ANNOTATION: canonical_digest(
                        contract
                    ),
                },
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "shadow-sandbox.io/storage-egress": "regional-s3-sts"
                    }
                },
                "policyTypes": ["Egress"],
                "egress": [
                    {
                        "to": [{"ipBlock": {"cidr": "10.0.0.30/32"}}],
                        "ports": [{"protocol": "TCP", "port": 443}],
                    },
                    {
                        "to": [{"ipBlock": {"cidr": "10.0.0.31/32"}}],
                        "ports": [{"protocol": "TCP", "port": 443}],
                    },
                ],
            },
        }

    def test_storage_egress_contract_rejects_extra_or_unbound_destinations(
        self,
    ) -> None:
        policy = self._storage_policy()
        contract = StorageEgressContract.from_policy(policy)
        self.assertIsNotNone(contract)
        assert contract is not None
        self.assertTrue(storage_probe_network_policy_exact(policy))
        with self.assertRaises(DomainError) as arbitrary_cidr:
            resolve_storage_egress_contract(
                contract,
                resolver=lambda hostname: (
                    ("10.0.0.99",) if hostname.startswith("s3.") else ("10.0.0.31",)
                ),
            )
        self.assertEqual(
            "STORAGE_EGRESS_DNS_CONTRACT_MISMATCH", arbitrary_cidr.exception.code
        )

        extra_peer = copy.deepcopy(policy)
        extra_peer["spec"]["egress"][0]["to"].append(  # type: ignore[index]
            {"ipBlock": {"cidr": "10.0.0.32/32"}}
        )
        self.assertFalse(storage_probe_network_policy_exact(extra_peer))

        extra_port = copy.deepcopy(policy)
        extra_port["spec"]["egress"][1]["ports"].append(  # type: ignore[index]
            {"protocol": "TCP", "port": 444}
        )
        self.assertFalse(storage_probe_network_policy_exact(extra_port))

        unbound_endpoint = copy.deepcopy(policy)
        annotations = unbound_endpoint["metadata"]["annotations"]  # type: ignore[index]
        payload = json.loads(annotations[STORAGE_EGRESS_CONTRACT_ANNOTATION])
        payload["s3_endpoint"] = "attacker.example.com"
        annotations[STORAGE_EGRESS_CONTRACT_ANNOTATION] = canonical_json(payload)
        annotations[STORAGE_EGRESS_CONTRACT_DIGEST_ANNOTATION] = canonical_digest(
            payload
        )
        self.assertFalse(storage_probe_network_policy_exact(unbound_endpoint))

        wrong_kind = copy.deepcopy(policy)
        wrong_kind["kind"] = "ConfigMap"
        self.assertFalse(storage_probe_network_policy_exact(wrong_kind))

        wrong_selector = copy.deepcopy(policy)
        wrong_selector["spec"]["podSelector"] = {  # type: ignore[index]
            "matchLabels": {"app.kubernetes.io/name": "industrial-shadow-storage-probe"}
        }
        self.assertFalse(storage_probe_network_policy_exact(wrong_selector))

        with self.assertRaises(DomainError) as regional_sts_drift:
            resolve_storage_egress_contract(
                contract,
                resolver=lambda hostname: (
                    ("10.0.0.30",) if hostname.startswith("s3.") else ("10.0.0.98",)
                ),
            )
        self.assertEqual(
            "STORAGE_EGRESS_DNS_CONTRACT_MISMATCH",
            regional_sts_drift.exception.code,
        )

    def test_legacy_workload_policies_cannot_restore_an_alternate_storage_path(
        self,
    ) -> None:
        simulator = {
            "metadata": {"name": "simulator-plane"},
            "spec": {"egress": []},
        }
        data_jobs = {
            "metadata": {"name": "data-jobs-egress"},
            "spec": {
                "egress": [
                    {
                        "to": [{"ipBlock": {"cidr": "10.0.0.20/32"}}],
                        "ports": [{"protocol": "TCP", "port": 5432}],
                    }
                ]
            },
        }
        self.assertTrue(legacy_storage_https_egress_absent(simulator))
        self.assertTrue(legacy_storage_https_egress_absent(data_jobs))

        simulator["spec"]["egress"] = [  # type: ignore[index]
            {
                "to": [{"podSelector": {"matchLabels": {"app": "storage-proxy"}}}],
                "ports": [{"protocol": "TCP", "port": "https"}],
            }
        ]
        self.assertFalse(legacy_storage_https_egress_absent(simulator))

        data_jobs["spec"]["egress"][0]["ports"] = []  # type: ignore[index]
        self.assertFalse(legacy_storage_https_egress_absent(data_jobs))

    def test_live_storage_egress_gate_reuses_the_sealed_contract(self) -> None:
        declared = self._storage_policy()

        def runner(_command: Sequence[str], _timeout: int) -> str:
            return json.dumps({"items": [declared]})

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network-policy.yaml"
            path.write_text(json.dumps(declared), encoding="utf-8")
            checks = validate_live_policy_contract(
                "industrial-shadow",
                path,
                context="storage-network",
                runner=runner,
                resolver=lambda hostname: (
                    ("10.0.0.30",) if hostname.startswith("s3.") else ("10.0.0.31",)
                ),
            )
        self.assertTrue(all(check.passed for check in checks))

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network-policy.yaml"
            path.write_text(json.dumps(declared), encoding="utf-8")
            dns_drift_checks = validate_live_policy_contract(
                "industrial-shadow",
                path,
                context="storage-network",
                runner=runner,
                resolver=lambda hostname: (
                    ("10.0.0.98",) if hostname.startswith("s3.") else ("10.0.0.31",)
                ),
            )
        self.assertFalse(
            next(
                check
                for check in dns_drift_checks
                if check.name == "live_storage_endpoint_dns_resolution_exact"
            ).passed
        )

        drifted = copy.deepcopy(declared)
        drifted["spec"]["egress"][0]["to"] = [  # type: ignore[index]
            {"ipBlock": {"cidr": "10.0.0.99/32"}}
        ]

        def drifted_runner(_command: Sequence[str], _timeout: int) -> str:
            return json.dumps({"items": [drifted]})

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network-policy.yaml"
            path.write_text(json.dumps(declared), encoding="utf-8")
            checks = validate_live_policy_contract(
                "industrial-shadow",
                path,
                context="storage-network",
                runner=drifted_runner,
                resolver=lambda hostname: (
                    ("10.0.0.30",) if hostname.startswith("s3.") else ("10.0.0.31",)
                ),
            )
        self.assertFalse(all(check.passed for check in checks))

    def test_publish_rbac_is_an_exact_allowlist(self) -> None:
        self.assertTrue(validate_exact_rbac(rules_review(PUBLISH_RBAC), PUBLISH_RBAC))
        extra = PUBLISH_RBAC | {("", "secrets", "get")}
        self.assertFalse(validate_exact_rbac(rules_review(extra), PUBLISH_RBAC))
        wildcard = rules_review(PUBLISH_RBAC)
        wildcard["status"]["resourceRules"].append(  # type: ignore[index]
            {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}
        )
        self.assertFalse(validate_exact_rbac(wildcard, PUBLISH_RBAC))
        non_resource = rules_review(PUBLISH_RBAC)
        non_resource["status"]["nonResourceRules"] = [  # type: ignore[index]
            {"nonResourceURLs": ["*"], "verbs": ["get"]}
        ]
        self.assertFalse(validate_exact_rbac(non_resource, PUBLISH_RBAC))

    def test_cluster_identity_binds_namespace_uid_and_api_ca(self) -> None:
        ca = b"production-api-ca"
        commands: list[tuple[str, ...]] = []

        def runner(command: Sequence[str], _timeout: int) -> str:
            values = tuple(command)
            commands.append(values)
            if "namespace" in values:
                return json.dumps({"metadata": {"uid": "kube-system-production-uid"}})
            return json.dumps(
                {
                    "clusters": [
                        {
                            "cluster": {
                                "server": "https://api.production.internal",
                                "certificate-authority-data": base64.b64encode(
                                    ca
                                ).decode(),
                            }
                        }
                    ]
                }
            )

        identity, api_ca_digest = cluster_identity(runner, "production-target")
        expected_ca_digest = hashlib.sha256(ca).hexdigest()
        self.assertEqual(expected_ca_digest, api_ca_digest)
        self.assertEqual(
            canonical_digest(
                {
                    "api_server_ca_sha256": expected_ca_digest,
                    "kube_system_namespace_uid": "kube-system-production-uid",
                }
            ),
            identity,
        )
        self.assertTrue(commands)
        self.assertTrue(
            all(
                values[1:3] == ("--context", "production-target") for values in commands
            )
        )


if __name__ == "__main__":
    unittest.main()
