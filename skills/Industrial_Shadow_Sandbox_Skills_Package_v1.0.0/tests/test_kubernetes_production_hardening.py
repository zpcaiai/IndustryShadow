from __future__ import annotations

import base64
import hashlib
import json
import unittest
from collections.abc import Sequence

from shadow_sandbox.common.models import canonical_digest
from shadow_sandbox.operations.production_deployment import (
    PUBLISH_RBAC,
    cluster_identity,
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
