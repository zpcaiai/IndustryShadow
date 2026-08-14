from __future__ import annotations

import asyncio
import datetime as dt
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from shadow_collector.runner import (
    _certificate_fingerprint,
    _load_collector_pki,
    _validate_collector_plane,
)
from shadow_sandbox.common.models import DomainError
from shadow_sandbox.common.opcua_readonly import ReadonlyAsyncUaAdapter
from shadow_sandbox.operations.network_probe import validate_policy_contract
from test_foundation import ROOT


class OtProductionHardeningTests(unittest.TestCase):
    @staticmethod
    def _client_material(root: Path, name: str, uri: str) -> tuple[Path, Path]:
        now = dt.datetime.now(dt.UTC)
        private_key = generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(hours=1))
            .not_valid_after(now + dt.timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        certificate_path = root / f"{name}.crt"
        private_key_path = root / f"{name}.key"
        certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        private_key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        private_key_path.chmod(0o400)
        return certificate_path, private_key_path

    def test_collector_pki_requires_uri_bound_distinct_rotation_material(self) -> None:
        client_uri = "urn:industrial-shadow:real-ot-collector"
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            current_certificate, current_key = self._client_material(
                root, "current-client", client_uri
            )
            next_certificate, next_key = self._client_material(
                root, "next-client", client_uri
            )
            server_certificate, _server_key = self._client_material(
                root, "server", "urn:industrial-shadow:server"
            )
            environment = {
                "SHADOW_OPCUA_CLIENT_CERTIFICATE_CURRENT_PATH": str(current_certificate),
                "SHADOW_OPCUA_CLIENT_PRIVATE_KEY_CURRENT_PATH": str(current_key),
                "SHADOW_OPCUA_CLIENT_CERTIFICATE_NEXT_PATH": str(next_certificate),
                "SHADOW_OPCUA_CLIENT_PRIVATE_KEY_NEXT_PATH": str(next_key),
                "SHADOW_OPCUA_SERVER_CERTIFICATE_PATH": str(server_certificate),
            }
            current_fingerprint = _certificate_fingerprint(current_certificate)
            next_fingerprint = _certificate_fingerprint(next_certificate)
            with patch.dict(os.environ, environment, clear=False):
                material = _load_collector_pki(
                    client_uri,
                    _certificate_fingerprint(server_certificate),
                    expected_current_fingerprint=current_fingerprint,
                    expected_next_fingerprint=next_fingerprint,
                )
                self.assertTrue(material.rotation_ready)
                self.assertNotEqual(
                    material.current_fingerprint, material.next_fingerprint
                )
                with self.assertRaises(DomainError) as uri_error:
                    _load_collector_pki(
                        "urn:industrial-shadow:different-client",
                        _certificate_fingerprint(server_certificate),
                        expected_current_fingerprint=current_fingerprint,
                        expected_next_fingerprint=next_fingerprint,
                    )
                self.assertEqual(
                    "COLLECTOR_PKI_IDENTITY_INVALID", uri_error.exception.code
                )

            duplicate = dict(environment)
            duplicate["SHADOW_OPCUA_CLIENT_CERTIFICATE_NEXT_PATH"] = str(
                current_certificate
            )
            duplicate["SHADOW_OPCUA_CLIENT_PRIVATE_KEY_NEXT_PATH"] = str(current_key)
            with patch.dict(os.environ, duplicate, clear=False):
                with self.assertRaises(DomainError) as rotation_error:
                    _load_collector_pki(
                        client_uri,
                        _certificate_fingerprint(server_certificate),
                        expected_current_fingerprint=current_fingerprint,
                        expected_next_fingerprint=next_fingerprint,
                    )
                self.assertEqual(
                    "COLLECTOR_PKI_ROTATION_INVALID", rotation_error.exception.code
                )

    def test_collector_plane_binding_cannot_swap_real_and_simulator_targets(self) -> None:
        _validate_collector_plane(
            "real_ot", "real_readonly", "opc.tcp://ot.example.internal:4840"
        )
        _validate_collector_plane(
            "simulator", "simulator", "opc.tcp://simulator:4840/shadow"
        )
        for identity, environment_type, endpoint in (
            ("real_ot", "real_readonly", "opc.tcp://simulator:4840/shadow"),
            ("simulator", "simulator", "opc.tcp://ot.example.internal:4840"),
            ("simulator", "real_readonly", "opc.tcp://simulator:4840/shadow"),
        ):
            with self.subTest(identity=identity, endpoint=endpoint), self.assertRaises(
                DomainError
            ):
                _validate_collector_plane(identity, environment_type, endpoint)

    def test_readonly_adapter_fails_process_health_when_session_is_lost(self) -> None:
        class Subscription:
            unsubscribed = False
            deleted = False

            async def subscribe_data_change(self, _nodes: object) -> list[int]:
                return [1]

            async def unsubscribe(self, _handles: object) -> None:
                self.unsubscribed = True

            async def delete(self) -> None:
                self.deleted = True

        class Client:
            def __init__(self) -> None:
                self.subscription = Subscription()

            def get_node(self, node_id: str) -> str:
                return node_id

            async def create_subscription(
                self, _interval: int, _handler: object
            ) -> Subscription:
                return self.subscription

            async def check_connection(self) -> None:
                raise DomainError("OPCUA_CONNECTION_LOST", "connection lost")

        client = Client()
        adapter = ReadonlyAsyncUaAdapter(client)
        with self.assertRaises(DomainError) as caught:
            asyncio.run(
                adapter.subscribe_until_cancelled(
                    ("ns=2;s=Level",),
                    sampling_interval_ms=500,
                    handler=object(),
                    cancellation=asyncio.Event(),
                )
            )
        self.assertEqual("OPCUA_CONNECTION_LOST", caught.exception.code)
        self.assertTrue(client.subscription.unsubscribed)
        self.assertTrue(client.subscription.deleted)

    def test_production_collectors_have_distinct_identity_pki_and_network_planes(self) -> None:
        production = ROOT / "deploy/production"
        workloads = [
            item
            for item in yaml.safe_load_all((production / "workloads.yaml").read_text())
            if item and item.get("kind") == "Deployment"
        ]
        by_name = {item["metadata"]["name"]: item for item in workloads}
        collector_names = {"real-ot-collector", "simulator-collector"}
        self.assertTrue(collector_names.issubset(by_name))
        service_accounts: set[str] = set()
        secret_refs: set[str] = set()
        pki_secrets: set[str] = set()
        for name in collector_names:
            pod = by_name[name]["spec"]["template"]
            target = "real-ot" if name == "real-ot-collector" else "simulator"
            self.assertEqual(target, pod["metadata"]["labels"]["collector-target"])
            self.assertFalse(pod["spec"]["automountServiceAccountToken"])
            service_accounts.add(pod["spec"]["serviceAccountName"])
            container = pod["spec"]["containers"][0]
            readiness_command = container["readinessProbe"]["exec"]["command"][2]
            liveness_command = container["livenessProbe"]["exec"]["command"][2]
            self.assertIn("collector-session-health", readiness_command)
            self.assertIn("collector-ingestion-health", readiness_command)
            self.assertIn("collector-session-health", liveness_command)
            secret_refs.update(
                source["secretRef"]["name"]
                for source in container["envFrom"]
                if "secretRef" in source
            )
            pki_secrets.update(
                volume["secret"]["secretName"]
                for volume in pod["spec"]["volumes"]
                if "secret" in volume
            )
        self.assertEqual(2, len(service_accounts))
        self.assertEqual(2, len(secret_refs))
        self.assertEqual(4, len(pki_secrets))
        declared_accounts = {
            item["metadata"]["name"]
            for item in yaml.safe_load_all(
                (production / "service-accounts.yaml").read_text()
            )
            if item and item.get("kind") == "ServiceAccount"
        }
        self.assertTrue(service_accounts.issubset(declared_accounts))

        bindings = {
            item["metadata"]["name"]: item["data"]
            for item in yaml.safe_load_all((production / "config.yaml").read_text())
            if item and item.get("kind") == "ConfigMap" and "collector-binding" in item["metadata"]["name"]
        }
        real_binding = bindings["shadow-real-ot-collector-binding"]
        simulator_binding = bindings["shadow-simulator-collector-binding"]
        self.assertEqual("real_ot", real_binding["SHADOW_COLLECTOR_IDENTITY"])
        self.assertEqual("simulator", simulator_binding["SHADOW_COLLECTOR_IDENTITY"])
        self.assertNotEqual(
            real_binding["SHADOW_CLIENT_APPLICATION_URI"],
            simulator_binding["SHADOW_CLIENT_APPLICATION_URI"],
        )
        for binding in (real_binding, simulator_binding):
            self.assertNotEqual(
                binding["SHADOW_OPCUA_CLIENT_CERTIFICATE_CURRENT_PATH"],
                binding["SHADOW_OPCUA_CLIENT_CERTIFICATE_NEXT_PATH"],
            )
            self.assertNotEqual(
                binding["SHADOW_OPCUA_CLIENT_PRIVATE_KEY_CURRENT_PATH"],
                binding["SHADOW_OPCUA_CLIENT_PRIVATE_KEY_NEXT_PATH"],
            )

        policies = [
            item
            for item in yaml.safe_load_all(
                (production / "network-policies.yaml").read_text()
            )
            if item and item.get("kind") == "NetworkPolicy"
        ]
        policy_by_name = {item["metadata"]["name"]: item for item in policies}
        real_egress = policy_by_name[
            "real-ot-collector-read-only-egress"
        ]["spec"]["egress"]
        simulator_egress = policy_by_name[
            "simulator-collector-read-only-egress"
        ]["spec"]["egress"]
        self.assertTrue(
            any("ipBlock" in peer for rule in real_egress for peer in rule.get("to", []))
        )
        self.assertFalse(
            any(
                peer.get("podSelector", {}).get("matchLabels", {}).get("app")
                == "simulator"
                for rule in real_egress
                for peer in rule.get("to", [])
            )
        )
        self.assertTrue(
            any(
                peer.get("podSelector", {}).get("matchLabels", {}).get("app")
                == "simulator"
                for rule in simulator_egress
                for peer in rule.get("to", [])
            )
        )
        self.assertFalse(
            any(
                str(peer.get("ipBlock", {}).get("cidr", "")).startswith("192.0.2.")
                for rule in simulator_egress
                for peer in rule.get("to", [])
            )
        )
        simulator_ingress = policy_by_name["simulator-plane"]["spec"]["ingress"]
        opcua_sources = [
            peer.get("podSelector", {}).get("matchLabels", {})
            for rule in simulator_ingress
            if any(port.get("port") == 4840 for port in rule.get("ports", []))
            for peer in rule.get("from", [])
        ]
        self.assertEqual(
            [{"app": "simulator-collector", "collector-target": "simulator"}],
            opcua_sources,
        )
        self.assertTrue(
            all(
                check.passed
                for check in validate_policy_contract(
                    production / "network-policies.yaml"
                )
            )
        )


if __name__ == "__main__":
    unittest.main()
