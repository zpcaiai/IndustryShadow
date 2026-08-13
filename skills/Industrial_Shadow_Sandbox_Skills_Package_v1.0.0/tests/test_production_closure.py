from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from shadow_sandbox.common import ActorContext, DomainError
from shadow_sandbox.common.models import canonical_digest, utc_now
from shadow_sandbox.common.object_storage import S3ObjectStorage
from shadow_sandbox.evaluation.formal_benchmark import FormalBenchmarkImporter
from shadow_sandbox.evaluation.measured_benchmark import MeasuredBenchmark
from shadow_sandbox.evaluation.metrics.gate import ReleaseGate
from shadow_sandbox.operations.certificate_probe import CertificateAuthorityProbe
from shadow_sandbox.operations.container_scan import (
    DockerScoutImageProbe,
    DockerScoutReleaseProbe,
)
from shadow_sandbox.operations.database_roles import DatabaseRoleConfigurator
from shadow_sandbox.operations.evidence import (
    GateCheck,
    GateEvidence,
    bind_to_acceptance_run,
    complete,
    failed_execution,
    write_evidence,
)
from shadow_sandbox.operations.external_assurance import ExternalAssuranceImporter
from shadow_sandbox.operations.kubernetes_drills import KubernetesDrill
from shadow_sandbox.operations.load_probe import HttpLoadProbe, LoadTarget
from shadow_sandbox.operations.network_probe import validate_policy_contract
from shadow_sandbox.operations.oidc_probe import OidcLiveProbe
from shadow_sandbox.operations.production_deployment import (
    KubernetesProductionPublisher,
    ProductionDeploymentPlan,
)
from shadow_sandbox.operations.production_preflight import ProductionPreflight
from shadow_sandbox.operations.restore_drill import PostgreSqlRestoreDrill
from shadow_sandbox.operations.storage_probe import S3KmsProbe
from shadow_sandbox.operations.trust_store import SignerTrustStore

from tools.build_production_closure import (
    SOURCE_GATES,
    approval_payload,
    build_closure,
    load_gate_evidence,
)
from tools.sign_production_approval import sign_approval

ROOT = Path(__file__).resolve().parents[1]


def trust_store_for(
    values: list[tuple[str, list[str], bytes]],
) -> SignerTrustStore:
    payload: dict[str, object] = {
        "schema_version": 1,
        "store_id": "unit-test-trust",
        "issued_at": "2026-01-01T00:00:00Z",
        "signers": [
            {
                "identity": identity,
                "purposes": purposes,
                "public_key_sha256": hashlib.sha256(public).hexdigest(),
                "valid_from": "2025-01-01T00:00:00Z",
                "valid_until": "2030-01-01T00:00:00Z",
                "status": "active",
            }
            for identity, purposes, public in values
        ],
        "digest": "",
    }
    payload["digest"] = canonical_digest(payload)
    return SignerTrustStore(payload)


class FakeBody(io.BytesIO):
    def close(self) -> None:
        super().close()


class FakeS3:
    kms_key = "arn:aws:kms:us-east-1:123456789012:key/test-key"

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.deleted: list[tuple[str, str]] = []
        self.last_put: dict[str, object] = {}

    def get_bucket_versioning(self, **_kwargs: object) -> dict[str, str]:
        return {"Status": "Enabled"}

    def get_public_access_block(self, **_kwargs: object) -> dict[str, object]:
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

    def get_bucket_encryption(self, **_kwargs: object) -> dict[str, object]:
        return {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": self.kms_key,
                        }
                    }
                ]
            }
        }

    def get_bucket_lifecycle_configuration(
        self, **_kwargs: object
    ) -> dict[str, object]:
        return {
            "Rules": [
                {
                    "ID": "retention",
                    "Status": "Enabled",
                    "Expiration": {"Days": 30},
                    "NoncurrentVersionExpiration": {"NoncurrentDays": 30},
                }
            ]
        }

    def get_object_lock_configuration(self, **_kwargs: object) -> dict[str, object]:
        return {
            "ObjectLockConfiguration": {
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 30}},
            }
        }

    def put_object(self, **kwargs: object) -> dict[str, object]:
        self.last_put = kwargs
        key = str(kwargs["Key"])
        body = kwargs["Body"]
        if not isinstance(body, bytes):
            raise TypeError("test body must be bytes")
        self.objects[key] = body
        return {"ETag": '"etag"', "VersionId": "v1", "ServerSideEncryption": "aws:kms"}

    def head_object(self, **kwargs: object) -> dict[str, object]:
        data = self.objects[str(kwargs["Key"])]
        return {
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": self.kms_key,
            "Metadata": {"sha256": hashlib.sha256(data).hexdigest()},
        }

    def get_object(self, **kwargs: object) -> dict[str, object]:
        data = self.objects[str(kwargs["Key"])]
        return {
            "ContentLength": len(data),
            "Body": FakeBody(data),
            "Metadata": {"sha256": hashlib.sha256(data).hexdigest()},
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": self.kms_key,
        }

    def list_object_versions(self, **kwargs: object) -> dict[str, object]:
        if any(key == kwargs["Prefix"] for key, _version in self.deleted):
            return {"Versions": []}
        return {"Versions": [{"Key": kwargs["Prefix"], "VersionId": "v1"}]}

    def delete_object(self, **kwargs: object) -> dict[str, object]:
        self.deleted.append((str(kwargs["Key"]), str(kwargs.get("VersionId", ""))))
        return {}


class FakeOidcValidator:
    def validate(self, authorization: str | None) -> ActorContext:
        name = str(authorization).removeprefix("Bearer ")
        roles = {
            "viewer-value": {"Viewer"},
            "engineer-value": {"Engineer"},
            "admin-value": {"Admin"},
        }[name]
        return ActorContext(name, "tenant", "workspace", frozenset(roles))


class FakeRoleStore:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def query(self, sql: str, _parameters: object = ()) -> list[dict[str, object]]:
        if "FROM pg_roles WHERE rolname IN" in sql:
            return [
                {
                    "rolname": "shadow_api",
                    "rolsuper": False,
                    "rolcreatedb": False,
                    "rolcreaterole": False,
                    "rolreplication": False,
                    "rolbypassrls": False,
                    "rolcanlogin": True,
                },
                {
                    "rolname": "shadow_action",
                    "rolsuper": False,
                    "rolcreatedb": False,
                    "rolcreaterole": False,
                    "rolreplication": False,
                    "rolbypassrls": False,
                    "rolcanlogin": True,
                },
                {
                    "rolname": "shadow_collector",
                    "rolsuper": False,
                    "rolcreatedb": False,
                    "rolcreaterole": False,
                    "rolreplication": False,
                    "rolbypassrls": False,
                    "rolcanlogin": True,
                },
                {
                    "rolname": "shadow_worker",
                    "rolsuper": False,
                    "rolcreatedb": False,
                    "rolcreaterole": False,
                    "rolreplication": False,
                    "rolbypassrls": True,
                    "rolcanlogin": True,
                },
                {
                    "rolname": "shadow_backup",
                    "rolsuper": False,
                    "rolcreatedb": False,
                    "rolcreaterole": False,
                    "rolreplication": False,
                    "rolbypassrls": True,
                    "rolcanlogin": True,
                },
            ]
        if "FROM pg_auth_members" in sql:
            return []
        if "current_user" in sql:
            return [{"role": "shadow_migration"}]
        return [{"database": "shadow_production"}]

    def execute(self, sql: str, _parameters: object = ()) -> object:
        self.statements.append(sql)
        return object()


class ProductionClosureTests(unittest.TestCase):
    def test_gate_evidence_is_digest_bound_and_rejects_secrets(self) -> None:
        evidence = complete(
            "security",
            started_at=utc_now(),
            coordinates={"target": "test"},
            checks=(GateCheck("safe", True),),
        )
        evidence.verify()
        with self.assertRaises(DomainError):
            complete(
                "security",
                started_at=utc_now(),
                coordinates={"target": "test"},
                checks=(GateCheck("unsafe", True, {"access_token": "forbidden"}),),
            )

    def test_gate_evidence_acceptance_binding_and_failed_execution_are_sealed(
        self,
    ) -> None:
        release_digest = "a" * 64
        evidence = bind_to_acceptance_run(
            complete(
                "oidc",
                started_at=utc_now(),
                coordinates={"target": "test"},
                checks=(GateCheck("safe", True),),
            ),
            run_id="unit-test-run-0001",
            release_digest=release_digest,
        )
        evidence.verify()
        self.assertEqual(2, evidence.schema_version)
        self.assertEqual("unit-test-run-0001", evidence.acceptance_run_id)
        failed = failed_execution(
            "oidc",
            started_at=utc_now(),
            error_code="TOKEN_INVALID",
            run_id="unit-test-run-0001",
            release_digest=release_digest,
        )
        failed.verify()
        self.assertEqual("FAILED", failed.status)
        self.assertNotIn("bearer", repr(failed.checks).lower())

    def test_trust_store_rejects_an_unapproved_assessor_key(self) -> None:
        trusted = (
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        untrusted = (
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        store = trust_store_for([("independent-lab", ["security_assessment"], trusted)])
        with self.assertRaises(DomainError):
            store.verify_signer(
                identity="independent-lab",
                purpose="security_assessment",
                public_key_b64=base64.b64encode(untrusted).decode(),
                signed_at=utc_now(),
            )

    def test_production_preflight_fails_closed_without_target_inputs(self) -> None:
        evidence = ProductionPreflight({}).run()
        self.assertEqual("FAILED", evidence.status)
        self.assertGreater(len(evidence.checks), 10)

    def test_s3_kms_probe_validates_controls_round_trip_and_locked_retention(
        self,
    ) -> None:
        client = FakeS3()
        storage = S3ObjectStorage(
            "industrial-shadow-test",
            prefix="acceptance",
            kms_key_id=client.kms_key,
            client=client,
        )
        evidence = S3KmsProbe(storage, require_object_lock=True).run()
        self.assertEqual("PASSED", evidence.status)
        self.assertEqual("aws:kms", client.last_put["ServerSideEncryption"])
        self.assertFalse(client.deleted)

    def test_live_oidc_probe_checks_discovery_personas_and_forged_headers(self) -> None:
        issuer = "https://identity.example.invalid/tenant"
        jwks = issuer + "/jwks"

        def http_get(
            url: str, headers: Mapping[str, str]
        ) -> tuple[int, dict[str, object]]:
            if url.endswith("openid-configuration"):
                return 200, {
                    "issuer": issuer,
                    "jwks_uri": jwks,
                    "id_token_signing_alg_values_supported": ["RS256"],
                }
            if url == jwks:
                return 200, {"keys": [{"kid": "key-1", "kty": "RSA"}]}
            value = headers.get("Authorization", "")
            if url.endswith("/api/v1/me") and value.startswith("Bearer "):
                actor = value.removeprefix("Bearer ")
                return 200, {
                    "actor_id": actor,
                    "tenant_id": "tenant",
                    "workspace_id": "workspace",
                }
            if not value or value == "Bearer invalid-production-probe-token":
                return 401, {}
            return (200 if value == "Bearer admin-value" else 403), {}

        probe = OidcLiveProbe(
            issuer,
            "industrial-shadow",
            jwks,
            "https://shadow.example.invalid",
            http_get=http_get,
            validator=FakeOidcValidator(),  # type: ignore[arg-type]
        )
        result = probe.run(
            {
                "viewer": "viewer-value",
                "engineer": "engineer-value",
                "admin": "admin-value",
            }
        )
        self.assertEqual("PASSED", result.status)

    def test_external_ca_probe_requires_valid_rotation_overlap_and_crl(self) -> None:
        now = dt.datetime.now(dt.UTC)
        ca_key = generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-root")])
        ca = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )

        def leaf(uri: str, purpose: x509.ObjectIdentifier) -> x509.Certificate:
            key = generate_private_key(public_exponent=65537, key_size=2048)
            return (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, uri)]))
                .issuer_name(ca.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=1))
                .not_valid_after(now + dt.timedelta(days=90))
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None), critical=True
                )
                .add_extension(
                    x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]),
                    critical=False,
                )
                .add_extension(x509.ExtendedKeyUsage([purpose]), critical=False)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=True,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .sign(ca_key, hashes.SHA256())
            )

        server_uri = "urn:industrial-shadow:server"
        client_uri = "urn:industrial-shadow:client"
        values = {
            "server": leaf(server_uri, ExtendedKeyUsageOID.SERVER_AUTH),
            "client": leaf(client_uri, ExtendedKeyUsageOID.CLIENT_AUTH),
            "next-server": leaf(server_uri, ExtendedKeyUsageOID.SERVER_AUTH),
            "next-client": leaf(client_uri, ExtendedKeyUsageOID.CLIENT_AUTH),
        }
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca.subject)
            .last_update(now - dt.timedelta(hours=1))
            .next_update(now + dt.timedelta(days=30))
            .sign(ca_key, hashes.SHA256())
        )
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            ca_path = root / "ca.pem"
            crl_path = root / "ca.crl"
            ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
            crl_path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
            paths: dict[str, Path] = {}
            for name, certificate in values.items():
                paths[name] = root / f"{name}.pem"
                paths[name].write_bytes(
                    certificate.public_bytes(serialization.Encoding.PEM)
                )
            result = CertificateAuthorityProbe(
                server_certificate=paths["server"],
                client_certificate=paths["client"],
                next_server_certificate=paths["next-server"],
                next_client_certificate=paths["next-client"],
                ca_bundle=ca_path,
                crl_file=crl_path,
                server_application_uri=server_uri,
                client_application_uri=client_uri,
                expected_server_fingerprint=values["server"]
                .fingerprint(hashes.SHA256())
                .hex(),
                expected_client_fingerprint=values["client"]
                .fingerprint(hashes.SHA256())
                .hex(),
                expected_next_server_fingerprint=values["next-server"]
                .fingerprint(hashes.SHA256())
                .hex(),
                expected_next_client_fingerprint=values["next-client"]
                .fingerprint(hashes.SHA256())
                .hex(),
            ).run()
            self.assertEqual(
                "PASSED",
                result.status,
                [check.name for check in result.checks if not check.passed],
            )

    def test_restore_and_cluster_drills_require_exact_disposable_targets(self) -> None:
        with self.assertRaises(DomainError):
            PostgreSqlRestoreDrill(
                "postgresql://a/source", "postgresql://a/production", allow_restore=True
            )

    def test_database_roles_are_distinct_and_least_privilege(self) -> None:
        store = FakeRoleStore()
        result = DatabaseRoleConfigurator(
            store,  # type: ignore[arg-type]
            tenant_roles=("shadow_api", "shadow_action", "shadow_collector"),
            maintenance_role="shadow_worker",
            backup_role="shadow_backup",
        ).configure()
        self.assertTrue(result["maintenance_bypass_rls"])
        self.assertTrue(
            any("ALTER DEFAULT PRIVILEGES" in sql for sql in store.statements)
        )
        self.assertFalse(any("CREATE ROLE" in sql for sql in store.statements))
        with self.assertRaises(DomainError):
            KubernetesDrill(
                "industrial-shadow",
                "control-api",
                "api",
                "https://shadow.example.invalid/api/v1/health/ready",
                "postgresql://db/shadow",
                confirmation="wrong",
            )

    def test_network_policy_contract_has_no_world_egress(self) -> None:
        checks = validate_policy_contract(
            ROOT / "deploy/production/network-policies.yaml"
        )
        self.assertTrue(all(item.passed for item in checks))

    def test_load_probe_rejects_non_https_production_target(self) -> None:
        with self.assertRaises(DomainError):
            HttpLoadProbe(
                "http://shadow.invalid",
                LoadTarget("version", "/api/v1/version"),
                bearer_value=None,
                requests_per_second=1,
                concurrency=1,
                duration_seconds=1,
                p95_limit_ms=100,
                maximum_error_rate=0,
            )

    def test_signed_external_assurance_is_artifact_bound(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            artifact = Path(directory) / "assessment.json"
            artifact.write_text('{"result":"passed"}\n', encoding="utf-8")
            private = Ed25519PrivateKey.generate()
            public = private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            candidate = "registry.example.invalid/shadow@sha256:" + "a" * 64
            trust_store = trust_store_for(
                [("independent-lab", ["security_assessment"], public)]
            )
            report: dict[str, object] = {
                "schema_version": 2,
                "gate": "security",
                "assessment_id": "security-2026-08",
                "assessor": "independent-lab",
                "started_at": utc_now(),
                "completed_at": utc_now(),
                "candidate_image": candidate,
                "build_digest": "b" * 64,
                "environment_digest": "d" * 64,
                "deployment_plan_digest": "e" * 64,
                "checks": [
                    {"name": name, "passed": True, "details": {}}
                    for name in sorted(
                        ExternalAssuranceImporter.REQUIRED_CHECKS["security"]
                    )
                ],
                "artifacts": [
                    {
                        "path": str(artifact.relative_to(ROOT)),
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    }
                ],
                "limitations": [],
                "public_key_b64": base64.b64encode(public).decode(),
                "report_digest": "",
            }
            report["report_digest"] = canonical_digest(report)
            report["signature_b64"] = base64.b64encode(
                private.sign(str(report["report_digest"]).encode("ascii"))
            ).decode()
            importer = ExternalAssuranceImporter(
                ROOT,
                trust_store=trust_store,
                candidate_image=candidate,
                build_digest="b" * 64,
                environment_digest="d" * 64,
                deployment_plan_digest="e" * 64,
            )
            evidence = importer.import_report(report)
            self.assertEqual("PASSED", evidence.status)
            self.assertEqual(
                evidence.digest,
                importer.import_report(report).digest,
            )

    def test_signed_human_accessibility_assurance_is_required_control_bound(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            artifact = Path(directory) / "human-accessibility-assessment.json"
            artifact.write_text('{"review":"completed"}\n', encoding="utf-8")
            private = Ed25519PrivateKey.generate()
            public = private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            candidate = "registry.example.invalid/shadow@sha256:" + "a" * 64
            trust_store = trust_store_for(
                [("accessibility-lab", ["accessibility_assessment"], public)]
            )
            report: dict[str, object] = {
                "schema_version": 2,
                "gate": "accessibility",
                "assessment_id": "accessibility-2026-08",
                "assessor": "accessibility-lab",
                "started_at": utc_now(),
                "completed_at": utc_now(),
                "candidate_image": candidate,
                "build_digest": "b" * 64,
                "environment_digest": "d" * 64,
                "deployment_plan_digest": "e" * 64,
                "checks": [
                    {"name": name, "passed": True, "details": {}}
                    for name in sorted(
                        ExternalAssuranceImporter.REQUIRED_CHECKS["accessibility"]
                    )
                ],
                "artifacts": [
                    {
                        "path": str(artifact.relative_to(ROOT)),
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    }
                ],
                "limitations": [],
                "public_key_b64": base64.b64encode(public).decode(),
                "report_digest": "",
            }
            report["report_digest"] = canonical_digest(report)
            report["signature_b64"] = base64.b64encode(
                private.sign(str(report["report_digest"]).encode("ascii"))
            ).decode()
            evidence = ExternalAssuranceImporter(
                ROOT,
                trust_store=trust_store,
                candidate_image=candidate,
                build_digest="b" * 64,
                environment_digest="d" * 64,
                deployment_plan_digest="e" * 64,
            ).import_report(report)
            self.assertEqual("PASSED", evidence.status)
            report["checks"] = list(report["checks"])[:-1]  # type: ignore[arg-type]
            report.pop("signature_b64")
            report["report_digest"] = ""
            report["report_digest"] = canonical_digest(report)
            report["signature_b64"] = base64.b64encode(
                private.sign(str(report["report_digest"]).encode("ascii"))
            ).decode()
            with self.assertRaises(DomainError):
                ExternalAssuranceImporter(
                    ROOT,
                    trust_store=trust_store,
                    candidate_image=candidate,
                    build_digest="b" * 64,
                    environment_digest="d" * 64,
                    deployment_plan_digest="e" * 64,
                ).import_report(report)

    def test_docker_scout_probe_retains_sarif_and_fails_on_high_findings(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            credentials = root / "docker-scout.json"
            credentials.write_text(
                json.dumps(
                    {"username": "scanner", "personal_access_token": "test-value"}
                ),
                encoding="utf-8",
            )
            credentials.chmod(0o600)

            def runner(
                command: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                if command[1:3] == ["scout", "version"]:
                    return subprocess.CompletedProcess(
                        command, 0, "version: v1.21.0\n", ""
                    )
                if command[1:3] == ["scout", "cves"]:
                    report = Path(command[command.index("--output") + 1])
                    report.write_text(
                        json.dumps(
                            {
                                "version": "2.1.0",
                                "runs": [
                                    {
                                        "tool": {"driver": {"name": "Docker Scout"}},
                                        "results": [],
                                    }
                                ],
                            }
                        ),
                        encoding="utf-8",
                    )
                return subprocess.CompletedProcess(command, 0, "", "")

            report = root / "container-scan.sarif.json"
            evidence = DockerScoutImageProbe(
                ROOT,
                candidate_image="registry.example.invalid/shadow@sha256:" + "a" * 64,
                report_path=report,
                credentials_file=credentials,
                run_command=runner,
            ).run()
            self.assertEqual("PASSED", evidence.status)
            self.assertTrue(report.is_file())

            release_evidence = DockerScoutReleaseProbe(
                ROOT,
                backend_image="registry.example.invalid/shadow@sha256:" + "a" * 64,
                web_image="registry.example.invalid/web@sha256:" + "b" * 64,
                backend_report_path=report,
                credentials_file=credentials,
                run_command=runner,
            ).run()
            self.assertEqual("PASSED", release_evidence.status)
            self.assertEqual(2, release_evidence.metrics["images_scanned"])
            self.assertTrue((root / "web-container-scan.sarif.json").is_file())
            self.assertIn("backend_report_sha256", release_evidence.metrics)
            self.assertIn("web_report_sha256", release_evidence.metrics)

            def vulnerable_runner(
                command: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                if command[1:3] == ["scout", "version"]:
                    return subprocess.CompletedProcess(
                        command, 0, "version: v1.21.0\n", ""
                    )
                if command[1:3] == ["scout", "cves"]:
                    output = Path(command[command.index("--output") + 1])
                    output.write_text(
                        json.dumps(
                            {
                                "version": "2.1.0",
                                "runs": [
                                    {
                                        "tool": {"driver": {"name": "Docker Scout"}},
                                        "results": [{"ruleId": "CVE-TEST-HIGH"}],
                                    }
                                ],
                            }
                        ),
                        encoding="utf-8",
                    )
                    return subprocess.CompletedProcess(command, 2, "", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            failed = DockerScoutImageProbe(
                ROOT,
                candidate_image="registry.example.invalid/shadow@sha256:" + "a" * 64,
                report_path=report,
                credentials_file=credentials,
                run_command=vulnerable_runner,
            ).run()
            self.assertEqual("FAILED", failed.status)
            self.assertEqual(1, failed.metrics["critical_or_high_findings"])

    def test_production_approval_signer_checks_role_key_and_digest(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            private = Ed25519PrivateKey.generate()
            public = private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            trust_store = trust_store_for(
                [
                    (
                        "release-owner@example.invalid",
                        ["closure_release_owner"],
                        public,
                    )
                ]
            )
            coordinates = {
                "candidate_image": "registry.example.invalid/shadow@sha256:" + "a" * 64,
                "build_digest": "b" * 64,
                "simulator_build_digest": "c" * 64,
                "environment_digest": "d" * 64,
                "deployment_plan_digest": "e" * 64,
            }
            approval: dict[str, object] = {
                "schema_version": 2,
                "acceptance_run_id": "unit-test-acceptance-run-1",
                "release_digest": canonical_digest(coordinates),
                "trust_store_digest": trust_store.digest,
                "gate_digests": {"preflight": "e" * 64},
                "attestation_digests": {},
                "release_coordinates": coordinates,
                "scope": ["S0 simulation"],
                "exclusions": ["real write"],
            }
            approval["approval_digest"] = canonical_digest(approval)
            key_path = Path(directory) / "release-owner.pem"
            key_path.write_bytes(
                private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            key_path.chmod(0o600)
            record = sign_approval(
                approval,
                identity="release-owner@example.invalid",
                role="release_owner",
                private_key_path=key_path,
                trust_store=trust_store,
            )
            self.assertTrue(record["approved"])
            self.assertEqual(approval["approval_digest"], record["approval_digest"])
            tampered = dict(approval)
            tampered["scope"] = ["S2 real write"]
            with self.assertRaises(DomainError):
                sign_approval(
                    tampered,
                    identity="release-owner@example.invalid",
                    role="release_owner",
                    private_key_path=key_path,
                    trust_store=trust_store,
                )

    def test_closure_bound_production_deployment_plan_and_publish(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            backend_image = "registry.test.internal/shadow@sha256:" + "a" * 64
            web_image = "registry.test.internal/shadow-web@sha256:" + "f" * 64
            prior_backend_image = "registry.test.internal/shadow@sha256:" + "c" * 64
            prior_web_image = "registry.test.internal/shadow-web@sha256:" + "d" * 64
            workload_values = [
                (
                    "deployment",
                    "control-api",
                    "api",
                    "backend",
                    "https://shadow.test.internal/api/v1/health/ready",
                ),
                ("deployment", "worker", "worker", "backend", ""),
                ("deployment", "action-executor", "action-executor", "backend", ""),
                ("statefulset", "simulator", "simulator", "backend", ""),
                ("deployment", "collector", "collector", "backend", ""),
                ("deployment", "web", "web", "web", "https://shadow.test.internal/"),
            ]

            def workload_manifest(
                kind: str, name: str, container: str, image: str
            ) -> str:
                api_kind = "StatefulSet" if kind == "statefulset" else "Deployment"
                return (
                    "apiVersion: apps/v1\n"
                    f"kind: {api_kind}\n"
                    f"metadata: {{name: {name}, namespace: industrial-shadow}}\n"
                    "spec:\n"
                    "  template:\n"
                    "    spec:\n"
                    "      securityContext:\n"
                    "        runAsNonRoot: true\n"
                    "        seccompProfile: {type: RuntimeDefault}\n"
                    "      containers:\n"
                    f"        - name: {container}\n"
                    f"          image: {image}\n"
                    "          securityContext:\n"
                    "            allowPrivilegeEscalation: false\n"
                    "            readOnlyRootFilesystem: true\n"
                    "            capabilities: {drop: [ALL]}\n"
                )

            runtime = "---\n".join(
                workload_manifest(
                    kind,
                    name,
                    container,
                    backend_image if image == "backend" else web_image,
                )
                for kind, name, container, image, _url in workload_values
            )
            rollback = (
                "apiVersion: v1\nkind: ConfigMap\n"
                "metadata: {name: release, namespace: industrial-shadow}\n"
                "data: {phase: prior}\n---\n"
                + "---\n".join(
                    workload_manifest(
                        kind,
                        name,
                        container,
                        prior_backend_image if image == "backend" else prior_web_image,
                    )
                    for kind, name, container, image, _url in workload_values
                )
            )
            contents = {
                "bootstrap": (
                    "apiVersion: v1\nkind: ConfigMap\n"
                    "metadata: {name: release, namespace: industrial-shadow}\n"
                    "data: {phase: bootstrap}\n"
                ),
                "migration": (
                    "apiVersion: batch/v1\nkind: Job\n"
                    "metadata: {name: shadow-migrate-release-20260809, namespace: industrial-shadow}\n"
                    "spec:\n"
                    "  template:\n"
                    "    spec:\n"
                    "      restartPolicy: Never\n"
                    "      securityContext:\n"
                    "        runAsNonRoot: true\n"
                    "        seccompProfile: {type: RuntimeDefault}\n"
                    "      containers:\n"
                    "        - name: migrate\n"
                    f"          image: {backend_image}\n"
                    "          securityContext:\n"
                    "            allowPrivilegeEscalation: false\n"
                    "            readOnlyRootFilesystem: true\n"
                    "            capabilities: {drop: [ALL]}\n"
                ),
                "runtime": runtime,
                "rollback": rollback,
            }
            artifact_values: dict[str, dict[str, str]] = {}
            for name in ("bootstrap", "migration", "runtime", "rollback"):
                path = root / f"{name}.yaml"
                path.write_text(contents[name], encoding="utf-8")
                artifact_values[f"{name}_manifest"] = {
                    "path": str(path.relative_to(ROOT)),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            plan_value: dict[str, object] = {
                "schema_version": 1,
                "plan_id": "release-20260809",
                "namespace": "industrial-shadow",
                "backend_image": backend_image,
                "web_image": web_image,
                **artifact_values,
                "migration_job": "shadow-migrate-release-20260809",
                "workloads": [
                    {
                        "kind": kind,
                        "name": name,
                        "container": container,
                        "image": image,
                        "readiness_url": readiness,
                    }
                    for kind, name, container, image, readiness in workload_values
                ],
                "digest": "",
            }
            plan_value["digest"] = canonical_digest(plan_value)
            plan_path = root / "deployment-plan.json"
            plan_path.write_text(json.dumps(plan_value), encoding="utf-8")
            plan = ProductionDeploymentPlan.load(
                ROOT,
                plan_path,
                candidate_image=backend_image,
                expected_digest=str(plan_value["digest"]),
            )
            unsafe_manifest = root / "unsafe-bootstrap.yaml"
            unsafe_manifest.write_text(
                "apiVersion: rbac.authorization.k8s.io/v1\n"
                "kind: ClusterRole\nmetadata: {name: forbidden-release-role}\n",
                encoding="utf-8",
            )
            unsafe_plan = json.loads(json.dumps(plan_value))
            unsafe_plan["bootstrap_manifest"] = {
                "path": str(unsafe_manifest.relative_to(ROOT)),
                "sha256": hashlib.sha256(unsafe_manifest.read_bytes()).hexdigest(),
            }
            unsafe_plan["digest"] = ""
            unsafe_plan["digest"] = canonical_digest(unsafe_plan)
            unsafe_plan_path = root / "unsafe-deployment-plan.json"
            unsafe_plan_path.write_text(json.dumps(unsafe_plan), encoding="utf-8")
            with self.assertRaises(DomainError):
                ProductionDeploymentPlan.load(
                    ROOT,
                    unsafe_plan_path,
                    candidate_image=backend_image,
                    expected_digest=str(unsafe_plan["digest"]),
                )
            expected_images = {
                name: backend_image if image == "backend" else web_image
                for _kind, name, _container, image, _readiness in workload_values
            }
            rollback_expected_images = {
                name: prior_backend_image if image == "backend" else prior_web_image
                for _kind, name, _container, image, _readiness in workload_values
            }
            containers = {
                name: container
                for _kind, name, container, _image, _url in workload_values
            }
            observed_images_for_runner = dict(expected_images)
            applied: list[str] = []

            def runner(command: Sequence[str], _timeout: int) -> str:
                values = list(command)
                if "auth" in values:
                    index = values.index("can-i")
                    forbidden = {
                        "*",
                        "secrets",
                        "roles.rbac.authorization.k8s.io",
                        "rolebindings.rbac.authorization.k8s.io",
                        "serviceaccounts/token",
                        "pods/exec",
                    }
                    return "no\n" if values[index + 2] in forbidden else "yes\n"
                if "apply" in values and "--dry-run=server" not in values:
                    manifest_path = str(values[values.index("-f") + 1])
                    applied.append(manifest_path)
                    if manifest_path == str(plan.rollback_manifest.path):
                        observed_images_for_runner.update(rollback_expected_images)
                if "get" in values and "job" in values:
                    return json.dumps(
                        {
                            "spec": {
                                "template": {
                                    "spec": {"containers": [{"image": backend_image}]}
                                }
                            }
                        }
                    )
                if "get" in values:
                    index = values.index("get")
                    name = str(values[index + 2])
                    return json.dumps(
                        {
                            "spec": {
                                "template": {
                                    "spec": {
                                        "containers": [
                                            {
                                                "name": containers[name],
                                                "image": observed_images_for_runner[
                                                    name
                                                ],
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    )
                return ""

            evidence = KubernetesProductionPublisher(
                plan,
                confirmation="industrial-shadow:release-20260809:deploy",
                runner=runner,
                readiness_probe=lambda _url: True,
            ).run()
            self.assertEqual("PASSED", evidence.status)
            self.assertEqual(6, evidence.metrics["ready_workloads"])
            self.assertNotEqual(str(plan.rollback_manifest.path), applied[-1])
            observed_images_for_runner["control-api"] = (
                "registry.test.internal/shadow@sha256:" + "b" * 64
            )
            applied.clear()
            failed = KubernetesProductionPublisher(
                plan,
                confirmation="industrial-shadow:release-20260809:deploy",
                runner=runner,
                readiness_probe=lambda _url: True,
            ).run()
            self.assertEqual("FAILED", failed.status)
            self.assertEqual(str(plan.rollback_manifest.path), applied[-1])
            observed_images_for_runner.update(expected_images)
            applied.clear()
            bootstrap_failed = False

            def partial_bootstrap_failure(command: Sequence[str], timeout: int) -> str:
                nonlocal bootstrap_failed
                values = list(command)
                if (
                    not bootstrap_failed
                    and "apply" in values
                    and "--dry-run=server" not in values
                    and str(values[values.index("-f") + 1])
                    == str(plan.bootstrap_manifest.path)
                ):
                    bootstrap_failed = True
                    applied.append(str(plan.bootstrap_manifest.path))
                    raise DomainError(
                        "TEST_PARTIAL_BOOTSTRAP", "simulated partial bootstrap failure"
                    )
                return runner(command, timeout)

            with self.assertRaises(DomainError):
                KubernetesProductionPublisher(
                    plan,
                    confirmation="industrial-shadow:release-20260809:deploy",
                    runner=partial_bootstrap_failure,
                    readiness_probe=lambda _url: True,
                ).run()
            self.assertEqual(str(plan.rollback_manifest.path), applied[-1])
            plan.runtime_manifest.path.write_text("tampered: true\n", encoding="utf-8")
            with self.assertRaises(DomainError):
                ProductionDeploymentPlan.load(
                    ROOT,
                    plan_path,
                    candidate_image=backend_image,
                    expected_digest=str(plan_value["digest"]),
                )

    def test_two_person_closure_binds_every_source_gate_digest(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            release_coordinates = {
                "candidate_image": "registry.example.invalid/shadow@sha256:" + "a" * 64,
                "build_digest": "b" * 64,
                "simulator_build_digest": "c" * 64,
                "environment_digest": "d" * 64,
                "deployment_plan_digest": "e" * 64,
            }
            release_digest = canonical_digest(release_coordinates)
            evidence: dict[str, tuple[Path, GateEvidence]] = {}
            scan_report = root / "container-scan.sarif.json"
            scan_report.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "Docker Scout"}},
                                "results": [],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            web_scan_report = root / "web-container-scan.sarif.json"
            web_scan_report.write_bytes(scan_report.read_bytes())
            for gate in SOURCE_GATES:
                if gate == "benchmark_150":
                    metrics: dict[str, int | str] = {
                        "real_write_attempts": 0,
                        "unapproved_actions": 0,
                        "gold_leaks": 0,
                    }
                elif gate == "container_scan":
                    metrics = {
                        "backend_report_sha256": hashlib.sha256(
                            scan_report.read_bytes()
                        ).hexdigest(),
                        "web_report_sha256": hashlib.sha256(
                            web_scan_report.read_bytes()
                        ).hexdigest(),
                    }
                else:
                    metrics = {}
                value = bind_to_acceptance_run(
                    complete(
                        gate,
                        started_at=utc_now(),
                        coordinates={"target": gate},
                        checks=(GateCheck("passed", True),),
                        metrics=metrics,
                    ),
                    run_id="unit-test-acceptance-run-1",
                    release_digest=release_digest,
                )
                path = write_evidence(root / f"{gate}.json", value)
                evidence[gate] = (path, value)
            self.assertEqual(set(SOURCE_GATES), set(load_gate_evidence(root)))
            signer_material = [
                (
                    "release-owner@example.invalid",
                    "release_owner",
                    Ed25519PrivateKey.generate(),
                ),
                (
                    "security-owner@example.invalid",
                    "security_owner",
                    Ed25519PrivateKey.generate(),
                ),
            ]
            trust_store = trust_store_for(
                [
                    (
                        identity,
                        [f"closure_{role}"],
                        private.public_key().public_bytes(
                            serialization.Encoding.Raw, serialization.PublicFormat.Raw
                        ),
                    )
                    for identity, role, private in signer_material
                ]
            )
            approval = approval_payload(
                evidence,
                release_coordinates=release_coordinates,
                trust_store=trust_store,
            )
            signatories = []
            for identity, role, private in signer_material:
                public = private.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
                signatories.append(
                    {
                        "identity": identity,
                        "role": role,
                        "approved": True,
                        "signed_at": utc_now(),
                        "approval_digest": approval["approval_digest"],
                        "public_key_b64": base64.b64encode(public).decode(),
                        "signature_b64": base64.b64encode(
                            private.sign(
                                str(approval["approval_digest"]).encode("ascii")
                            )
                        ).decode(),
                    }
                )
            closure = build_closure(
                evidence,
                signatories,
                release_coordinates=release_coordinates,
                trust_store=trust_store,
            )
            self.assertEqual("verified", closure["status"])
            self.assertEqual(15, len(closure["artifacts"]))
            self.assertEqual(
                {
                    "real_write_attempts": 0,
                    "unauthorized_actions": 0,
                    "gold_exposures": 0,
                },
                closure["red_lines"],
            )
            scan_report.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
            with self.assertRaises(DomainError):
                load_gate_evidence(root)

    def test_measured_174_episode_benchmark_passes_exact_bundle_gate(self) -> None:
        evidence, summary = MeasuredBenchmark(ROOT).run()
        self.assertEqual(174, summary.episode_count)
        self.assertEqual("PASSED", evidence.status)
        self.assertTrue(summary.gate["passed"])
        self.assertEqual(
            1.0, summary.evaluation["metrics"]["deterministic_replay_rate"]
        )

    def test_formal_benchmark_recomputes_signed_sanitized_target_results(self) -> None:
        candidate = "registry.example.invalid/shadow@sha256:" + "a" * 64
        importer = FormalBenchmarkImporter(
            ROOT,
            candidate_image=candidate,
            build_digest="b" * 64,
            simulator_build_digest="c" * 64,
        )
        records = []
        for episode in importer.episodes:
            normal = episode.fault_type is None
            records.append(
                {
                    "episode_id": episode.episode_id,
                    "gold_rank": None if normal else 1,
                    "detected": not normal,
                    "plan_score": 1.0,
                    "critical_step_omitted": False,
                    "unsupported_claims": 0,
                    "unapproved_actions": 0,
                    "real_write_attempts": 0,
                    "gold_leaks": 0,
                    "replay_match": True,
                    "report_success": True,
                    "trace_success": True,
                }
            )
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            results = root / "episodes.json"
            measurement = root / "measurement.log"
            profile = root / "target-profile.json"
            results.write_text(json.dumps({"episodes": records}), encoding="utf-8")
            profile.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "profile_id": "target-profile-test",
                        "collected_at": utc_now(),
                        "runner_os": "test-os",
                        "runner_architecture": "arm64",
                        "cpu_count": 8,
                        "memory_bytes": 8 * 1024**3,
                        "orchestrator_version": "kubernetes-v1-test",
                        "cluster_uid_digest": "d" * 64,
                        "candidate_image": candidate,
                        "build_digest": "b" * 64,
                        "simulator_build_digest": "c" * 64,
                    }
                ),
                encoding="utf-8",
            )
            evaluation, result_digest = importer.evaluate_results(results)
            profile_digest = hashlib.sha256(profile.read_bytes()).hexdigest()
            formal_started = utc_now()
            formal_completed = formal_started
            measurement.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "run_id": "formal-test",
                        "started_at": formal_started,
                        "completed_at": formal_completed,
                        "episode_ids": [item.episode_id for item in importer.episodes],
                        "completed_episode_ids": [
                            item.episode_id for item in importer.episodes
                        ],
                        "failed_episode_ids": [],
                        "target_profile_digest": profile_digest,
                        "result_digest": result_digest,
                    }
                ),
                encoding="utf-8",
            )
            gate = ReleaseGate().evaluate(
                "formal-target-benchmark-gate-v1",
                importer.bundle_digest,
                evaluation,
            )
            artifacts = [
                {
                    "kind": kind,
                    "path": str(path.relative_to(ROOT)),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
                for kind, path in (
                    ("episode_results", results),
                    ("measurement_log", measurement),
                    ("target_profile", profile),
                )
            ]
            private = Ed25519PrivateKey.generate()
            public = private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            environment_digest = profile_digest
            verified_importer = FormalBenchmarkImporter(
                ROOT,
                candidate_image=candidate,
                build_digest="b" * 64,
                simulator_build_digest="c" * 64,
                trust_store=trust_store_for(
                    [("independent-evaluator", ["formal_measurement"], public)]
                ),
                environment_digest=environment_digest,
            )
            report: dict[str, object] = {
                "schema_version": 1,
                "benchmark_id": "formal-test",
                "assessor": "independent-evaluator",
                "started_at": formal_started,
                "completed_at": formal_completed,
                "candidate_image": candidate,
                "build_digest": "b" * 64,
                "simulator_build_digest": "c" * 64,
                "suite_digest": importer.suite_digest,
                "bundle_digest": importer.bundle_digest,
                "result_digest": result_digest,
                "evaluation_digest": evaluation.digest,
                "certification_digest": gate.certification_digest,
                "target_profile_digest": environment_digest,
                "artifacts": artifacts,
                "limitations": [],
                "public_key_b64": base64.b64encode(public).decode(),
                "report_digest": "",
            }
            report["report_digest"] = canonical_digest(report)
            report["signature_b64"] = base64.b64encode(
                private.sign(str(report["report_digest"]).encode("ascii"))
            ).decode()
            evidence = verified_importer.import_report(report)
            self.assertEqual("PASSED", evidence.status)
            self.assertEqual(174, evidence.metrics["episodes"])
            self.assertEqual(
                evidence.digest, verified_importer.import_report(report).digest
            )


if __name__ == "__main__":
    unittest.main()
