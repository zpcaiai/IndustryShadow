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
    PUBLISH_RBAC,
    KubernetesProductionPublisher,
    ProductionDeploymentPlan,
)
from shadow_sandbox.operations.production_preflight import (
    ProductionPreflight,
    validate_oidc_browser_journey_output_target,
)
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


def assurance_artifacts(
    directory: Path,
    *,
    gate: str,
    assessment_id: str,
    assessor: str,
    executed_at: str,
    candidate_image: str,
    build_digest: str,
    environment_digest: str,
    deployment_plan_digest: str,
) -> list[dict[str, str]]:
    target_digest = canonical_digest(
        {
            "candidate_image": candidate_image,
            "build_digest": build_digest,
            "environment_digest": environment_digest,
            "deployment_plan_digest": deployment_plan_digest,
        }
    )
    records = []
    for kind in sorted(ExternalAssuranceImporter.REQUIRED_CHECKS[gate]):
        artifact = directory / f"{kind}.json"
        artifact.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "assessment_id": assessment_id,
                    "gate": gate,
                    "artifact_kind": kind,
                    "assessor": assessor,
                    "executed_at": executed_at,
                    "assessment_mode": "human"
                    if gate == "accessibility"
                    else "tool_assisted",
                    "target_digest": target_digest,
                    "result": "PASSED",
                    "sample_count": 1,
                    "findings": [],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        records.append(
            {
                "kind": kind,
                "path": str(artifact.relative_to(ROOT)),
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "media_type": "application/json",
            }
        )
    return records


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

    def get_object_retention(self, **_kwargs: object) -> dict[str, object]:
        return {
            "Retention": {
                "Mode": "COMPLIANCE",
                "RetainUntilDate": dt.datetime.now(dt.UTC) + dt.timedelta(days=30),
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
            "ContentLength": len(data),
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": self.kms_key,
            "Metadata": {"sha256": hashlib.sha256(data).hexdigest()},
            "VersionId": "v1",
        }

    def get_object(self, **kwargs: object) -> dict[str, object]:
        data = self.objects[str(kwargs["Key"])]
        return {
            "ContentLength": len(data),
            "Body": FakeBody(data),
            "Metadata": {"sha256": hashlib.sha256(data).hexdigest()},
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": self.kms_key,
            "VersionId": "v1",
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
            "approver-value": {"Approver"},
            "pack-author-value": {"PackAuthor"},
            "admin-value": {"Admin"},
            "auditor-value": {"Auditor"},
            "evaluator-value": {"EvaluatorService"},
        }[name]
        return ActorContext(
            name,
            "tenant",
            "workspace",
            frozenset(roles),
            name == "evaluator-value",
        )


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
        if ") AS owned" in sql:
            return [{"count": 0}]
        if "WITH requested(role_name)" in sql:
            role = str(tuple(_parameters)[0])  # type: ignore[arg-type]
            read_write = role != "shadow_backup"
            return [
                {
                    "database_connect": True,
                    "database_temp": False,
                    "schema_usage": True,
                    "schema_create": False,
                    "table_count": 2,
                    "table_select": 2,
                    "table_insert": 2 if read_write else 0,
                    "table_update": 2 if read_write else 0,
                    "table_delete": 2 if read_write else 0,
                    "table_elevated": 0,
                    "sequence_count": 1,
                    "sequence_usage": 1 if read_write else 0,
                    "sequence_select": 1,
                    "sequence_update": 0,
                    "routine_execute": 0,
                }
            ]
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

    def test_gate_evidence_rejects_sensitive_field_aliases(self) -> None:
        for field_name in (
            "api_key",
            "api-key",
            "apiKey",
            "bearer",
            "bearer_value",
            "authorization_header",
            "authorizationHeader",
            "credential",
            "credentials",
            "dsn",
            "database_url",
            "databaseUrl",
            "connection_string",
            "connectionString",
        ):
            with self.subTest(field_name=field_name):
                with self.assertRaises(DomainError) as raised:
                    complete(
                        "security",
                        started_at=utc_now(),
                        coordinates={"target": "test"},
                        checks=(GateCheck("unsafe", True, {field_name: "redacted"}),),
                    )
                self.assertEqual("EVIDENCE_SECRET_FORBIDDEN", raised.exception.code)

    def test_gate_evidence_rejects_secret_bearing_string_values(self) -> None:
        opaque_secret = base64.b64encode(
            hashlib.sha512(b"industrial-shadow-test-secret").digest()
        ).decode("ascii")
        values = {
            "uri_userinfo": "postgresql://shadow:top-secret@db.internal/shadow",
            "bearer": "Bearer QWxhZGRpbjpvcGVuIHNlc2FtZQ1234567890",
            "jwt": (
                "eyJhbGciOiJSUzI1NiJ9."
                "eyJzdWIiOiJzaGFkb3ctYWRtaW4ifQ."
                "VGVzdFNpZ25hdHVyZVZhbHVlMTIzNDU2"
            ),
            "high_entropy": opaque_secret,
            "high_entropy_hex": hashlib.sha256(b"industrial-shadow-hex-secret")
            .hexdigest()
            .upper(),
        }
        for reason, secret_value in values.items():
            with self.subTest(reason=reason):
                with self.assertRaises(DomainError) as raised:
                    complete(
                        "security",
                        started_at=utc_now(),
                        coordinates={"target": "test"},
                        checks=(
                            GateCheck("unsafe", True, {"observation": secret_value}),
                        ),
                    )
                self.assertEqual("EVIDENCE_SECRET_FORBIDDEN", raised.exception.code)

    def test_gate_evidence_allows_digest_and_public_identifier_values(self) -> None:
        evidence = complete(
            "security",
            started_at=utc_now(),
            coordinates={"target": "test"},
            checks=(
                GateCheck(
                    "safe",
                    True,
                    {
                        "artifact_sha256": "a" * 64,
                        "candidate_image": "registry.test/shadow@sha256:" + "b" * 64,
                        "public_key": base64.b64encode(
                            hashlib.sha256(b"public-test-key").digest()
                        ).decode("ascii"),
                        "public_endpoint": "https://shadow.test.internal/health",
                    },
                ),
            ),
        )
        evidence.verify()

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
        self.assertFalse(
            next(
                check.passed
                for check in evidence.checks
                if check.name == "s3_control_plane_mutation_authorization"
            )
        )

    def test_preflight_accepts_only_pristine_run_bound_oidc_journey_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target_directory = root / "web" / "test-results"
            target_directory.mkdir(parents=True, mode=0o700)
            target_directory.chmod(0o700)
            run_id = "unit-test-run-0001"
            target = f"web/test-results/production-oidc-journey-{run_id}.json"
            self.assertTrue(
                validate_oidc_browser_journey_output_target(root, target, run_id)
            )
            target_directory.chmod(0o755)
            self.assertFalse(
                validate_oidc_browser_journey_output_target(root, target, run_id)
            )
            target_directory.chmod(0o700)
            self.assertFalse(
                validate_oidc_browser_journey_output_target(
                    root,
                    "web/test-results/production-oidc-journey.json",
                    run_id,
                )
            )
            (root / target).write_text("{}\n", encoding="utf-8")
            self.assertFalse(
                validate_oidc_browser_journey_output_target(root, target, run_id)
            )

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
                    "authorization_endpoint": issuer + "/authorize",
                    "token_endpoint": issuer + "/token",
                    "end_session_endpoint": issuer + "/logout",
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "code_challenge_methods_supported": ["S256"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "response_types_supported": ["code"],
                    "scopes_supported": ["openid", "profile"],
                    "token_endpoint_auth_methods_supported": ["none"],
                }
            if url == jwks:
                return 200, {"keys": [{"kid": "key-1", "kty": "RSA"}]}
            value = headers.get("Authorization", "")
            if url.endswith("/api/v1/me") and value.startswith("Bearer "):
                actor = value.removeprefix("Bearer ")
                roles = {
                    "viewer-value": ["Viewer"],
                    "engineer-value": ["Engineer"],
                    "approver-value": ["Approver"],
                    "pack-author-value": ["PackAuthor"],
                    "admin-value": ["Admin"],
                    "auditor-value": ["Auditor"],
                    "evaluator-value": ["EvaluatorService"],
                }[actor]
                return 200, {
                    "actor_id": actor,
                    "tenant_id": "tenant",
                    "workspace_id": "workspace",
                    "roles": roles,
                    "service": actor == "evaluator-value",
                }
            if not value or value == "Bearer invalid-production-probe-token":
                return 401, {}
            if "/api/v1/authorization-probe/" in url:
                capability = url.rsplit("/", 1)[-1].replace("-", "_")
                identity = (
                    value.removeprefix("Bearer ")
                    .removesuffix("-value")
                    .replace("-", "_")
                )
                allowed = {
                    "viewer": {"viewer"},
                    "engineer": {"viewer", "engineer"},
                    "approver": {"viewer", "approver"},
                    "pack_author": {"viewer", "pack_author"},
                    "admin": {"viewer", "admin"},
                    "auditor": {"viewer", "auditor"},
                    "evaluator": {"evaluator_service"},
                }
                return (
                    (200, {"authorized": True})
                    if capability in allowed.get(identity, set())
                    else (403, {})
                )
            return 404, {}

        browser_binding = {
            "acceptance_run_id": "unit-test-run-0001",
            "release_digest": "a" * 64,
            "candidate_image_digest": "b" * 64,
            "web_candidate_image_digest": "c" * 64,
            "build_digest": "d" * 64,
            "simulator_build_digest": "e" * 64,
            "environment_digest": "f" * 64,
            "deployment_plan_digest": "1" * 64,
        }
        probe = OidcLiveProbe(
            issuer,
            "industrial-shadow",
            jwks,
            "https://shadow.example.invalid",
            client_id="test-client",
            authorization_url=issuer + "/authorize",
            token_url=issuer + "/token",
            end_session_url=issuer + "/logout",
            service_client_ids=("test-evaluator-client",),
            browser_binding=browser_binding,
            http_get=http_get,
            validator=FakeOidcValidator(),  # type: ignore[arg-type]
        )
        journey = {
            "schema_version": 2,
            **browser_binding,
            "started_at": utc_now(),
            "completed_at": utc_now(),
            "web_origin": "https://shadow.example.invalid",
            "issuer": issuer,
            "client_id_digest": hashlib.sha256(b"test-client").hexdigest(),
            "personas": [
                "viewer",
                "engineer",
                "approver",
                "pack_author",
                "admin",
                "auditor",
            ],
            "checks": {
                "authorization_code": True,
                "pkce_s256": True,
                "token_exchange": True,
                "id_token_verified": True,
                "access_token_api": True,
                "logout": True,
                "no_cross_origin_redirect": True,
            },
        }
        result = probe.run(
            {
                "viewer": "viewer-value",
                "engineer": "engineer-value",
                "approver": "approver-value",
                "pack_author": "pack-author-value",
                "admin": "admin-value",
                "auditor": "auditor-value",
                "evaluator_service": "evaluator-value",
            },
            browser_journey=journey,
        )
        self.assertEqual("PASSED", result.status)
        result_checks = {check.name: check.passed for check in result.checks}
        self.assertTrue(result_checks["browser_journey_run_binding"])
        self.assertTrue(result_checks["browser_journey_freshness"])

        wrong_run = {**journey, "acceptance_run_id": "unit-test-run-9999"}
        wrong_run_checks = probe._browser_checks(  # noqa: SLF001
            wrong_run,
            gate_started_at=utc_now(),
        )
        self.assertFalse(
            {check.name: check.passed for check in wrong_run_checks}[
                "browser_journey_run_binding"
            ]
        )

        now = dt.datetime.now(dt.UTC)
        stale = {
            **journey,
            "started_at": (now - dt.timedelta(minutes=12)).isoformat(),
            "completed_at": (now - dt.timedelta(minutes=11)).isoformat(),
        }
        stale_checks = probe._browser_checks(  # noqa: SLF001
            stale,
            gate_started_at=now.isoformat(),
        )
        self.assertFalse(
            {check.name: check.passed for check in stale_checks}[
                "browser_journey_freshness"
            ]
        )

        future = {
            **journey,
            "started_at": now.isoformat(),
            "completed_at": (now + dt.timedelta(seconds=1)).isoformat(),
        }
        future_checks = probe._browser_checks(  # noqa: SLF001
            future,
            gate_started_at=now.isoformat(),
        )
        self.assertFalse(
            {check.name: check.passed for check in future_checks}[
                "browser_journey_freshness"
            ]
        )

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
                security_policy="Basic256Sha256",
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
            self.assertEqual(
                values["server"].fingerprint(hashes.SHA256()).hex(),
                result.metrics["server_certificate_fingerprint"],
            )
            self.assertEqual(client_uri, result.metrics["client_application_uri"])
            self.assertEqual("Basic256Sha256", result.metrics["security_policy"])

    def test_restore_and_cluster_drills_require_exact_disposable_targets(self) -> None:
        with self.assertRaises(DomainError):
            PostgreSqlRestoreDrill(
                "postgresql://a/source", "postgresql://a/production", allow_restore=True
            )

    def test_production_load_probe_rejects_write_targets(self) -> None:
        for method, body in (
            ("POST", {"action": "mutate"}),
            ("GET", {"query": "body"}),
        ):
            with self.subTest(method=method, body=body), self.assertRaises(DomainError):
                HttpLoadProbe(
                    "https://shadow.example.invalid",
                    LoadTarget("unsafe", "/api/v1/actions", method=method, body=body),
                    bearer_value=None,
                    requests_per_second=1,
                    concurrency=1,
                    duration_seconds=1,
                    p95_limit_ms=1000,
                    maximum_error_rate=0,
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
        self.assertTrue(result["existing_privileges_reset"])
        self.assertTrue(result["role_matrix_verified"])
        self.assertTrue(
            any(
                'REVOKE ALL PRIVILEGES ON DATABASE "shadow_production" FROM "shadow_api"'
                in sql
                for sql in store.statements
            )
        )
        self.assertTrue(
            any(
                "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC" in sql
                for sql in store.statements
            )
        )
        self.assertTrue(
            any(
                'GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO "shadow_backup"'
                in sql
                for sql in store.statements
            )
        )
        self.assertFalse(any("CREATE ROLE" in sql for sql in store.statements))

        class OwnedRoleStore(FakeRoleStore):
            def query(
                self, sql: str, parameters: object = ()
            ) -> list[dict[str, object]]:
                if ") AS owned" in sql:
                    return [{"count": 1}]
                return super().query(sql, parameters)

        with self.assertRaises(DomainError):
            DatabaseRoleConfigurator(
                OwnedRoleStore(),  # type: ignore[arg-type]
                tenant_roles=("shadow_api", "shadow_action", "shadow_collector"),
                maintenance_role="shadow_worker",
                backup_role="shadow_backup",
            ).configure()
        with self.assertRaises(DomainError):
            KubernetesDrill(
                "industrial-shadow",
                "control-api",
                "api",
                "https://shadow.example.invalid/api/v1/health/ready",
                "https://shadow.example.invalid/",
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
            root = Path(directory)
            private = Ed25519PrivateKey.generate()
            public = private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            candidate = "registry.example.invalid/shadow@sha256:" + "a" * 64
            trust_store = trust_store_for(
                [("independent-lab", ["security_assessment"], public)]
            )
            started_at = utc_now()
            completed_at = utc_now()
            artifacts = assurance_artifacts(
                root,
                gate="security",
                assessment_id="security-2026-08",
                assessor="independent-lab",
                executed_at=completed_at,
                candidate_image=candidate,
                build_digest="b" * 64,
                environment_digest="d" * 64,
                deployment_plan_digest="e" * 64,
            )
            report: dict[str, object] = {
                "schema_version": 3,
                "gate": "security",
                "assessment_id": "security-2026-08",
                "assessor": "independent-lab",
                "started_at": started_at,
                "completed_at": completed_at,
                "candidate_image": candidate,
                "build_digest": "b" * 64,
                "environment_digest": "d" * 64,
                "deployment_plan_digest": "e" * 64,
                "checks": [
                    {"name": name, "passed": True, "details": {"artifact_kind": name}}
                    for name in sorted(
                        ExternalAssuranceImporter.REQUIRED_CHECKS["security"]
                    )
                ],
                "artifacts": artifacts,
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
            root = Path(directory)
            private = Ed25519PrivateKey.generate()
            public = private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            candidate = "registry.example.invalid/shadow@sha256:" + "a" * 64
            trust_store = trust_store_for(
                [("accessibility-lab", ["accessibility_assessment"], public)]
            )
            started_at = utc_now()
            completed_at = utc_now()
            artifacts = assurance_artifacts(
                root,
                gate="accessibility",
                assessment_id="accessibility-2026-08",
                assessor="accessibility-lab",
                executed_at=completed_at,
                candidate_image=candidate,
                build_digest="b" * 64,
                environment_digest="d" * 64,
                deployment_plan_digest="e" * 64,
            )
            report: dict[str, object] = {
                "schema_version": 3,
                "gate": "accessibility",
                "assessment_id": "accessibility-2026-08",
                "assessor": "accessibility-lab",
                "started_at": started_at,
                "completed_at": completed_at,
                "candidate_image": candidate,
                "build_digest": "b" * 64,
                "environment_digest": "d" * 64,
                "deployment_plan_digest": "e" * 64,
                "checks": [
                    {"name": name, "passed": True, "details": {"artifact_kind": name}}
                    for name in sorted(
                        ExternalAssuranceImporter.REQUIRED_CHECKS["accessibility"]
                    )
                ],
                "artifacts": artifacts,
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
            registry_credentials = root / "registry.json"
            registry_credentials.write_text(
                json.dumps(
                    {
                        "registry": "registry.example.invalid",
                        "username": "puller",
                        "access_token": "registry-test-value",
                    }
                ),
                encoding="utf-8",
            )
            registry_credentials.chmod(0o600)

            def runner(
                command: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                if command[1:3] == ["scout", "version"]:
                    return subprocess.CompletedProcess(
                        command, 0, "version: v1.21.0\n", ""
                    )
                if command[1:3] == ["image", "inspect"]:
                    return subprocess.CompletedProcess(
                        command, 0, json.dumps([command[-1]]) + "\n", ""
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
                registry_credentials_file=registry_credentials,
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
                registry_credentials_file=registry_credentials,
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
                if command[1:3] == ["image", "inspect"]:
                    return subprocess.CompletedProcess(
                        command, 0, json.dumps([command[-1]]) + "\n", ""
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
                registry_credentials_file=registry_credentials,
                run_command=vulnerable_runner,
            ).run()
            self.assertEqual("FAILED", failed.status)
            self.assertEqual(1, failed.metrics["critical_or_high_findings"])

    def test_docker_scout_rejects_conflicting_docker_hub_identities(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            credentials = root / "docker-scout.json"
            credentials.write_text(
                json.dumps(
                    {"username": "scanner", "personal_access_token": "scout-token"}
                ),
                encoding="utf-8",
            )
            credentials.chmod(0o600)
            registry_credentials = root / "registry.json"
            registry_credentials.write_text(
                json.dumps(
                    {
                        "registry": "docker.io",
                        "username": "puller",
                        "access_token": "registry-token",
                    }
                ),
                encoding="utf-8",
            )
            registry_credentials.chmod(0o600)

            calls: list[list[str]] = []

            def runner(
                command: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                calls.append(command)
                return subprocess.CompletedProcess(command, 0, "", "")

            with self.assertRaises(DomainError):
                DockerScoutImageProbe(
                    ROOT,
                    candidate_image="docker.io/example/shadow@sha256:" + "a" * 64,
                    report_path=root / "container-scan.sarif.json",
                    credentials_file=credentials,
                    registry_credentials_file=registry_credentials,
                    run_command=runner,
                ).run()
            self.assertEqual(1, len(calls))

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
                (
                    "deployment",
                    "real-ot-collector",
                    "real-ot-collector",
                    "backend",
                    "",
                ),
                (
                    "deployment",
                    "simulator-collector",
                    "simulator-collector",
                    "backend",
                    "",
                ),
                ("deployment", "web", "web", "web", "https://shadow.test.internal/"),
            ]

            def workload_manifest(
                kind: str, name: str, container: str, image: str
            ) -> str:
                api_kind = "StatefulSet" if kind == "statefulset" else "Deployment"
                accounts = {
                    "control-api": "shadow-control-api",
                    "worker": "shadow-worker",
                    "action-executor": "shadow-action-executor",
                    "simulator": "shadow-simulator-storage",
                    "real-ot-collector": "shadow-real-ot-collector",
                    "simulator-collector": "shadow-simulator-collector",
                    "web": "shadow-web",
                }
                args = {
                    "control-api": [
                        "uvicorn",
                        "shadow_sandbox.main:create_app",
                        "--factory",
                        "--host",
                        "0.0.0.0",
                        "--port",
                        "8000",
                        "--proxy-headers",
                    ],
                    "worker": ["python", "-m", "shadow_sandbox.worker"],
                    "action-executor": [
                        "uvicorn",
                        "shadow_sandbox.action_api:create_app",
                        "--factory",
                        "--host",
                        "0.0.0.0",
                        "--port",
                        "8020",
                    ],
                    "simulator": [
                        "uvicorn",
                        "shadow_simulator.api:create_app",
                        "--factory",
                        "--host",
                        "0.0.0.0",
                        "--port",
                        "8010",
                    ],
                    "real-ot-collector": ["python", "-m", "shadow_collector.runner"],
                    "simulator-collector": ["python", "-m", "shadow_collector.runner"],
                    "web": [],
                }
                environment_references = {
                    "control-api": [
                        ("configMapRef", "shadow-runtime"),
                        ("configMapRef", "shadow-release-coordinates"),
                    ],
                    "worker": [
                        ("configMapRef", "shadow-runtime"),
                        ("configMapRef", "shadow-release-coordinates"),
                    ],
                    "action-executor": [
                        ("configMapRef", "shadow-runtime"),
                        ("configMapRef", "shadow-release-coordinates"),
                    ],
                    "simulator": [
                        ("configMapRef", "shadow-runtime"),
                        ("configMapRef", "shadow-release-coordinates"),
                    ],
                    "real-ot-collector": [
                        ("configMapRef", "shadow-real-ot-collector-binding"),
                    ],
                    "simulator-collector": [
                        ("configMapRef", "shadow-simulator-collector-binding"),
                    ],
                    "web": [],
                }
                secret_environment = {
                    "control-api": [
                        (
                            "SHADOW_DATABASE_URL",
                            "shadow-api-secrets",
                            "SHADOW_DATABASE_URL",
                        ),
                        (
                            "SHADOW_INTERNAL_SERVICE_TOKEN",
                            "shadow-api-secrets",
                            "SHADOW_INTERNAL_SERVICE_TOKEN",
                        ),
                    ],
                    "worker": [
                        (
                            "SHADOW_DATABASE_URL",
                            "shadow-worker-secrets",
                            "SHADOW_DATABASE_URL",
                        )
                    ],
                    "action-executor": [
                        (
                            "SHADOW_DATABASE_URL",
                            "shadow-action-secrets",
                            "SHADOW_DATABASE_URL",
                        ),
                        (
                            "SHADOW_INTERNAL_SERVICE_TOKEN",
                            "shadow-action-secrets",
                            "SHADOW_INTERNAL_SERVICE_TOKEN",
                        ),
                    ],
                    "simulator": [
                        (
                            "SHADOW_INTERNAL_SERVICE_TOKEN",
                            "shadow-simulator-secrets",
                            "SHADOW_INTERNAL_SERVICE_TOKEN",
                        )
                    ],
                    "real-ot-collector": [
                        (
                            "SHADOW_DATABASE_URL",
                            "shadow-real-ot-collector-secrets",
                            "SHADOW_DATABASE_URL",
                        )
                    ],
                    "simulator-collector": [
                        (
                            "SHADOW_DATABASE_URL",
                            "shadow-simulator-collector-secrets",
                            "SHADOW_DATABASE_URL",
                        )
                    ],
                    "web": [],
                }
                secret_names = {
                    "simulator": ["shadow-simulator-pki"],
                    "real-ot-collector": [
                        "shadow-real-ot-collector-pki-current",
                        "shadow-real-ot-collector-pki-next",
                    ],
                    "simulator-collector": [
                        "shadow-simulator-collector-pki-current",
                        "shadow-simulator-collector-pki-next",
                    ],
                }
                env_from = "".join(
                    f"            - {reference}: {{name: {target}}}\n"
                    for reference, target in environment_references[name]
                )
                env_entries = "".join(
                    "            - name: "
                    + variable
                    + "\n"
                    + "              valueFrom:\n"
                    + "                secretKeyRef:\n"
                    + f"                  name: {secret}\n"
                    + f"                  key: {key}\n"
                    for variable, secret, key in secret_environment[name]
                )
                if name == "simulator":
                    env_entries += (
                        "            - {name: SHADOW_DATABASE_PATH, value: /var/lib/shadow/simulator.db}\n"
                        "            - {name: SHADOW_OPCUA_CERTIFICATE_PATH, value: /var/run/shadow-pki/server.crt}\n"
                        "            - {name: SHADOW_OPCUA_PRIVATE_KEY_PATH, value: /var/run/shadow-pki/server.key}\n"
                    )
                secret_volumes = "".join(
                    f"        - name: secret-{index}\n          secret: {{secretName: {secret}}}\n"
                    for index, secret in enumerate(secret_names.get(name, []))
                )
                labels = {
                    "control-api": "{app: control-api, plane: control}",
                    "worker": "{app: worker, plane: data}",
                    "action-executor": "{app: action-executor, plane: action}",
                    "simulator": "{app: simulator, plane: simulator}",
                    "real-ot-collector": "{app: real-ot-collector, plane: collector, collector-target: real-ot}",
                    "simulator-collector": "{app: simulator-collector, plane: collector, collector-target: simulator}",
                    "web": "{app: web, plane: ingress}",
                }
                return (
                    "apiVersion: apps/v1\n"
                    f"kind: {api_kind}\n"
                    f"metadata: {{name: {name}, namespace: industrial-shadow}}\n"
                    "spec:\n"
                    f"  selector: {{matchLabels: {{app: {name}}}}}\n"
                    "  template:\n"
                    f"    metadata: {{labels: {labels[name]}}}\n"
                    "    spec:\n"
                    f"      serviceAccountName: {accounts[name]}\n"
                    f"      automountServiceAccountToken: {'true' if name == 'simulator' else 'false'}\n"
                    "      securityContext:\n"
                    "        runAsNonRoot: true\n"
                    "        seccompProfile: {type: RuntimeDefault}\n"
                    "      containers:\n"
                    f"        - name: {container}\n"
                    f"          image: {image}\n"
                    + (
                        f"          args: {json.dumps(args[name])}\n"
                        if args[name]
                        else ""
                    )
                    + ("          envFrom:\n" + env_from if env_from else "")
                    + ("          env:\n" + env_entries if env_entries else "")
                    + "          securityContext:\n"
                    "            allowPrivilegeEscalation: false\n"
                    "            readOnlyRootFilesystem: true\n"
                    "            capabilities: {drop: [ALL]}\n"
                    + ("      volumes:\n" + secret_volumes if secret_volumes else "")
                )

            services = (
                "apiVersion: v1\nkind: Service\nmetadata: {name: control-api, namespace: industrial-shadow}\nspec: {selector: {app: control-api}, ports: [{name: http, port: 8000, targetPort: http}]}\n---\n"
                "apiVersion: v1\nkind: Service\nmetadata: {name: action-executor, namespace: industrial-shadow}\nspec: {selector: {app: action-executor}, ports: [{name: http, port: 8020, targetPort: http}]}\n---\n"
                "apiVersion: v1\nkind: Service\nmetadata: {name: simulator, namespace: industrial-shadow}\nspec: {selector: {app: simulator}, ports: [{name: http, port: 8010, targetPort: http}, {name: opcua, port: 4840, targetPort: opcua}]}\n---\n"
                "apiVersion: v1\nkind: Service\nmetadata: {name: web, namespace: industrial-shadow}\nspec: {selector: {app: web}, ports: [{name: http, port: 80, targetPort: http}]}\n"
            )
            storage_roles = {
                "shadow-simulator-storage": "arn:aws:iam::123456789012:role/shadow-snapshot",
                "shadow-backup-storage": "arn:aws:iam::123456789012:role/shadow-backup",
            }

            def service_account_manifest(name: str) -> str:
                if name in storage_roles:
                    metadata = (
                        "metadata:\n"
                        f"  name: {name}\n"
                        "  namespace: industrial-shadow\n"
                        "  annotations:\n"
                        f"    eks.amazonaws.com/role-arn: {storage_roles[name]}\n"
                    )
                else:
                    metadata = (
                        f"metadata: {{name: {name}, namespace: industrial-shadow}}\n"
                    )
                token = name in {
                    "shadow-simulator-storage",
                    "shadow-backup-storage",
                }
                return (
                    "apiVersion: v1\nkind: ServiceAccount\n"
                    f"{metadata}"
                    f"automountServiceAccountToken: {'true' if token else 'false'}\n"
                )

            service_accounts = "---\n".join(
                service_account_manifest(name)
                for name in (
                    "shadow-control-api",
                    "shadow-worker",
                    "shadow-action-executor",
                    "shadow-web",
                    "shadow-migration",
                    "shadow-real-ot-collector",
                    "shadow-simulator-collector",
                    "shadow-simulator-storage",
                    "shadow-backup-storage",
                )
            )
            policy_names = (
                "default-deny",
                "dns-egress",
                "web-ingress-and-api",
                "control-api-ingress",
                "action-plane",
                "simulator-plane",
                "real-ot-collector-read-only-egress",
                "simulator-collector-read-only-egress",
                "data-jobs-egress",
                "storage-identity-probe-egress",
            )

            def policy_manifest(name: str) -> str:
                if name == "storage-identity-probe-egress":
                    return (
                        "apiVersion: networking.k8s.io/v1\n"
                        "kind: NetworkPolicy\n"
                        "metadata: {name: storage-identity-probe-egress, "
                        "namespace: industrial-shadow}\n"
                        "spec:\n"
                        "  podSelector: {matchLabels: {app.kubernetes.io/name: "
                        "industrial-shadow-storage-probe}}\n"
                        "  policyTypes: [Egress]\n"
                        "  egress:\n"
                        "    - to:\n"
                        "        - {ipBlock: {cidr: 10.0.0.30/32}}\n"
                        "        - {ipBlock: {cidr: 10.0.0.31/32}}\n"
                        "      ports: [{protocol: TCP, port: 443}]\n"
                    )
                return (
                    "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n"
                    f"metadata: {{name: {name}, namespace: industrial-shadow}}\n"
                    "spec: {podSelector: {}, policyTypes: [Ingress, Egress]}\n"
                )

            policies = "---\n".join(policy_manifest(name) for name in policy_names)

            runtime_workloads = "---\n".join(
                workload_manifest(
                    kind,
                    name,
                    container,
                    backend_image if image == "backend" else web_image,
                )
                for kind, name, container, image, _url in workload_values
            )
            runtime = runtime_workloads + "---\n" + services
            bootstrap = (
                "apiVersion: v1\nkind: ConfigMap\n"
                "metadata: {name: release, namespace: industrial-shadow}\n"
                "data: {phase: bootstrap}\n---\n"
                "apiVersion: v1\nkind: ConfigMap\n"
                "metadata: {name: shadow-runtime, namespace: industrial-shadow}\n"
                "data: {SHADOW_AUTO_MIGRATE: 'false', SHADOW_SNAPSHOT_OBJECT_STORAGE_PREFIX: industrial-shadow/production/snapshots, SHADOW_BACKUP_OBJECT_STORAGE_PREFIX: industrial-shadow/production/backups}\n---\n"
                "apiVersion: v1\nkind: ConfigMap\n"
                "metadata: {name: shadow-release-coordinates, namespace: industrial-shadow}\n"
                f"data: {{SHADOW_BUILD_DIGEST: {'a' * 64}, SHADOW_SIMULATOR_BUILD_DIGEST: {'b' * 64}, SHADOW_SIMULATOR_DIGEST: {'c' * 64}}}\n---\n"
                "apiVersion: v1\nkind: ConfigMap\n"
                "metadata: {name: shadow-real-ot-collector-binding, namespace: industrial-shadow}\n"
                "data:\n"
                "  SHADOW_AUTO_MIGRATE: 'false'\n"
                "  SHADOW_ENDPOINT_URI: opc.tcp://ot.test.internal:4840\n"
                "  SHADOW_APPLICATION_URI: urn:industrial-shadow:test-server\n"
                "  SHADOW_CLIENT_APPLICATION_URI: urn:industrial-shadow:test-client\n"
                "  SHADOW_NAMESPACE_URI: urn:industrial-shadow:test-namespace\n"
                f"  SHADOW_CERTIFICATE_FINGERPRINT: {'f' * 64}\n"
                f"  SHADOW_CLIENT_CERTIFICATE_FINGERPRINT: {'1' * 64}\n"
                f"  SHADOW_NEXT_CLIENT_CERTIFICATE_FINGERPRINT: {'3' * 64}\n"
                '  SHADOW_NODE_ALLOWLIST: \'[{"node_id":"ns=2;s=temperature","signal_key":"temperature","sample_period_ms":500}]\'\n'
                "  SHADOW_MAXIMUM_NODES: '500'\n"
                "  SHADOW_OPCUA_SECURITY_PROFILE: Basic256Sha256,SignAndEncrypt\n---\n"
                "apiVersion: v1\nkind: ConfigMap\n"
                "metadata: {name: shadow-simulator-collector-binding, namespace: industrial-shadow}\n"
                "data: {SHADOW_AUTO_MIGRATE: 'false'}\n---\n"
                "apiVersion: v1\nkind: ConfigMap\n"
                "metadata: {name: shadow-database-roles, namespace: industrial-shadow}\n"
                "data: {SHADOW_DATABASE_TENANT_ROLES: 'shadow_api,shadow_action,shadow_collector', SHADOW_DATABASE_MAINTENANCE_ROLE: shadow_worker, SHADOW_DATABASE_BACKUP_ROLE: shadow_backup}\n---\n"
                + service_accounts
                + "---\n"
                + policies
            )
            rollback = (
                bootstrap
                + "---\n"
                + "---\n".join(
                    workload_manifest(
                        kind,
                        name,
                        container,
                        prior_backend_image if image == "backend" else prior_web_image,
                    )
                    for kind, name, container, image, _url in workload_values
                )
                + "---\n"
                + services
            )
            contents = {
                "bootstrap": bootstrap,
                "migration": (
                    "apiVersion: batch/v1\nkind: Job\n"
                    "metadata: {name: shadow-migrate-release-20260809, namespace: industrial-shadow}\n"
                    "spec:\n"
                    "  template:\n"
                    "    spec:\n"
                    "      restartPolicy: Never\n"
                    "      serviceAccountName: shadow-migration\n"
                    "      automountServiceAccountToken: false\n"
                    "      securityContext:\n"
                    "        runAsNonRoot: true\n"
                    "        seccompProfile: {type: RuntimeDefault}\n"
                    "      containers:\n"
                    "        - name: migrate\n"
                    f"          image: {backend_image}\n"
                    "          args: [python, -m, shadow_sandbox.operations.database_roles]\n"
                    "          envFrom:\n"
                    "            - configMapRef: {name: shadow-database-roles}\n"
                    "          env:\n"
                    "            - name: SHADOW_DATABASE_URL\n"
                    "              valueFrom:\n"
                    "                secretKeyRef:\n"
                    "                  name: shadow-migration-secrets\n"
                    "                  key: SHADOW_DATABASE_URL\n"
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
            self.assertEqual(
                canonical_digest(["ns=2;s=temperature"]),
                plan.real_ot_node_allowlist_digest,
            )
            self.assertEqual(
                "industrial-shadow/production/snapshots",
                plan.snapshot_object_storage_prefix,
            )
            self.assertEqual(
                "industrial-shadow/production/backups",
                plan.backup_object_storage_prefix,
            )

            def assert_invalid_manifest_bindings(label: str, **manifests: str) -> None:
                invalid_plan = json.loads(json.dumps(plan_value))
                for artifact_name, manifest in manifests.items():
                    invalid_manifest = root / f"{label}-{artifact_name}.yaml"
                    invalid_manifest.write_text(manifest, encoding="utf-8")
                    invalid_plan[f"{artifact_name}_manifest"] = {
                        "path": str(invalid_manifest.relative_to(ROOT)),
                        "sha256": hashlib.sha256(
                            invalid_manifest.read_bytes()
                        ).hexdigest(),
                    }
                invalid_plan["digest"] = ""
                invalid_plan["digest"] = canonical_digest(invalid_plan)
                invalid_plan_path = root / f"{label}-deployment-plan.json"
                invalid_plan_path.write_text(json.dumps(invalid_plan), encoding="utf-8")
                with self.assertRaises(DomainError):
                    ProductionDeploymentPlan.load(
                        ROOT,
                        invalid_plan_path,
                        candidate_image=backend_image,
                        expected_digest=str(invalid_plan["digest"]),
                    )

            assert_invalid_manifest_bindings(
                "wrong-secret-reference",
                runtime=runtime.replace(
                    "name: shadow-api-secrets",
                    "name: shadow-worker-secrets",
                    1,
                ),
            )
            assert_invalid_manifest_bindings(
                "extra-secret-reference",
                runtime=runtime.replace(
                    "          securityContext:\n",
                    "            - name: SHADOW_UNSEALED_OVERRIDE\n"
                    "              valueFrom:\n"
                    "                secretKeyRef:\n"
                    "                  name: shadow-api-secrets\n"
                    "                  key: SHADOW_UNSEALED_OVERRIDE\n"
                    "          securityContext:\n",
                    1,
                ),
            )
            assert_invalid_manifest_bindings(
                "rollback-storage-prefix-drift",
                rollback=rollback.replace(
                    "industrial-shadow/production/snapshots",
                    "industrial-shadow/production/snapshots-drift",
                    1,
                ),
            )
            nested_bootstrap = bootstrap.replace(
                "industrial-shadow/production/backups",
                "industrial-shadow/production/snapshots/archive",
                1,
            )
            nested_rollback = rollback.replace(
                "industrial-shadow/production/backups",
                "industrial-shadow/production/snapshots/archive",
                1,
            )
            assert_invalid_manifest_bindings(
                "nested-storage-prefixes",
                bootstrap=nested_bootstrap,
                rollback=nested_rollback,
            )
            duplicate_role_bootstrap = bootstrap.replace(
                "role/shadow-backup", "role/shadow-snapshot", 1
            )
            duplicate_role_rollback = rollback.replace(
                "role/shadow-backup", "role/shadow-snapshot", 1
            )
            assert_invalid_manifest_bindings(
                "shared-storage-role",
                bootstrap=duplicate_role_bootstrap,
                rollback=duplicate_role_rollback,
            )
            assert_invalid_manifest_bindings(
                "rollback-ot-endpoint-drift",
                rollback=rollback.replace(
                    "opc.tcp://ot.test.internal:4840",
                    "opc.tcp://ot-drift.test.internal:4840",
                    1,
                ),
            )
            assert_invalid_manifest_bindings(
                "rollback-ot-allowlist-drift",
                rollback=rollback.replace("ns=2;s=temperature", "ns=2;s=pressure", 1),
            )
            assert_invalid_manifest_bindings(
                "rollback-ot-fingerprint-drift",
                rollback=rollback.replace("1" * 64, "4" * 64, 1),
            )
            assert_invalid_manifest_bindings(
                "invalid-four-segment-ot-profile",
                bootstrap=bootstrap.replace(
                    "Basic256Sha256,SignAndEncrypt",
                    "Basic256Sha256,SignAndEncrypt,/pki/client.crt,/pki/client.key",
                    1,
                ),
            )
            overlapping_bootstrap = bootstrap.replace(
                "data: {SHADOW_BUILD_DIGEST:",
                "data: {SHADOW_AUTO_MIGRATE: 'false', SHADOW_BUILD_DIGEST:",
                1,
            )
            overlapping_rollback = rollback.replace(
                "data: {SHADOW_BUILD_DIGEST:",
                "data: {SHADOW_AUTO_MIGRATE: 'false', SHADOW_BUILD_DIGEST:",
                1,
            )
            assert_invalid_manifest_bindings(
                "overlapping-config-map-keys",
                bootstrap=overlapping_bootstrap,
                rollback=overlapping_rollback,
            )
            assert_invalid_manifest_bindings(
                "rollback-config-map-key-set-drift",
                rollback=rollback.replace(
                    "data: {SHADOW_BUILD_DIGEST:",
                    "data: {SHADOW_UNSEALED_COORDINATE: forbidden, SHADOW_BUILD_DIGEST:",
                    1,
                ),
            )
            acceptance_prefix_bootstrap = bootstrap.replace(
                "data: {SHADOW_AUTO_MIGRATE: 'false',",
                "data: {SHADOW_OBJECT_STORAGE_PREFIX: industrial-shadow/acceptance, "
                "SHADOW_AUTO_MIGRATE: 'false',",
                1,
            )
            acceptance_prefix_rollback = rollback.replace(
                "data: {SHADOW_AUTO_MIGRATE: 'false',",
                "data: {SHADOW_OBJECT_STORAGE_PREFIX: industrial-shadow/acceptance, "
                "SHADOW_AUTO_MIGRATE: 'false',",
                1,
            )
            assert_invalid_manifest_bindings(
                "acceptance-prefix-in-runtime-config",
                bootstrap=acceptance_prefix_bootstrap,
                rollback=acceptance_prefix_rollback,
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
            workload_kinds = {
                name: kind for kind, name, _container, _image, _url in workload_values
            }
            observed_images_for_runner = dict(expected_images)
            applied: list[str] = []
            api_ca = b"test-kubernetes-api-ca"
            api_ca_digest = hashlib.sha256(api_ca).hexdigest()
            cluster_uid_digest = canonical_digest(
                {
                    "api_server_ca_sha256": api_ca_digest,
                    "kube_system_namespace_uid": "kube-system-test-uid",
                }
            )
            rbac_payload = {
                "resourceRules": [
                    {
                        "apiGroups": [group],
                        "resources": [resource],
                        "verbs": [verb],
                        "resourceNames": [],
                    }
                    for group, resource, verb in sorted(PUBLISH_RBAC)
                ],
                "nonResourceRules": [],
                "incomplete": False,
                "evaluationError": "",
            }

            def runner(command: Sequence[str], _timeout: int) -> str:
                values = list(command)
                if "config" in values and "view" in values:
                    return json.dumps(
                        {
                            "clusters": [
                                {
                                    "cluster": {
                                        "server": "https://kubernetes.test.internal",
                                        "certificate-authority-data": base64.b64encode(
                                            api_ca
                                        ).decode(),
                                    }
                                }
                            ]
                        }
                    )
                if (
                    "get" in values
                    and "namespace" in values
                    and "kube-system" in values
                ):
                    return json.dumps({"metadata": {"uid": "kube-system-test-uid"}})
                if "auth" in values:
                    return json.dumps(rbac_payload)
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
                                    "spec": {
                                        "containers": [
                                            {"name": "migrate", "image": backend_image}
                                        ]
                                    }
                                }
                            },
                            "status": {
                                "succeeded": 1,
                                "failed": 0,
                                "conditions": [{"type": "Complete", "status": "True"}],
                            },
                        }
                    )
                if "get" in values and "pods" in values:
                    selector = values[values.index("-l") + 1]
                    if selector.startswith("job-name="):
                        return json.dumps({"items": []})
                    name = selector.removeprefix("app=")
                    image = observed_images_for_runner[name]
                    owner_uid = (
                        name + "-rs-uid"
                        if workload_kinds[name] == "deployment"
                        else name + "-uid"
                    )
                    return json.dumps(
                        {
                            "items": [
                                {
                                    "metadata": {
                                        "name": name + "-pod",
                                        "uid": name + "-pod-uid",
                                        "ownerReferences": [
                                            {
                                                "uid": owner_uid,
                                                "controller": True,
                                            }
                                        ],
                                    },
                                    "status": {
                                        "phase": "Running",
                                        "conditions": [
                                            {"type": "Ready", "status": "True"}
                                        ],
                                        "containerStatuses": [
                                            {
                                                "name": containers[name],
                                                "ready": True,
                                                "imageID": "docker-pullable://" + image,
                                            }
                                        ],
                                    },
                                }
                            ]
                        }
                    )
                if "get" in values and "replicasets" in values:
                    selector = values[values.index("-l") + 1]
                    name = selector.removeprefix("app=")
                    return json.dumps(
                        {
                            "items": [
                                {
                                    "metadata": {
                                        "uid": name + "-rs-uid",
                                        "annotations": {
                                            "deployment.kubernetes.io/revision": "1"
                                        },
                                        "ownerReferences": [
                                            {"uid": name + "-uid", "controller": True}
                                        ],
                                    },
                                    "spec": {"replicas": 1},
                                    "status": {"readyReplicas": 1},
                                }
                            ]
                        }
                    )
                if "get" in values:
                    index = values.index("get")
                    name = str(values[index + 2])
                    return json.dumps(
                        {
                            "metadata": {
                                "uid": name + "-uid",
                                "generation": 1,
                                "annotations": {
                                    "deployment.kubernetes.io/revision": "1"
                                },
                            },
                            "spec": {
                                "replicas": 1,
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
                                },
                            },
                            "status": {
                                "observedGeneration": 1,
                                "updatedReplicas": 1,
                                "currentReplicas": 1,
                                "readyReplicas": 1,
                                "availableReplicas": 1,
                                "unavailableReplicas": 0,
                                "currentRevision": "revision-1",
                                "updateRevision": "revision-1",
                            },
                        }
                    )
                return ""

            evidence = KubernetesProductionPublisher(
                plan,
                confirmation="industrial-shadow:release-20260809:deploy",
                context="production-test",
                expected_cluster_uid_digest=cluster_uid_digest,
                expected_kubernetes_api_ca_digest=api_ca_digest,
                runner=runner,
                readiness_probe=lambda _url: True,
            ).run()
            self.assertEqual("PASSED", evidence.status)
            self.assertEqual(7, evidence.metrics["ready_workloads"])
            self.assertNotEqual(str(plan.rollback_manifest.path), applied[-1])
            observed_images_for_runner["control-api"] = (
                "registry.test.internal/shadow@sha256:" + "b" * 64
            )
            applied.clear()
            failed = KubernetesProductionPublisher(
                plan,
                confirmation="industrial-shadow:release-20260809:deploy",
                context="production-test",
                expected_cluster_uid_digest=cluster_uid_digest,
                expected_kubernetes_api_ca_digest=api_ca_digest,
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
                    context="production-test",
                    expected_cluster_uid_digest=cluster_uid_digest,
                    expected_kubernetes_api_ca_digest=api_ca_digest,
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
                elif gate in {"external_ca", "real_ot"}:
                    metrics = {
                        "server_certificate_fingerprint": "f" * 64,
                        "client_certificate_fingerprint": "1" * 64,
                        "next_client_certificate_fingerprint": "3" * 64,
                        "client_application_uri": "urn:industrial-shadow:test-client",
                        "security_policy": "Basic256Sha256",
                    }
                    if gate == "real_ot":
                        metrics["node_allowlist_digest"] = "2" * 64
                        metrics["runtime_binding_digest"] = "4" * 64
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
            attestations = []
            for gate in ("security", "privacy", "accessibility", "benchmark_150"):
                report = root / f"{gate}-report.json"
                artifact = root / f"{gate}-artifact.json"
                report.write_text('{"signed":"fixture"}\n', encoding="utf-8")
                artifact.write_text('{"evidence":"fixture"}\n', encoding="utf-8")
                attestations.append(
                    {
                        "gate": gate,
                        "report_path": str(report.relative_to(ROOT)),
                        "report_sha256": hashlib.sha256(
                            report.read_bytes()
                        ).hexdigest(),
                        "report_digest": hashlib.sha256(
                            (gate + "-report").encode()
                        ).hexdigest(),
                        "trust_store_digest": trust_store.digest,
                        "artifacts": [
                            {
                                "path": str(artifact.relative_to(ROOT)),
                                "sha256": hashlib.sha256(
                                    artifact.read_bytes()
                                ).hexdigest(),
                            }
                        ],
                    }
                )
            approval = approval_payload(
                evidence,
                attestations,
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
                attestations=attestations,
                release_coordinates=release_coordinates,
                trust_store=trust_store,
            )
            self.assertEqual("verified", closure["status"])
            self.assertEqual(len(SOURCE_GATES), len(closure["artifacts"]))
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
                        "kubernetes_api_ca_digest": "e" * 64,
                        "aws_account_id": "123456789012",
                        "aws_region": "us-east-1",
                        "s3_bucket": "industrial-shadow-production",
                        "s3_probe_prefix": "industrial-shadow/production-acceptance",
                        "snapshot_object_storage_prefix": "industrial-shadow/snapshots",
                        "backup_object_storage_prefix": "industrial-shadow/backups",
                        "kms_key_id_digest": "1" * 64,
                        "backup_restore_receipt_digest": "0" * 64,
                        "backup_workload_identity_arn_digest": "2" * 64,
                        "snapshot_workload_identity_arn_digest": "3" * 64,
                        "oidc_issuer": "https://identity.internal/tenant",
                        "oidc_audience_digest": "0" * 64,
                        "oidc_human_client_id_digest": "1" * 64,
                        "oidc_service_client_ids_digest": "2" * 64,
                        "managed_postgresql_provider": "aws-rds",
                        "managed_postgresql_source_resource_digest": "4" * 64,
                        "managed_postgresql_restore_resource_digest": "5" * 64,
                        "managed_postgresql_source_coordinate_digest": "6" * 64,
                        "managed_postgresql_restore_coordinate_digest": "7" * 64,
                        "managed_postgresql_source_kms_key_digest": "8" * 64,
                        "managed_postgresql_restore_kms_key_digest": "9" * 64,
                        "managed_postgresql_source_ca_identifier_digest": "a" * 64,
                        "managed_postgresql_restore_ca_identifier_digest": "f" * 64,
                        "candidate_image": candidate,
                        "build_digest": "b" * 64,
                        "simulator_build_digest": "c" * 64,
                        "deployment_plan_digest": "d" * 64,
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
                deployment_plan_digest="d" * 64,
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
                "deployment_plan_digest": "d" * 64,
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
