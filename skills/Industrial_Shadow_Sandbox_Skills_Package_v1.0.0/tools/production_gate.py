from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import (
    DomainError,
    canonical_digest,
    canonical_json,
    utc_now,
)
from shadow_sandbox.common.object_storage import S3ObjectStorage
from shadow_sandbox.evaluation.formal_benchmark import FormalBenchmarkImporter
from shadow_sandbox.evaluation.measured_benchmark import MeasuredBenchmark
from shadow_sandbox.operations.certificate_probe import CertificateAuthorityProbe
from shadow_sandbox.operations.container_scan import DockerScoutReleaseProbe
from shadow_sandbox.operations.evidence import (
    GateEvidence,
    bind_to_acceptance_run,
    failed_execution,
    write_evidence,
)
from shadow_sandbox.operations.external_assurance import ExternalAssuranceImporter
from shadow_sandbox.operations.kubernetes_drills import (
    KubernetesChaosSuite,
    KubernetesDrill,
)
from shadow_sandbox.operations.load_probe import run_http_load_suite
from shadow_sandbox.operations.network_probe import (
    run_kubernetes_policy_suite,
)
from shadow_sandbox.operations.oidc_probe import OidcLiveProbe
from shadow_sandbox.operations.opcua_probe import ReadonlyOpcUaProbe
from shadow_sandbox.operations.production_deployment import ProductionDeploymentPlan
from shadow_sandbox.operations.production_preflight import ProductionPreflight
from shadow_sandbox.operations.restore_drill import PostgreSqlRestoreDrill
from shadow_sandbox.operations.storage_probe import S3KmsProbe
from shadow_sandbox.operations.trust_store import SignerTrustStore

ROOT = Path(__file__).resolve().parents[1]


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise DomainError("PRODUCTION_GATE_CONFIG_MISSING", f"{name} is required")
    return value


def _secret_json(path_value: str) -> Mapping[str, Any]:
    path = Path(path_value)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise DomainError(
            "PRODUCTION_GATE_SECRET_PERMISSIONS",
            "secret input must not be readable by group or other users",
        )
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise DomainError(
            "PRODUCTION_GATE_CONFIG_INVALID", "secret input must be an object"
        )
    return value


def _config(path_value: str) -> Mapping[str, Any]:
    value = json.loads(Path(path_value).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise DomainError(
            "PRODUCTION_GATE_CONFIG_INVALID", "config input must be an object"
        )
    return value


def _trust_store() -> SignerTrustStore:
    return SignerTrustStore.load(_required("SHADOW_ASSESSOR_TRUST_STORE"))


def _release_digest(*, strict: bool) -> str:
    names = {
        "candidate_image": "SHADOW_CANDIDATE_IMAGE",
        "build_digest": "SHADOW_BUILD_DIGEST",
        "simulator_build_digest": "SHADOW_SIMULATOR_BUILD_DIGEST",
        "environment_digest": "SHADOW_PRODUCTION_ENVIRONMENT_DIGEST",
        "deployment_plan_digest": "SHADOW_DEPLOYMENT_PLAN_DIGEST",
    }
    values = {key: os.environ.get(name, "") for key, name in names.items()}
    if strict and not all(values.values()):
        missing = next(names[key] for key, value in values.items() if not value)
        raise DomainError("PRODUCTION_GATE_CONFIG_MISSING", f"{missing} is required")
    return canonical_digest(
        values if all(values.values()) else {"configuration": "incomplete"}
    )


def run_gate(name: str) -> tuple[GateEvidence, Mapping[str, Any] | None]:
    if name == "preflight":
        return ProductionPreflight().run(), None
    if name == "benchmark_local":
        evidence, summary = MeasuredBenchmark(ROOT).run()
        return evidence, asdict(summary)
    if name == "benchmark_150":
        report = _config(_required("SHADOW_FORMAL_BENCHMARK_REPORT"))
        return FormalBenchmarkImporter(
            ROOT,
            candidate_image=_required("SHADOW_CANDIDATE_IMAGE"),
            build_digest=_required("SHADOW_BUILD_DIGEST"),
            simulator_build_digest=_required("SHADOW_SIMULATOR_BUILD_DIGEST"),
            trust_store=_trust_store(),
            environment_digest=_required("SHADOW_PRODUCTION_ENVIRONMENT_DIGEST"),
        ).import_report(report), None
    if name in {"security", "privacy", "accessibility"}:
        report_names = {
            "security": "SHADOW_SECURITY_ASSURANCE_REPORT",
            "privacy": "SHADOW_PRIVACY_ASSURANCE_REPORT",
            "accessibility": "SHADOW_ACCESSIBILITY_ASSURANCE_REPORT",
        }
        report = _config(_required(report_names[name]))
        return ExternalAssuranceImporter(
            ROOT,
            trust_store=_trust_store(),
            candidate_image=_required("SHADOW_CANDIDATE_IMAGE"),
            build_digest=_required("SHADOW_BUILD_DIGEST"),
            environment_digest=_required("SHADOW_PRODUCTION_ENVIRONMENT_DIGEST"),
            deployment_plan_digest=_required("SHADOW_DEPLOYMENT_PLAN_DIGEST"),
        ).import_report(report), None
    if name == "container_scan":
        plan = ProductionDeploymentPlan.load(
            ROOT,
            _required("SHADOW_PRODUCTION_DEPLOYMENT_PLAN"),
            candidate_image=_required("SHADOW_CANDIDATE_IMAGE"),
            expected_digest=_required("SHADOW_DEPLOYMENT_PLAN_DIGEST"),
        )
        return DockerScoutReleaseProbe(
            ROOT,
            backend_image=plan.backend_image,
            web_image=plan.web_image,
            backend_report_path=_required("SHADOW_CONTAINER_SCAN_REPORT"),
            credentials_file=_required("SHADOW_DOCKER_SCOUT_CREDENTIALS_FILE"),
        ).run(), None
    if name == "oidc":
        secrets = _secret_json(_required("SHADOW_OIDC_PROBE_SECRETS_FILE"))
        probe = OidcLiveProbe(
            _required("SHADOW_OIDC_ISSUER"),
            _required("SHADOW_OIDC_AUDIENCE"),
            _required("SHADOW_OIDC_JWKS_URL"),
            _required("SHADOW_PRODUCTION_API_URL"),
        )
        values = secrets.get("persona_bearer_values", {})
        if not isinstance(values, Mapping):
            raise DomainError(
                "OIDC_PROBE_PERSONAS_REQUIRED", "persona bearer map is required"
            )
        return probe.run({str(key): str(value) for key, value in values.items()}), None
    if name == "s3":
        try:
            import boto3
        except ImportError as error:
            raise DomainError(
                "S3_DEPENDENCY_UNAVAILABLE", "install the object-storage dependency"
            ) from error
        region = _required("SHADOW_OBJECT_STORAGE_REGION")
        endpoint = os.environ.get("SHADOW_OBJECT_STORAGE_ENDPOINT")
        storage = S3ObjectStorage(
            _required("SHADOW_OBJECT_STORAGE_BUCKET"),
            region=region,
            endpoint_url=endpoint,
            prefix=os.environ.get(
                "SHADOW_OBJECT_STORAGE_PREFIX", "industrial-shadow/production"
            ),
            kms_key_id=_required("SHADOW_OBJECT_STORAGE_KMS_KEY_ID"),
            kms_encryption_context={
                "application": "industrial-shadow",
                "purpose": "probe",
            },
        )
        return S3KmsProbe(
            storage,
            require_object_lock=os.environ.get(
                "SHADOW_REQUIRE_OBJECT_LOCK", "true"
            ).lower()
            == "true",
            kms_client=boto3.client("kms", region_name=region),
            sts_client=boto3.client("sts", region_name=region),
            expected_account_id=_required("SHADOW_AWS_ACCOUNT_ID"),
            require_cloud_control_plane=True,
        ).run(), None
    if name == "external_ca":
        probe = CertificateAuthorityProbe(
            server_certificate=_required("SHADOW_OPCUA_SERVER_CERTIFICATE"),
            client_certificate=_required("SHADOW_OPCUA_CLIENT_CERTIFICATE"),
            ca_bundle=_required("SHADOW_OPCUA_CA_BUNDLE"),
            crl_file=_required("SHADOW_OPCUA_CRL_FILE"),
            server_application_uri=_required("SHADOW_OPCUA_APPLICATION_URI"),
            client_application_uri=_required("SHADOW_OPCUA_CLIENT_APPLICATION_URI"),
            expected_server_fingerprint=_required("SHADOW_CERTIFICATE_FINGERPRINT"),
            expected_client_fingerprint=_required(
                "SHADOW_CLIENT_CERTIFICATE_FINGERPRINT"
            ),
            next_server_certificate=_required("SHADOW_OPCUA_NEXT_SERVER_CERTIFICATE"),
            next_client_certificate=_required("SHADOW_OPCUA_NEXT_CLIENT_CERTIFICATE"),
            expected_next_server_fingerprint=_required(
                "SHADOW_NEXT_SERVER_CERTIFICATE_FINGERPRINT"
            ),
            expected_next_client_fingerprint=_required(
                "SHADOW_NEXT_CLIENT_CERTIFICATE_FINGERPRINT"
            ),
            minimum_validity_days=int(
                os.environ.get("SHADOW_CERTIFICATE_MINIMUM_DAYS", "30")
            ),
            client_private_key=_required("SHADOW_OPCUA_CLIENT_PRIVATE_KEY"),
            next_client_private_key=_required("SHADOW_OPCUA_NEXT_CLIENT_PRIVATE_KEY"),
            require_client_key_match=True,
        )
        return probe.run(), None
    if name == "real_ot":
        binding = _config(_required("SHADOW_OPCUA_PROBE_CONFIG"))
        probe = ReadonlyOpcUaProbe(
            endpoint_uri=str(binding["endpoint_uri"]),
            application_uri=str(binding["application_uri"]),
            namespace_uri=str(binding["namespace_uri"]),
            certificate_fingerprint=str(binding["certificate_fingerprint"]),
            node_ids=tuple(str(item) for item in binding["node_ids"]),
            security_string=_required("SHADOW_OPCUA_SECURITY_STRING"),
            sampling_interval_ms=int(binding.get("sampling_interval_ms", 500)),
            observation_seconds=float(binding.get("observation_seconds", 30)),
            allowed_security_policies=tuple(
                str(item)
                for item in binding.get(
                    "allowed_security_policies",
                    ("Basic256Sha256", "Aes256_Sha256_RsaPss"),
                )
            ),
        )
        return asyncio.run(probe.run()), None
    if name == "backup_restore":
        probe = PostgreSqlRestoreDrill(
            _required("SHADOW_RESTORE_SOURCE_DATABASE_URL"),
            _required("SHADOW_RESTORE_TARGET_DATABASE_URL"),
            allow_restore=os.environ.get("SHADOW_ALLOW_DESTRUCTIVE_RESTORE_DRILL")
            == "true",
            application_target_url=_required("SHADOW_RESTORE_APPLICATION_DATABASE_URL"),
            backup_target_url=_required("SHADOW_RESTORE_BACKUP_DATABASE_URL"),
            tenant_roles=tuple(
                item.strip()
                for item in _required("SHADOW_DATABASE_TENANT_ROLES").split(",")
                if item.strip()
            ),
            maintenance_role=_required("SHADOW_DATABASE_MAINTENANCE_ROLE"),
            backup_role=_required("SHADOW_DATABASE_BACKUP_ROLE"),
            maximum_restore_seconds=int(
                os.environ.get("SHADOW_RESTORE_MAXIMUM_SECONDS", "1800")
            ),
            maximum_archive_bytes=int(
                os.environ.get(
                    "SHADOW_RESTORE_MAXIMUM_ARCHIVE_BYTES", str(100 * 1024**3)
                )
            ),
            managed_provider=_required("SHADOW_MANAGED_POSTGRESQL_PROVIDER"),
            managed_instance_digest=_required(
                "SHADOW_MANAGED_POSTGRESQL_INSTANCE_DIGEST"
            ),
            require_managed_coordinates=True,
        )
        return probe.run(), None
    if name == "network_policy":
        config = _config(_required("SHADOW_NETWORK_PROBE_CONFIG"))
        return run_kubernetes_policy_suite(
            namespace=str(config["namespace"]),
            probes=tuple(config["probes"]),
            policy_path=config.get(
                "policy_path", ROOT / "deploy/production/network-policies.yaml"
            ),
            confirmation=_required("SHADOW_PRODUCTION_NETWORK_PROBE_CONFIRMATION"),
            timeout_seconds=int(config.get("timeout_seconds", 120)),
        ), None
    if name == "performance":
        config = _config(_required("SHADOW_LOAD_PROBE_CONFIG"))
        secrets = _secret_json(_required("SHADOW_LOAD_PROBE_SECRETS_FILE"))
        return run_http_load_suite(
            str(config["base_url"]),
            tuple(config["profiles"]),
            bearer_value=str(secrets.get("bearer_value") or "") or None,
            health_path=str(config.get("health_path", "/api/v1/health/ready")),
        ), None
    if name == "resilience":
        config = _config(_required("SHADOW_CHAOS_DRILL_CONFIG"))
        suite = KubernetesChaosSuite(
            str(config["namespace"]),
            _required("SHADOW_DRILL_DATABASE_URL"),
            confirmation=_required("SHADOW_PRODUCTION_CHAOS_CONFIRMATION"),
        )
        return suite.run(tuple(config["scenarios"])), None
    if name == "upgrade_rollback":
        config = _config(_required("SHADOW_KUBERNETES_DRILL_CONFIG"))
        drill = KubernetesDrill(
            str(config["namespace"]),
            str(config["deployment"]),
            str(config["container"]),
            str(config["readiness_url"]),
            _required("SHADOW_DRILL_DATABASE_URL"),
            confirmation=_required("SHADOW_PRODUCTION_DRILL_CONFIRMATION"),
            maximum_rollback_seconds=int(config.get("maximum_rollback_seconds", 900)),
        )
        return drill.upgrade_and_rollback(
            _required("SHADOW_CANDIDATE_IMAGE"), str(config["migration_job"])
        ), None
    raise DomainError("PRODUCTION_GATE_UNKNOWN", f"unknown production gate: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run one fail-closed production acceptance gate"
    )
    parser.add_argument(
        "gate",
        choices=(
            "preflight",
            "oidc",
            "backup_restore",
            "external_ca",
            "real_ot",
            "s3",
            "network_policy",
            "container_scan",
            "security",
            "performance",
            "privacy",
            "accessibility",
            "resilience",
            "upgrade_rollback",
            "benchmark_local",
            "benchmark_150",
        ),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    if args.gate == "benchmark_local":
        evidence, summary = run_gate(args.gate)
    else:
        configured_run_id = os.environ.get("SHADOW_ACCEPTANCE_RUN_ID", "")
        run_id = configured_run_id or (
            "unbound-"
            + canonical_digest({"gate": args.gate, "started_at": utc_now()})[:20]
        )
        started = utc_now()
        try:
            if not configured_run_id:
                raise DomainError(
                    "PRODUCTION_GATE_RUN_ID_MISSING",
                    "SHADOW_ACCEPTANCE_RUN_ID is required",
                )
            release_digest = _release_digest(strict=True)
            evidence, summary = run_gate(args.gate)
            evidence = bind_to_acceptance_run(
                evidence, run_id=run_id, release_digest=release_digest
            )
        except DomainError as error:
            evidence = failed_execution(
                args.gate,
                started_at=started,
                error_code=error.code,
                run_id=run_id,
                release_digest=_release_digest(strict=False),
            )
            summary = None
        except Exception:  # noqa: BLE001 - unexpected probe faults emit sealed FAILED evidence
            evidence = failed_execution(
                args.gate,
                started_at=started,
                error_code="UNEXPECTED",
                run_id=run_id,
                release_digest=_release_digest(strict=False),
            )
            summary = None
    write_evidence(args.output, evidence)
    if summary is not None:
        if not args.summary:
            parser.error("--summary is required for this benchmark command")
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(canonical_json(summary) + "\n", encoding="utf-8")
    print(
        canonical_json(
            {
                "gate": evidence.gate,
                "status": evidence.status,
                "evidence": str(args.output),
                "digest": evidence.digest,
            }
        )
    )
    return 0 if evidence.status == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
