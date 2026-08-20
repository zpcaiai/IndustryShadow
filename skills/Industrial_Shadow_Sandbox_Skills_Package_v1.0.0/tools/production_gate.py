from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
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
from shadow_sandbox.common.object_storage import S3ObjectStorage, validate_object_key
from shadow_sandbox.common.opcua_readonly import (
    normalize_opcua_fingerprint,
    normalize_opcua_security_string,
    opcua_runtime_binding_digest,
)
from shadow_sandbox.common.secure_files import read_private_json_object
from shadow_sandbox.evaluation.formal_benchmark import (
    FormalBenchmarkImporter,
    production_storage_binding_digest,
    validate_production_storage_target,
)
from shadow_sandbox.evaluation.measured_benchmark import MeasuredBenchmark
from shadow_sandbox.operations.backup_job import database_coordinate_digest
from shadow_sandbox.operations.certificate_probe import CertificateAuthorityProbe
from shadow_sandbox.operations.container_scan import DockerScoutReleaseProbe
from shadow_sandbox.operations.evidence import (
    GateCheck,
    GateEvidence,
    bind_to_acceptance_run,
    complete,
    failed_execution,
    write_evidence,
)
from shadow_sandbox.operations.external_assurance import ExternalAssuranceImporter
from shadow_sandbox.operations.kubernetes_drills import (
    KubernetesChaosSuite,
    KubernetesDrill,
)
from shadow_sandbox.operations.kubernetes_storage_probe import (
    run_kubernetes_storage_identity_probe,
)
from shadow_sandbox.operations.load_probe import run_http_load_suite
from shadow_sandbox.operations.managed_postgresql_probe import AwsRdsControlPlaneProbe
from shadow_sandbox.operations.network_probe import (
    run_kubernetes_policy_suite,
)
from shadow_sandbox.operations.oidc_probe import OidcLiveProbe
from shadow_sandbox.operations.opcua_probe import ReadonlyOpcUaProbe
from shadow_sandbox.operations.postgresql_migration import (
    MigrationCompatibilityManifest,
    PostgreSqlMigrationProbe,
)
from shadow_sandbox.operations.production_deployment import ProductionDeploymentPlan
from shadow_sandbox.operations.production_preflight import ProductionPreflight
from shadow_sandbox.operations.restore_drill import (
    BackupRestoreReceipt,
    PostgreSqlRestoreDrill,
)
from shadow_sandbox.operations.storage_probe import (
    AWS_STORAGE_POLICY_DIGEST_FIELDS,
    IAM_OIDC_PROVIDER_ARN,
    IAM_ROLE_ARN,
    S3KmsProbe,
    aws_partition_for_region,
    github_actions_caller_trust_contract,
    normalized_iam_role_arn,
)
from shadow_sandbox.operations.supply_chain import (
    ReleaseCandidate,
    SupplyChainAttestationProbe,
)
from shadow_sandbox.operations.trust_store import SignerTrustStore

ROOT = Path(__file__).resolve().parents[1]


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise DomainError("PRODUCTION_GATE_CONFIG_MISSING", f"{name} is required")
    return value


def _secret_json(path_value: str) -> Mapping[str, Any]:
    return read_private_json_object(
        path_value,
        code="PRODUCTION_GATE_SECRET_INVALID",
    )


def _config(path_value: str) -> Mapping[str, Any]:
    value = json.loads(Path(path_value).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise DomainError(
            "PRODUCTION_GATE_CONFIG_INVALID", "config input must be an object"
        )
    return value


def _trust_store() -> SignerTrustStore:
    return SignerTrustStore.load_verified(
        _required("SHADOW_ASSESSOR_TRUST_STORE"),
        root_attestation_path=_required("SHADOW_ASSESSOR_TRUST_ROOT_ATTESTATION"),
        root_public_key_path=_required("SHADOW_ASSESSOR_TRUST_ROOT_PUBLIC_KEY"),
        expected_root_key_sha256=_required("SHADOW_ASSESSOR_TRUST_ROOT_KEY_SHA256"),
    )


def _signed_target_profile() -> Mapping[str, Any]:
    report = _config(_required("SHADOW_FORMAL_BENCHMARK_REPORT"))
    expected_profile_digest = _required("SHADOW_PRODUCTION_ENVIRONMENT_DIGEST")
    artifacts = report.get("artifacts", ())
    if not isinstance(artifacts, list):
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID", "target profile list is invalid"
        )
    targets = [
        item
        for item in artifacts
        if isinstance(item, Mapping) and item.get("kind") == "target_profile"
    ]
    if (
        len(targets) != 1
        or report.get("target_profile_digest") != expected_profile_digest
        or targets[0].get("sha256") != expected_profile_digest
    ):
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID",
            "release-bound target profile is missing",
        )
    target_path = (ROOT / str(targets[0].get("path", ""))).resolve(strict=True)
    if ROOT.resolve() not in target_path.parents or target_path.is_symlink():
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID", "target profile path is unsafe"
        )
    if hashlib.sha256(target_path.read_bytes()).hexdigest() != expected_profile_digest:
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID", "target profile digest mismatch"
        )
    target = _config(str(target_path))
    if (
        target.get("candidate_image") != _required("SHADOW_CANDIDATE_IMAGE")
        or target.get("build_digest") != _required("SHADOW_BUILD_DIGEST")
        or target.get("simulator_build_digest")
        != _required("SHADOW_SIMULATOR_BUILD_DIGEST")
        or target.get("deployment_plan_digest")
        != _required("SHADOW_DEPLOYMENT_PLAN_DIGEST")
        or not re.fullmatch(r"[a-f0-9]{64}", str(target.get("cluster_uid_digest", "")))
        or not re.fullmatch(
            r"[a-f0-9]{64}", str(target.get("kubernetes_api_ca_digest", ""))
        )
    ):
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID", "target profile coordinates mismatch"
        )
    return target


def _deployment_binding(
    context_environment_variable: str | None = None,
) -> tuple[ProductionDeploymentPlan, str, str, str]:
    plan = ProductionDeploymentPlan.load(
        ROOT,
        _required("SHADOW_PRODUCTION_DEPLOYMENT_PLAN"),
        candidate_image=_required("SHADOW_CANDIDATE_IMAGE"),
        expected_digest=_required("SHADOW_DEPLOYMENT_PLAN_DIGEST"),
    )
    target = _signed_target_profile()
    _validate_signed_identity_and_storage(target)
    if (
        target.get("candidate_image") != plan.backend_image
        or target.get("snapshot_object_storage_prefix")
        != plan.snapshot_object_storage_prefix
        or target.get("backup_object_storage_prefix")
        != plan.backup_object_storage_prefix
        or target.get("snapshot_workload_identity_arn_digest")
        != plan.snapshot_workload_identity_arn_digest
        or target.get("backup_workload_identity_arn_digest")
        != plan.backup_workload_identity_arn_digest
        or target.get("aws_region")
        != plan.object_storage_region
        or target.get("aws_account_id")
        != plan.object_storage_account_id
        or plan.object_storage_region != plan.storage_egress_contract.region
        or plan.storage_egress_contract.partition
        != target.get("aws_partition")
        or target.get("storage_egress_contract_digest")
        != plan.storage_egress_contract.digest
    ):
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID",
            "target profile is not bound to the sealed deployment plan and runtime storage paths",
        )
    return (
        plan,
        _required(context_environment_variable)
        if context_environment_variable is not None
        else "",
        str(target["cluster_uid_digest"]),
        str(target["kubernetes_api_ca_digest"]),
    )


def _real_ot_probe_binding_digest() -> str:
    binding = _config(_required("SHADOW_OPCUA_PROBE_CONFIG"))
    node_ids = binding.get("node_ids")
    if (
        not isinstance(node_ids, list)
        or not node_ids
        or any(not isinstance(item, str) or not item.strip() for item in node_ids)
        or len(node_ids) != len(set(node_ids))
    ):
        raise DomainError(
            "REAL_OT_BINDING_INVALID", "real-OT NodeId allowlist is invalid"
        )
    security_profile, _certificate_path, _key_path, _server_path = (
        normalize_opcua_security_string(
            _required("SHADOW_OPCUA_SECURITY_STRING"),
            code="REAL_OT_BINDING_INVALID",
        )
    )
    server_fingerprint = normalize_opcua_fingerprint(
        str(binding.get("certificate_fingerprint", "")),
        code="REAL_OT_BINDING_INVALID",
    )
    client_fingerprint = normalize_opcua_fingerprint(
        str(binding.get("client_certificate_fingerprint", "")),
        code="REAL_OT_BINDING_INVALID",
    )
    if (
        server_fingerprint
        != normalize_opcua_fingerprint(
            _required("SHADOW_CERTIFICATE_FINGERPRINT"),
            code="REAL_OT_BINDING_INVALID",
        )
        or client_fingerprint
        != normalize_opcua_fingerprint(
            _required("SHADOW_CLIENT_CERTIFICATE_FINGERPRINT"),
            code="REAL_OT_BINDING_INVALID",
        )
        or binding.get("application_uri") != _required("SHADOW_OPCUA_APPLICATION_URI")
        or binding.get("client_application_uri")
        != _required("SHADOW_OPCUA_CLIENT_APPLICATION_URI")
    ):
        raise DomainError(
            "REAL_OT_BINDING_INVALID",
            "real-OT probe and external-CA coordinates must be identical",
        )
    return opcua_runtime_binding_digest(
        endpoint_uri=str(binding.get("endpoint_uri", "")),
        application_uri=str(binding.get("application_uri", "")),
        client_application_uri=str(binding.get("client_application_uri", "")),
        namespace_uri=str(binding.get("namespace_uri", "")),
        server_certificate_fingerprint=server_fingerprint,
        client_certificate_fingerprint=client_fingerprint,
        next_client_certificate_fingerprint=_required(
            "SHADOW_NEXT_CLIENT_CERTIFICATE_FINGERPRINT"
        ),
        security_profile=security_profile,
        node_ids=tuple(node_ids),
        code="REAL_OT_BINDING_INVALID",
    )


def _service_client_ids() -> tuple[str, ...]:
    values = tuple(
        item.strip()
        for item in _required("SHADOW_OIDC_SERVICE_CLIENT_IDS").split(",")
        if item.strip()
    )
    if not values or len(values) != len(set(values)):
        raise DomainError(
            "OIDC_SERVICE_CLIENT_IDS_INVALID",
            "OIDC service client IDs must be a non-empty unique list",
        )
    return values


def _validate_signed_identity_and_storage(target: Mapping[str, Any]) -> None:
    validate_production_storage_target(target)
    receipt = BackupRestoreReceipt.load(
        _required("SHADOW_BACKUP_RESTORE_RECEIPT"),
        expected_source_database_digest=database_coordinate_digest(
            _required("SHADOW_RESTORE_SOURCE_DATABASE_URL")
        ),
    )
    prefixes = tuple(
        _required(name)
        for name in (
            "SHADOW_OBJECT_STORAGE_PREFIX",
            "SHADOW_SNAPSHOT_OBJECT_STORAGE_PREFIX",
            "SHADOW_BACKUP_OBJECT_STORAGE_PREFIX",
        )
    )
    segments = tuple(tuple(value.split("/")) for value in prefixes)
    if (
        len(set(prefixes)) != 3
        or any(validate_object_key(value) != value for value in prefixes)
        or any(
            left == right[: len(left)] or right == left[: len(right)]
            for index, left in enumerate(segments)
            for right in segments[index + 1 :]
        )
        or _required("SHADOW_BACKUP_WORKLOAD_IDENTITY_ARN")
        == _required("SHADOW_SNAPSHOT_WORKLOAD_IDENTITY_ARN")
    ):
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID",
            "storage prefixes must be canonical/non-nested and workload roles distinct",
        )
    account_id = _required("SHADOW_AWS_ACCOUNT_ID")
    region = _required("SHADOW_OBJECT_STORAGE_REGION")
    partition = aws_partition_for_region(region)
    caller_arn = _required("SHADOW_S3_CONTROL_PLANE_CALLER_ARN")
    kms_admin_role_arn = _required("SHADOW_KMS_ADMIN_ROLE_ARN")
    provider_arn = _required("SHADOW_AWS_IRSA_OIDC_PROVIDER_ARN")
    caller_match = IAM_ROLE_ARN.fullmatch(caller_arn)
    kms_admin_match = IAM_ROLE_ARN.fullmatch(kms_admin_role_arn)
    provider_match = IAM_OIDC_PROVIDER_ARN.fullmatch(provider_arn)
    role_arns = tuple(
        _required(name)
        for name in (
            "SHADOW_BACKUP_WORKLOAD_IDENTITY_ARN",
            "SHADOW_SNAPSHOT_WORKLOAD_IDENTITY_ARN",
        )
    )
    role_matches = tuple(IAM_ROLE_ARN.fullmatch(role_arn) for role_arn in role_arns)
    kms_match = re.fullmatch(
        rf"arn:{re.escape(partition)}:kms:{re.escape(region)}:"
        rf"{re.escape(account_id)}:key/[A-Za-z0-9-]+",
        _required("SHADOW_OBJECT_STORAGE_KMS_KEY_ID"),
    )
    if (
        caller_match is None
        or caller_match.group(1) != partition
        or caller_match.group(2) != account_id
        or normalized_iam_role_arn(caller_arn) != caller_arn
        or kms_admin_match is None
        or kms_admin_match.group(1) != partition
        or kms_admin_match.group(2) != account_id
        or provider_match is None
        or provider_match.group(1) != partition
        or provider_match.group(2) != account_id
        or any(
            match is None or match.group(1) != partition or match.group(2) != account_id
            for match in role_matches
        )
        or len({caller_arn, kms_admin_role_arn, *role_arns}) != 4
        or kms_match is None
    ):
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID",
            "AWS account, partition, caller, IRSA provider, role, or KMS binding is invalid",
        )
    caller_trust_contract = github_actions_caller_trust_contract(
        account_id=account_id,
        region=region,
        repository=_required("SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_REPOSITORY"),
        repository_owner_id=_required(
            "SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_REPOSITORY_OWNER_ID"
        ),
        repository_id=_required(
            "SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_REPOSITORY_ID"
        ),
        ref=_required("SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_REF"),
        environment=_required(
            "SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_ENVIRONMENT"
        ),
        workflow=_required("SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_WORKFLOW"),
    )
    expected = {
        "aws_account_id": account_id,
        "aws_partition": partition,
        "aws_region": region,
        "oidc_issuer": _required("SHADOW_OIDC_ISSUER").rstrip("/"),
        "oidc_audience_digest": canonical_digest(
            {"audience": _required("SHADOW_OIDC_AUDIENCE")}
        ),
        "oidc_human_client_id_digest": canonical_digest(
            {"client_id": _required("SHADOW_OIDC_CLIENT_ID")}
        ),
        "oidc_service_client_ids_digest": canonical_digest(
            sorted(_service_client_ids())
        ),
        "s3_bucket": _required("SHADOW_OBJECT_STORAGE_BUCKET"),
        "s3_probe_prefix": _required("SHADOW_OBJECT_STORAGE_PREFIX"),
        "snapshot_object_storage_prefix": _required(
            "SHADOW_SNAPSHOT_OBJECT_STORAGE_PREFIX"
        ),
        "backup_object_storage_prefix": _required(
            "SHADOW_BACKUP_OBJECT_STORAGE_PREFIX"
        ),
        "kms_key_id_digest": canonical_digest(
            {"kms_key_id": _required("SHADOW_OBJECT_STORAGE_KMS_KEY_ID")}
        ),
        "backup_restore_receipt_digest": receipt.receipt_digest,
        "backup_workload_identity_arn_digest": canonical_digest(
            {"workload_identity_arn": _required("SHADOW_BACKUP_WORKLOAD_IDENTITY_ARN")}
        ),
        "snapshot_workload_identity_arn_digest": canonical_digest(
            {
                "workload_identity_arn": _required(
                    "SHADOW_SNAPSHOT_WORKLOAD_IDENTITY_ARN"
                )
            }
        ),
        "s3_control_plane_caller_arn_digest": canonical_digest(
            {"caller_arn": caller_arn}
        ),
        "s3_control_plane_caller_trust_contract": caller_trust_contract,
        "s3_control_plane_caller_trust_contract_digest": canonical_digest(
            caller_trust_contract
        ),
        "kms_admin_role_arn_digest": canonical_digest(
            {"role_arn": kms_admin_role_arn}
        ),
        "aws_irsa_oidc_provider_arn_digest": canonical_digest(
            {"provider_arn": _required("SHADOW_AWS_IRSA_OIDC_PROVIDER_ARN")}
        ),
    }
    if any(target.get(name) != value for name, value in expected.items()):
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID",
            "OIDC, object-storage, or immutable backup coordinates are not signed",
        )


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


def _immutable_image_digest(name: str) -> str:
    value = _required(name)
    match = re.fullmatch(r"[^@\s]+@sha256:([a-f0-9]{64})", value)
    if match is None or match.group(1) == "0" * 64:
        raise DomainError(
            "PRODUCTION_GATE_IMAGE_INVALID",
            f"{name} must be an immutable non-zero image digest",
        )
    return match.group(1)


def _oidc_browser_binding() -> Mapping[str, str]:
    return {
        "acceptance_run_id": _required("SHADOW_ACCEPTANCE_RUN_ID"),
        "release_digest": _release_digest(strict=True),
        "candidate_image_digest": _immutable_image_digest("SHADOW_CANDIDATE_IMAGE"),
        "web_candidate_image_digest": _immutable_image_digest(
            "SHADOW_WEB_CANDIDATE_IMAGE"
        ),
        "build_digest": _required("SHADOW_BUILD_DIGEST"),
        "simulator_build_digest": _required("SHADOW_SIMULATOR_BUILD_DIGEST"),
        "environment_digest": _required("SHADOW_PRODUCTION_ENVIRONMENT_DIGEST"),
        "deployment_plan_digest": _required("SHADOW_DEPLOYMENT_PLAN_DIGEST"),
    }


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
            deployment_plan_digest=_required("SHADOW_DEPLOYMENT_PLAN_DIGEST"),
        ).import_report(report), None
    if name == "supply_chain":
        candidate = ReleaseCandidate.load(
            _required("SHADOW_RELEASE_CANDIDATE_MANIFEST"),
            expected_repository=_required("SHADOW_RELEASE_REPOSITORY"),
            expected_run_id=_required("SHADOW_RELEASE_RUN_ID"),
            expected_run_attempt=int(_required("SHADOW_RELEASE_RUN_ATTEMPT")),
        )
        if (
            candidate.backend_image != _required("SHADOW_CANDIDATE_IMAGE")
            or candidate.web_image != _required("SHADOW_WEB_CANDIDATE_IMAGE")
            or candidate.source_digest != _required("SHADOW_BUILD_DIGEST")
            or candidate.source_digest != _required("SHADOW_SIMULATOR_BUILD_DIGEST")
            or candidate.source_revision != _required("SHADOW_RELEASE_SOURCE_REVISION")
        ):
            raise DomainError(
                "RELEASE_CANDIDATE_MISMATCH",
                "candidate manifest does not match the acceptance release coordinates",
            )
        return SupplyChainAttestationProbe(
            candidate,
            candidate_attestation_bundle=_required("SHADOW_RELEASE_CANDIDATE_BUNDLE"),
            registry_credentials_file=_required(
                "SHADOW_IMAGE_REGISTRY_CREDENTIALS_FILE"
            ),
        ).run(), None
    if name == "postgresql_migration":
        secrets = _secret_json(_required("SHADOW_POSTGRESQL_MIGRATION_DATABASES_FILE"))
        if set(secrets) != {
            "fresh_database_url",
            "upgrade_database_url",
            "confirmation",
        }:
            raise DomainError(
                "POSTGRESQL_MIGRATION_CONFIG_INVALID",
                "migration drill secret fields are invalid",
            )
        candidate = ReleaseCandidate.load(
            _required("SHADOW_RELEASE_CANDIDATE_MANIFEST"),
            expected_repository=_required("SHADOW_RELEASE_REPOSITORY"),
            expected_run_id=_required("SHADOW_RELEASE_RUN_ID"),
            expected_run_attempt=int(_required("SHADOW_RELEASE_RUN_ATTEMPT")),
        )
        manifest = MigrationCompatibilityManifest.load(
            _required("SHADOW_POSTGRESQL_MIGRATION_MANIFEST"),
            expected_source_revision=_required("SHADOW_RELEASE_SOURCE_REVISION"),
            expected_source_digest=_required("SHADOW_BUILD_DIGEST"),
        )
        if manifest.path != candidate.postgresql_migration_manifest.path:
            raise DomainError(
                "POSTGRESQL_MIGRATION_MANIFEST_INVALID",
                "migration manifest is not the candidate-bound artifact",
            )
        return PostgreSqlMigrationProbe(
            str(secrets["fresh_database_url"]),
            str(secrets["upgrade_database_url"]),
            migration_directory=ROOT / "migrations",
            compatibility_manifest=manifest,
            confirmation=str(secrets["confirmation"]),
            maximum_seconds=int(
                os.environ.get("SHADOW_POSTGRESQL_MIGRATION_MAXIMUM_SECONDS", "900")
            ),
            maximum_protected_rows=int(
                os.environ.get("SHADOW_POSTGRESQL_MIGRATION_MAXIMUM_ROWS", "100000")
            ),
        ).run(), None
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
            registry_credentials_file=_required(
                "SHADOW_IMAGE_REGISTRY_CREDENTIALS_FILE"
            ),
        ).run(), None
    if name == "oidc":
        _validate_signed_identity_and_storage(_signed_target_profile())
        secrets = _secret_json(_required("SHADOW_OIDC_PROBE_SECRETS_FILE"))
        probe = OidcLiveProbe(
            _required("SHADOW_OIDC_ISSUER"),
            _required("SHADOW_OIDC_AUDIENCE"),
            _required("SHADOW_OIDC_JWKS_URL"),
            _required("SHADOW_PRODUCTION_API_URL"),
            client_id=_required("SHADOW_OIDC_CLIENT_ID"),
            authorization_url=_required("SHADOW_OIDC_AUTHORIZATION_URL"),
            token_url=_required("SHADOW_OIDC_TOKEN_URL"),
            end_session_url=_required("SHADOW_OIDC_END_SESSION_URL"),
            web_base_url=_required("SHADOW_PRODUCTION_WEB_URL"),
            service_client_ids=_service_client_ids(),
            algorithms=tuple(
                item.strip()
                for item in _required("SHADOW_OIDC_ID_TOKEN_SIGNING_ALGORITHMS").split(
                    ","
                )
                if item.strip()
            ),
            browser_binding=_oidc_browser_binding(),
        )
        values = secrets.get("persona_bearer_values", {})
        if not isinstance(values, Mapping):
            raise DomainError(
                "OIDC_PROBE_PERSONAS_REQUIRED", "persona bearer map is required"
            )
        return (
            probe.run(
                {str(key): str(value) for key, value in values.items()},
                browser_journey=read_private_json_object(
                    _required("SHADOW_OIDC_BROWSER_JOURNEY"),
                    code="OIDC_BROWSER_JOURNEY_FILE_INVALID",
                ),
            ),
            None,
        )
    if name == "s3":
        plan, context, cluster_uid_digest, kubernetes_api_ca_digest = (
            _deployment_binding("SHADOW_KUBERNETES_STORAGE_CONTEXT")
        )
        target_profile = _signed_target_profile()
        _validate_signed_identity_and_storage(target_profile)
        storage_binding_digest = production_storage_binding_digest(
            target_profile,
            plan,
        )
        try:
            import boto3
        except ImportError as error:
            raise DomainError(
                "S3_DEPENDENCY_UNAVAILABLE", "install the object-storage dependency"
            ) from error
        region = _required("SHADOW_OBJECT_STORAGE_REGION")
        endpoint = os.environ.get("SHADOW_OBJECT_STORAGE_ENDPOINT")
        account_id = _required("SHADOW_AWS_ACCOUNT_ID")
        probe_prefix = _required("SHADOW_OBJECT_STORAGE_PREFIX")
        snapshot_prefix = _required("SHADOW_SNAPSHOT_OBJECT_STORAGE_PREFIX")
        backup_prefix = _required("SHADOW_BACKUP_OBJECT_STORAGE_PREFIX")
        bucket = _required("SHADOW_OBJECT_STORAGE_BUCKET")
        kms_key_id = _required("SHADOW_OBJECT_STORAGE_KMS_KEY_ID")
        require_object_lock = _required("SHADOW_REQUIRE_OBJECT_LOCK") == "true"
        if not require_object_lock:
            raise DomainError(
                "S3_OBJECT_LOCK_REQUIRED",
                "production S3 probes require Object Lock retention",
            )
        storage = S3ObjectStorage(
            bucket,
            region=region,
            endpoint_url=endpoint,
            prefix=probe_prefix,
            kms_key_id=kms_key_id,
            kms_encryption_context={
                "application": "industrial-shadow",
                "purpose": "probe",
            },
            expected_bucket_owner=account_id,
            production=True,
        )
        expected_policy_digests = {
            name: str(target_profile[name]) for name in AWS_STORAGE_POLICY_DIGEST_FIELDS
        }
        control_probe = S3KmsProbe(
            storage,
            require_object_lock=require_object_lock,
            kms_client=boto3.client("kms", region_name=region),
            sts_client=boto3.client("sts", region_name=region),
            iam_client=boto3.client("iam", region_name=region),
            expected_account_id=account_id,
            expected_caller_arn=_required("SHADOW_S3_CONTROL_PLANE_CALLER_ARN"),
            expected_caller_trust_contract=target_profile[
                "s3_control_plane_caller_trust_contract"
            ],
            expected_kms_admin_role_arn=_required("SHADOW_KMS_ADMIN_ROLE_ARN"),
            expected_irsa_oidc_provider_arn=_required(
                "SHADOW_AWS_IRSA_OIDC_PROVIDER_ARN"
            ),
            expected_role_arns={
                "backup": _required("SHADOW_BACKUP_WORKLOAD_IDENTITY_ARN"),
                "snapshot": _required("SHADOW_SNAPSHOT_WORKLOAD_IDENTITY_ARN"),
            },
            expected_trust_subjects={
                "backup": (
                    f"system:serviceaccount:{plan.namespace}:shadow-backup-storage"
                ),
                "snapshot": (
                    f"system:serviceaccount:{plan.namespace}:shadow-simulator-storage"
                ),
            },
            expected_policy_digests=expected_policy_digests,
            expected_policy_bundle_digest=str(
                target_profile["aws_storage_policy_bundle_digest"]
            ),
            require_cloud_control_plane=True,
            lifecycle_prefixes={
                "acceptance": storage._key("production-probes").rstrip("/") + "/",
                "snapshot": snapshot_prefix,
                "backup": backup_prefix,
            },
            immutable_sentinel_keys={
                "backup": _required("SHADOW_BACKUP_FORBIDDEN_SENTINEL_KEY"),
                "snapshot": _required("SHADOW_SNAPSHOT_FORBIDDEN_SENTINEL_KEY"),
            },
            acceptance_run_id=_required("SHADOW_ACCEPTANCE_RUN_ID"),
            signed_target_profile_digest=_required(
                "SHADOW_PRODUCTION_ENVIRONMENT_DIGEST"
            ),
            mutation_confirmation=_required(
                "SHADOW_PRODUCTION_S3_CONTROL_PLANE_CONFIRMATION"
            ),
        )
        control_plane = control_probe.run()
        control_plane.verify()
        if control_plane.status != "PASSED" or control_plane.limitations:
            raise DomainError(
                "S3_CONTROL_PLANE_INVALID",
                "target-Pod probes require an unqualified S3/KMS control-plane PASS",
            )
        if set(control_probe.sentinel_bindings) != {"backup", "snapshot"}:
            raise DomainError(
                "S3_SENTINEL_BINDING_INVALID",
                "control plane did not bind both immutable cross-prefix sentinels",
            )
        workload_identity = run_kubernetes_storage_identity_probe(
            namespace=plan.namespace,
            context=context,
            candidate_image=plan.backend_image,
            bucket=bucket,
            region=region,
            prefixes={
                "acceptance": probe_prefix,
                "backup": backup_prefix,
                "snapshot": snapshot_prefix,
            },
            kms_key_arn=kms_key_id,
            account_id=account_id,
            expected_role_arns={
                "backup": _required("SHADOW_BACKUP_WORKLOAD_IDENTITY_ARN"),
                "snapshot": _required("SHADOW_SNAPSHOT_WORKLOAD_IDENTITY_ARN"),
            },
            immutable_sentinel_bindings=control_probe.sentinel_bindings,
            expected_cluster_uid_digest=cluster_uid_digest,
            expected_kubernetes_api_ca_digest=kubernetes_api_ca_digest,
            confirmation=_required(
                "SHADOW_PRODUCTION_S3_WORKLOAD_IDENTITY_CONFIRMATION"
            ),
            require_object_lock=require_object_lock,
        )
        workload_identity.verify()
        if workload_identity.status != "PASSED" or workload_identity.limitations:
            raise DomainError(
                "KUBERNETES_STORAGE_PROBE_EVIDENCE_INVALID",
                "both target-Pod workload identity probes must pass without limitations",
            )
        checks = [
            GateCheck("control_plane", control_plane.status == "PASSED"),
            *(
                GateCheck(f"control_{check.name}", check.passed, check.details)
                for check in control_plane.checks
            ),
        ]
        checks.append(
            GateCheck(
                "target_pod_workload_identities", workload_identity.status == "PASSED"
            )
        )
        checks.extend(
            (
                GateCheck("backup_identity", workload_identity.status == "PASSED"),
                GateCheck("snapshot_identity", workload_identity.status == "PASSED"),
            )
        )
        checks.extend(
            GateCheck(check.name, check.passed, check.details)
            for check in workload_identity.checks
        )
        sentinel_digests = {
            identity: binding.binding_digest
            for identity, binding in sorted(control_probe.sentinel_bindings.items())
        }
        return (
            complete(
                "s3",
                started_at=control_plane.started_at,
                coordinates={
                    "control_plane_target_digest": control_plane.target_digest,
                    "target_pod_identity_target_digest": workload_identity.target_digest,
                    "signed_target_profile_digest": _required(
                        "SHADOW_PRODUCTION_ENVIRONMENT_DIGEST"
                    ),
                    "backup_workload_identity_arn_digest": target_profile[
                        "backup_workload_identity_arn_digest"
                    ],
                    "snapshot_workload_identity_arn_digest": target_profile[
                        "snapshot_workload_identity_arn_digest"
                    ],
                    "aws_storage_policy_bundle_digest": target_profile[
                        "aws_storage_policy_bundle_digest"
                    ],
                    "sentinel_binding_digest": canonical_digest(sentinel_digests),
                },
                checks=checks,
                metrics={
                    **control_plane.metrics,
                    "workload_identities_verified": 2
                    if workload_identity.status == "PASSED"
                    else 0,
                    "target_pod_identities_verified": workload_identity.metrics.get(
                        "pods", 0
                    ),
                    "sentinel_bindings_verified": len(control_probe.sentinel_bindings),
                    "storage_binding_digest": storage_binding_digest,
                    "backup_sentinel_binding_digest": sentinel_digests["backup"],
                    "snapshot_sentinel_binding_digest": sentinel_digests["snapshot"],
                    "sentinel_binding_digest": canonical_digest(sentinel_digests),
                },
            ),
            None,
        )
    if name == "external_ca":
        probe = CertificateAuthorityProbe(
            server_certificate=_required("SHADOW_OPCUA_SERVER_CERTIFICATE"),
            client_certificate=_required("SHADOW_OPCUA_CLIENT_CERTIFICATE"),
            ca_bundle=_required("SHADOW_OPCUA_CA_BUNDLE"),
            crl_file=_required("SHADOW_OPCUA_CRL_FILE"),
            server_application_uri=_required("SHADOW_OPCUA_APPLICATION_URI"),
            client_application_uri=_required("SHADOW_OPCUA_CLIENT_APPLICATION_URI"),
            security_policy=_required("SHADOW_OPCUA_SECURITY_STRING").split(",", 1)[0],
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
        plan, _context, _cluster_uid, _api_ca = _deployment_binding()
        if plan.real_ot_runtime_binding_digest != _real_ot_probe_binding_digest():
            raise DomainError(
                "REAL_OT_BINDING_INVALID",
                "real-OT probe coordinates do not match the sealed Collector runtime binding",
            )
        binding = _config(_required("SHADOW_OPCUA_PROBE_CONFIG"))
        probe = ReadonlyOpcUaProbe(
            endpoint_uri=str(binding["endpoint_uri"]),
            application_uri=str(binding["application_uri"]),
            client_application_uri=str(binding["client_application_uri"]),
            namespace_uri=str(binding["namespace_uri"]),
            certificate_fingerprint=str(binding["certificate_fingerprint"]),
            client_certificate_fingerprint=str(
                binding["client_certificate_fingerprint"]
            ),
            next_client_certificate_fingerprint=_required(
                "SHADOW_NEXT_CLIENT_CERTIFICATE_FINGERPRINT"
            ),
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
        _validate_signed_identity_and_storage(_signed_target_profile())
        try:
            import boto3
        except ImportError as error:
            raise DomainError(
                "RDS_DEPENDENCY_UNAVAILABLE", "install the object-storage dependency"
            ) from error
        target_profile = _signed_target_profile()
        control_plane = AwsRdsControlPlaneProbe(
            _required("SHADOW_RESTORE_SOURCE_DATABASE_URL"),
            _required("SHADOW_RESTORE_TARGET_DATABASE_URL"),
            source_resource_arn=_required(
                "SHADOW_MANAGED_POSTGRESQL_SOURCE_RESOURCE_ARN"
            ),
            restore_resource_arn=_required(
                "SHADOW_MANAGED_POSTGRESQL_RESTORE_RESOURCE_ARN"
            ),
            expected_account_id=_required("SHADOW_AWS_ACCOUNT_ID"),
            expected_region=_required("SHADOW_OBJECT_STORAGE_REGION"),
            expected_source_resource_digest=str(
                target_profile["managed_postgresql_source_resource_digest"]
            ),
            expected_restore_resource_digest=str(
                target_profile["managed_postgresql_restore_resource_digest"]
            ),
            expected_source_coordinate_digest=str(
                target_profile["managed_postgresql_source_coordinate_digest"]
            ),
            expected_restore_coordinate_digest=str(
                target_profile["managed_postgresql_restore_coordinate_digest"]
            ),
            client=boto3.client(
                "rds", region_name=_required("SHADOW_OBJECT_STORAGE_REGION")
            ),
        ).run()
        signed_control_coordinates = {
            "source_kms_key_id_digest": "managed_postgresql_source_kms_key_digest",
            "restore_kms_key_id_digest": "managed_postgresql_restore_kms_key_digest",
            "source_ca_identifier_digest": "managed_postgresql_source_ca_identifier_digest",
            "restore_ca_identifier_digest": "managed_postgresql_restore_ca_identifier_digest",
        }
        control_plane_bound = control_plane.status == "PASSED" and all(
            control_plane.metrics.get(coordinate) == target_profile.get(profile_field)
            for coordinate, profile_field in signed_control_coordinates.items()
        )
        if not control_plane_bound:
            raise DomainError(
                "MANAGED_POSTGRESQL_TARGET_UNVERIFIED",
                "restore is forbidden until the live managed target matches the signed profile",
                status=503,
            )
        backup_storage = S3ObjectStorage(
            _required("SHADOW_OBJECT_STORAGE_BUCKET"),
            region=_required("SHADOW_OBJECT_STORAGE_REGION"),
            endpoint_url=os.environ.get("SHADOW_OBJECT_STORAGE_ENDPOINT"),
            prefix=_required("SHADOW_BACKUP_OBJECT_STORAGE_PREFIX"),
            kms_key_id=_required("SHADOW_OBJECT_STORAGE_KMS_KEY_ID"),
            kms_encryption_context={
                "application": "industrial-shadow",
                "purpose": "backup",
            },
        )
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
            managed_provider=str(target_profile["managed_postgresql_provider"]),
            managed_instance_digest=str(
                target_profile["managed_postgresql_restore_resource_digest"]
            ),
            require_managed_coordinates=True,
            object_storage=backup_storage,
            backup_receipt_path=_required("SHADOW_BACKUP_RESTORE_RECEIPT"),
            kms_key_id=_required("SHADOW_OBJECT_STORAGE_KMS_KEY_ID"),
            maximum_rpo_seconds=int(
                os.environ.get("SHADOW_RESTORE_MAXIMUM_RPO_SECONDS", "86400")
            ),
            require_immutable_backup=True,
        )
        restored = probe.run()
        immutable_backup_digest_fields = (
            "archive_version_digest",
            "manifest_version_digest",
            "sealed_receipt_version_digest",
            "archive_retention_digest",
            "manifest_retention_digest",
            "sealed_receipt_retention_digest",
        )
        immutable_backup_bound = bool(
            restored.status == "PASSED"
            and not restored.limitations
            and restored.metrics.get("object_lock_versions") == 3
            and restored.metrics.get("backup_receipt_digest")
            == target_profile["backup_restore_receipt_digest"]
            and all(
                isinstance(restored.metrics.get(name), str)
                and re.fullmatch(r"[a-f0-9]{64}", str(restored.metrics[name]))
                for name in immutable_backup_digest_fields
            )
        )
        checks = [
            GateCheck("managed_control_plane", control_plane.status == "PASSED"),
            *(
                GateCheck(f"managed_{check.name}", check.passed, check.details)
                for check in control_plane.checks
            ),
            GateCheck(
                "managed_signed_encryption_and_ca",
                control_plane_bound,
            ),
            GateCheck("restore_immutable_versions_bound", immutable_backup_bound),
            *(
                GateCheck(f"restore_{check.name}", check.passed, check.details)
                for check in restored.checks
            ),
        ]
        return (
            complete(
                "backup_restore",
                started_at=control_plane.started_at,
                coordinates={
                    "restore_gate_target_digest": restored.target_digest,
                    "managed_control_plane_target_digest": control_plane.target_digest,
                    "signed_target_profile_digest": _required(
                        "SHADOW_PRODUCTION_ENVIRONMENT_DIGEST"
                    ),
                    "managed_source_resource_digest": target_profile[
                        "managed_postgresql_source_resource_digest"
                    ],
                    "managed_restore_resource_digest": target_profile[
                        "managed_postgresql_restore_resource_digest"
                    ],
                    "backup_restore_receipt_digest": target_profile[
                        "backup_restore_receipt_digest"
                    ],
                    **{
                        name: restored.metrics[name]
                        for name in immutable_backup_digest_fields
                        if name in restored.metrics
                    },
                },
                checks=checks,
                metrics={
                    **restored.metrics,
                    "managed_resources": control_plane.metrics["resources"],
                },
            ),
            None,
        )
    if name == "network_policy":
        config = _config(_required("SHADOW_NETWORK_PROBE_CONFIG"))
        plan, context, cluster_uid_digest, api_ca_digest = _deployment_binding(
            "SHADOW_KUBERNETES_NETWORK_CONTEXT"
        )
        return run_kubernetes_policy_suite(
            namespace=str(config["namespace"]),
            probes=tuple(config["probes"]),
            policy_path=str(config["policy_path"]),
            confirmation=_required("SHADOW_PRODUCTION_NETWORK_PROBE_CONFIRMATION"),
            context=context,
            expected_cluster_uid_digest=cluster_uid_digest,
            expected_kubernetes_api_ca_digest=api_ca_digest,
            plan=plan,
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
        plan, context, cluster_uid_digest, api_ca_digest = _deployment_binding(
            "SHADOW_KUBERNETES_CHAOS_CONTEXT"
        )
        suite = KubernetesChaosSuite(
            str(config["namespace"]),
            _required("SHADOW_DRILL_DATABASE_URL"),
            confirmation=_required("SHADOW_PRODUCTION_CHAOS_CONFIRMATION"),
            context=context,
            expected_cluster_uid_digest=cluster_uid_digest,
            expected_kubernetes_api_ca_digest=api_ca_digest,
            plan=plan,
        )
        return suite.run(tuple(config["scenarios"])), None
    if name == "upgrade_rollback":
        config = _config(_required("SHADOW_KUBERNETES_DRILL_CONFIG"))
        plan, context, cluster_uid_digest, api_ca_digest = _deployment_binding(
            "SHADOW_KUBERNETES_ROLLBACK_CONTEXT"
        )
        drill = KubernetesDrill(
            str(config["namespace"]),
            str(config["deployment"]),
            str(config["container"]),
            str(config["readiness_url"]),
            str(config["web_readiness_url"]),
            _required("SHADOW_DRILL_DATABASE_URL"),
            confirmation=_required("SHADOW_PRODUCTION_DRILL_CONFIRMATION"),
            context=context,
            expected_cluster_uid_digest=cluster_uid_digest,
            expected_kubernetes_api_ca_digest=api_ca_digest,
            plan=plan,
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
            "supply_chain",
            "postgresql_migration",
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
