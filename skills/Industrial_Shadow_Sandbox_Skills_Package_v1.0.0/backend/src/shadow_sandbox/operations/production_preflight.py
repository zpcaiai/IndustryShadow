from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now
from shadow_sandbox.common.object_storage import validate_object_key
from shadow_sandbox.common.opcua_readonly import (
    normalize_opcua_fingerprint,
    normalize_opcua_security_string,
    opcua_runtime_binding_digest,
)
from shadow_sandbox.common.secure_files import read_private_file

from .backup_job import database_coordinate_digest
from .evidence import GateCheck, GateEvidence, complete
from .production_deployment import ProductionDeploymentPlan
from .restore_drill import BackupRestoreReceipt
from .storage_probe import s3_control_plane_mutation_confirmation
from .supply_chain import ReleaseCandidate
from .trust_store import SignerTrustStore

RELEASE_IMAGE = re.compile(r"^[^@\s]+@sha256:[a-f0-9]{64}$")
DIGEST = re.compile(r"^[a-f0-9]{64}$")
PLACEHOLDER = re.compile(
    r"(?:\.invalid\b|replace[-_ ]?with|change[-_ ]?me|example\.com|"
    r"\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.|(?:sha256:)?0{64}\b)",
    re.IGNORECASE,
)

REQUIRED_ENV = (
    "SHADOW_ACCEPTANCE_RUN_ID",
    "SHADOW_CANDIDATE_IMAGE",
    "SHADOW_WEB_CANDIDATE_IMAGE",
    "SHADOW_BUILD_DIGEST",
    "SHADOW_SIMULATOR_BUILD_DIGEST",
    "SHADOW_PRODUCTION_ENVIRONMENT_DIGEST",
    "SHADOW_DEPLOYMENT_PLAN_DIGEST",
    "SHADOW_RELEASE_CANDIDATE_MANIFEST",
    "SHADOW_RELEASE_CANDIDATE_BUNDLE",
    "SHADOW_RELEASE_SOURCE_REVISION",
    "SHADOW_RELEASE_REPOSITORY",
    "SHADOW_RELEASE_RUN_ID",
    "SHADOW_RELEASE_RUN_ATTEMPT",
    "SHADOW_POSTGRESQL_MIGRATION_MANIFEST",
    "SHADOW_POSTGRESQL_MIGRATION_DATABASES_FILE",
    "SHADOW_POSTGRESQL_MIGRATION_MAXIMUM_SECONDS",
    "SHADOW_POSTGRESQL_MIGRATION_MAXIMUM_ROWS",
    "SHADOW_PRODUCTION_DEPLOYMENT_PLAN",
    "SHADOW_KUBERNETES_NETWORK_CONTEXT",
    "SHADOW_KUBERNETES_STORAGE_CONTEXT",
    "SHADOW_KUBERNETES_CHAOS_CONTEXT",
    "SHADOW_KUBERNETES_ROLLBACK_CONTEXT",
    "SHADOW_ASSESSOR_TRUST_STORE",
    "SHADOW_ASSESSOR_TRUST_ROOT_ATTESTATION",
    "SHADOW_ASSESSOR_TRUST_ROOT_PUBLIC_KEY",
    "SHADOW_ASSESSOR_TRUST_ROOT_KEY_SHA256",
    "SHADOW_OIDC_ISSUER",
    "SHADOW_OIDC_AUDIENCE",
    "SHADOW_OIDC_JWKS_URL",
    "SHADOW_OIDC_CLIENT_ID",
    "SHADOW_OIDC_SERVICE_CLIENT_IDS",
    "SHADOW_OIDC_ID_TOKEN_SIGNING_ALGORITHMS",
    "SHADOW_OIDC_AUTHORIZATION_URL",
    "SHADOW_OIDC_TOKEN_URL",
    "SHADOW_OIDC_END_SESSION_URL",
    "SHADOW_PRODUCTION_API_URL",
    "SHADOW_PRODUCTION_WEB_URL",
    "SHADOW_OIDC_PROBE_SECRETS_FILE",
    "SHADOW_OIDC_BROWSER_SECRETS_FILE",
    "SHADOW_OIDC_BROWSER_JOURNEY",
    "SHADOW_OBJECT_STORAGE_BUCKET",
    "SHADOW_OBJECT_STORAGE_REGION",
    "SHADOW_OBJECT_STORAGE_PREFIX",
    "SHADOW_SNAPSHOT_OBJECT_STORAGE_PREFIX",
    "SHADOW_OBJECT_STORAGE_KMS_KEY_ID",
    "SHADOW_BACKUP_OBJECT_STORAGE_PREFIX",
    "SHADOW_AWS_ACCOUNT_ID",
    "SHADOW_REQUIRE_OBJECT_LOCK",
    "SHADOW_RESTORE_SOURCE_DATABASE_URL",
    "SHADOW_RESTORE_TARGET_DATABASE_URL",
    "SHADOW_RESTORE_APPLICATION_DATABASE_URL",
    "SHADOW_RESTORE_BACKUP_DATABASE_URL",
    "SHADOW_RESTORE_MAXIMUM_SECONDS",
    "SHADOW_RESTORE_MAXIMUM_ARCHIVE_BYTES",
    "SHADOW_RESTORE_MAXIMUM_RPO_SECONDS",
    "SHADOW_BACKUP_RESTORE_RECEIPT",
    "SHADOW_MANAGED_POSTGRESQL_PROVIDER",
    "SHADOW_MANAGED_POSTGRESQL_INSTANCE_DIGEST",
    "SHADOW_MANAGED_POSTGRESQL_SOURCE_RESOURCE_ARN",
    "SHADOW_MANAGED_POSTGRESQL_RESTORE_RESOURCE_ARN",
    "SHADOW_BACKUP_WORKLOAD_IDENTITY_ARN",
    "SHADOW_SNAPSHOT_WORKLOAD_IDENTITY_ARN",
    "SHADOW_PRODUCTION_S3_CONTROL_PLANE_CONFIRMATION",
    "SHADOW_PRODUCTION_S3_WORKLOAD_IDENTITY_CONFIRMATION",
    "SHADOW_BACKUP_FORBIDDEN_SENTINEL_KEY",
    "SHADOW_SNAPSHOT_FORBIDDEN_SENTINEL_KEY",
    "SHADOW_ALLOW_DESTRUCTIVE_RESTORE_DRILL",
    "SHADOW_DATABASE_TENANT_ROLES",
    "SHADOW_DATABASE_MAINTENANCE_ROLE",
    "SHADOW_DATABASE_BACKUP_ROLE",
    "SHADOW_OPCUA_SERVER_CERTIFICATE",
    "SHADOW_OPCUA_CLIENT_CERTIFICATE",
    "SHADOW_OPCUA_NEXT_SERVER_CERTIFICATE",
    "SHADOW_OPCUA_NEXT_CLIENT_CERTIFICATE",
    "SHADOW_OPCUA_CLIENT_PRIVATE_KEY",
    "SHADOW_OPCUA_NEXT_CLIENT_PRIVATE_KEY",
    "SHADOW_OPCUA_CA_BUNDLE",
    "SHADOW_OPCUA_CRL_FILE",
    "SHADOW_OPCUA_APPLICATION_URI",
    "SHADOW_OPCUA_CLIENT_APPLICATION_URI",
    "SHADOW_CERTIFICATE_FINGERPRINT",
    "SHADOW_CLIENT_CERTIFICATE_FINGERPRINT",
    "SHADOW_NEXT_SERVER_CERTIFICATE_FINGERPRINT",
    "SHADOW_NEXT_CLIENT_CERTIFICATE_FINGERPRINT",
    "SHADOW_OPCUA_SECURITY_STRING",
    "SHADOW_OPCUA_PROBE_CONFIG",
    "SHADOW_NETWORK_PROBE_CONFIG",
    "SHADOW_PRODUCTION_NETWORK_PROBE_CONFIRMATION",
    "SHADOW_LOAD_PROBE_CONFIG",
    "SHADOW_LOAD_PROBE_SECRETS_FILE",
    "SHADOW_KUBERNETES_DRILL_CONFIG",
    "SHADOW_CHAOS_DRILL_CONFIG",
    "SHADOW_DRILL_DATABASE_URL",
    "SHADOW_PRODUCTION_DRILL_CONFIRMATION",
    "SHADOW_PRODUCTION_CHAOS_CONFIRMATION",
    "SHADOW_FORMAL_BENCHMARK_REPORT",
    "SHADOW_SECURITY_ASSURANCE_REPORT",
    "SHADOW_PRIVACY_ASSURANCE_REPORT",
    "SHADOW_ACCESSIBILITY_ASSURANCE_REPORT",
    "SHADOW_DOCKER_SCOUT_CREDENTIALS_FILE",
    "SHADOW_IMAGE_REGISTRY_CREDENTIALS_FILE",
    "SHADOW_CONTAINER_SCAN_REPORT",
)
CONFIG_PATHS = (
    "SHADOW_OPCUA_PROBE_CONFIG",
    "SHADOW_NETWORK_PROBE_CONFIG",
    "SHADOW_LOAD_PROBE_CONFIG",
    "SHADOW_KUBERNETES_DRILL_CONFIG",
    "SHADOW_CHAOS_DRILL_CONFIG",
    "SHADOW_FORMAL_BENCHMARK_REPORT",
    "SHADOW_SECURITY_ASSURANCE_REPORT",
    "SHADOW_PRIVACY_ASSURANCE_REPORT",
    "SHADOW_ACCESSIBILITY_ASSURANCE_REPORT",
)
PUBLIC_FILES = (
    "SHADOW_RELEASE_CANDIDATE_MANIFEST",
    "SHADOW_RELEASE_CANDIDATE_BUNDLE",
    "SHADOW_POSTGRESQL_MIGRATION_MANIFEST",
    "SHADOW_ASSESSOR_TRUST_ROOT_ATTESTATION",
    "SHADOW_ASSESSOR_TRUST_ROOT_PUBLIC_KEY",
    "SHADOW_OPCUA_SERVER_CERTIFICATE",
    "SHADOW_OPCUA_CLIENT_CERTIFICATE",
    "SHADOW_OPCUA_NEXT_SERVER_CERTIFICATE",
    "SHADOW_OPCUA_NEXT_CLIENT_CERTIFICATE",
    "SHADOW_OPCUA_CA_BUNDLE",
    "SHADOW_OPCUA_CRL_FILE",
)
SECRET_FILES = (
    "SHADOW_OIDC_PROBE_SECRETS_FILE",
    "SHADOW_OIDC_BROWSER_SECRETS_FILE",
    "SHADOW_LOAD_PROBE_SECRETS_FILE",
    "SHADOW_OPCUA_CLIENT_PRIVATE_KEY",
    "SHADOW_OPCUA_NEXT_CLIENT_PRIVATE_KEY",
    "SHADOW_DOCKER_SCOUT_CREDENTIALS_FILE",
    "SHADOW_IMAGE_REGISTRY_CREDENTIALS_FILE",
    "SHADOW_POSTGRESQL_MIGRATION_DATABASES_FILE",
)


def _json_file(path: str) -> Mapping[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise DomainError("PREFLIGHT_CONFIG_INVALID", "production config must be an object")
    return value


def _postgres_tls(url: str) -> bool:
    normalized = url.replace("postgresql+psycopg://", "postgresql://", 1)
    parsed = urlsplit(normalized)
    query = parse_qs(parsed.query)
    return (
        parsed.scheme == "postgresql"
        and query.get("sslmode") == ["verify-full"]
        and len(query.get("sslrootcert", ())) == 1
        and bool(query["sslrootcert"][0].strip())
    )


def _release_digest(value: str) -> bool:
    return bool(DIGEST.fullmatch(value) and value != "0" * 64)


def validate_oidc_browser_journey_output_target(
    repository_root: Path,
    path_value: str,
    acceptance_run_id: str,
) -> bool:
    """Require a pristine, run-attempt-qualified output below web/test-results."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", acceptance_run_id):
        return False
    expected = Path(
        "web",
        "test-results",
        f"production-oidc-journey-{acceptance_run_id}.json",
    )
    raw = Path(path_value)
    if raw.is_absolute() or path_value != expected.as_posix():
        return False
    parent = repository_root / expected.parent
    if not parent.is_dir():
        return False
    cursor = repository_root
    for part in expected.parent.parts:
        cursor /= part
        if cursor.is_symlink():
            return False
    parent_stat = parent.lstat()
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.geteuid()
        or stat.S_IMODE(parent_stat.st_mode) != 0o700
    ):
        return False
    target = repository_root / expected
    return not target.exists() and not target.is_symlink()


def _docker_scout_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            ["docker", "scout", "version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and "version:" in result.stdout


class ProductionPreflight:
    """Non-mutating validation of the complete target acceptance input surface."""

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self.environment = dict(os.environ if environment is None else environment)

    def _value(self, name: str) -> str:
        return self.environment.get(name, "")

    def run(self) -> GateEvidence:
        started = utc_now()
        missing = [name for name in REQUIRED_ENV if not self._value(name)]
        repository_root = Path(__file__).resolve().parents[4]
        oidc_browser_journey_output_target_valid = validate_oidc_browser_journey_output_target(
            repository_root,
            self._value("SHADOW_OIDC_BROWSER_JOURNEY"),
            self._value("SHADOW_ACCEPTANCE_RUN_ID"),
        )
        files = [*CONFIG_PATHS, *PUBLIC_FILES, *SECRET_FILES, "SHADOW_ASSESSOR_TRUST_STORE"]
        public_file_names = [
            *CONFIG_PATHS,
            *PUBLIC_FILES,
            "SHADOW_ASSESSOR_TRUST_STORE",
        ]
        existing_files = [name for name in public_file_names if Path(self._value(name)).is_file()]
        secure_secret_files: list[str] = []
        for name in SECRET_FILES:
            try:
                read_private_file(
                    self._value(name),
                    code="PREFLIGHT_SECRET_FILE_INVALID",
                )
            except DomainError:
                continue
            secure_secret_files.append(name)
        existing_files.extend(secure_secret_files)
        configs: dict[str, Mapping[str, Any]] = {}
        placeholder_free = True
        try:
            for name in CONFIG_PATHS:
                if Path(self._value(name)).is_file():
                    configs[name] = _json_file(self._value(name))
                    placeholder_free = placeholder_free and not PLACEHOLDER.search(
                        json.dumps(configs[name], sort_keys=True)
                    )
        except (OSError, json.JSONDecodeError, DomainError):
            placeholder_free = False

        trust_store: SignerTrustStore | None = None
        try:
            trust_store = SignerTrustStore.load_verified(
                self._value("SHADOW_ASSESSOR_TRUST_STORE"),
                root_attestation_path=self._value("SHADOW_ASSESSOR_TRUST_ROOT_ATTESTATION"),
                root_public_key_path=self._value("SHADOW_ASSESSOR_TRUST_ROOT_PUBLIC_KEY"),
                expected_root_key_sha256=self._value("SHADOW_ASSESSOR_TRUST_ROOT_KEY_SHA256"),
            )
            placeholder_free = placeholder_free and not PLACEHOLDER.search(
                Path(self._value("SHADOW_ASSESSOR_TRUST_STORE")).read_text(encoding="utf-8")
            )
        except Exception:  # noqa: BLE001 - malformed trust input must fail closed
            trust_store = None
            placeholder_free = False

        candidate = self._value("SHADOW_CANDIDATE_IMAGE")
        build_digest = self._value("SHADOW_BUILD_DIGEST")
        simulator_digest = self._value("SHADOW_SIMULATOR_BUILD_DIGEST")
        environment_digest = self._value("SHADOW_PRODUCTION_ENVIRONMENT_DIGEST")
        deployment_plan_digest = self._value("SHADOW_DEPLOYMENT_PLAN_DIGEST")
        kubernetes_contexts = tuple(
            self._value(name)
            for name in (
                "SHADOW_KUBERNETES_NETWORK_CONTEXT",
                "SHADOW_KUBERNETES_STORAGE_CONTEXT",
                "SHADOW_KUBERNETES_CHAOS_CONTEXT",
                "SHADOW_KUBERNETES_ROLLBACK_CONTEXT",
            )
        )
        kubernetes_contexts_isolated = bool(
            len(set(kubernetes_contexts)) == 4
            and all(
                value
                and len(value) <= 253
                and not any(character.isspace() or ord(character) < 0x20 for character in value)
                for value in kubernetes_contexts
            )
        )
        deployment_plan: ProductionDeploymentPlan | None = None
        release_candidate: ReleaseCandidate | None = None
        backup_receipt: BackupRestoreReceipt | None = None
        target_profile: Mapping[str, Any] | None = None
        try:
            deployment_plan = ProductionDeploymentPlan.load(
                Path(__file__).resolve().parents[4],
                self._value("SHADOW_PRODUCTION_DEPLOYMENT_PLAN"),
                candidate_image=candidate,
                expected_digest=deployment_plan_digest,
            )
        except Exception:  # noqa: BLE001 - invalid deployment plans must fail preflight
            deployment_plan = None
        try:
            release_candidate = ReleaseCandidate.load(
                self._value("SHADOW_RELEASE_CANDIDATE_MANIFEST"),
                expected_repository=self._value("SHADOW_RELEASE_REPOSITORY"),
                expected_run_id=self._value("SHADOW_RELEASE_RUN_ID"),
                expected_run_attempt=int(self._value("SHADOW_RELEASE_RUN_ATTEMPT")),
            )
        except Exception:  # noqa: BLE001 - invalid release candidates fail preflight
            release_candidate = None
        try:
            backup_receipt = BackupRestoreReceipt.load(
                self._value("SHADOW_BACKUP_RESTORE_RECEIPT"),
                expected_source_database_digest=database_coordinate_digest(
                    self._value("SHADOW_RESTORE_SOURCE_DATABASE_URL")
                ),
            )
        except Exception:  # noqa: BLE001 - malformed restore receipts fail preflight
            backup_receipt = None
        workload_identity_probe_contract_valid = bool(
            deployment_plan is not None
            and self._value("SHADOW_PRODUCTION_S3_WORKLOAD_IDENTITY_CONFIRMATION")
            == f"{deployment_plan.namespace}:s3-workload-identity-probe"
            and validate_object_key(self._value("SHADOW_BACKUP_FORBIDDEN_SENTINEL_KEY"))
            == self._value("SHADOW_BACKUP_FORBIDDEN_SENTINEL_KEY")
            and validate_object_key(self._value("SHADOW_SNAPSHOT_FORBIDDEN_SENTINEL_KEY"))
            == self._value("SHADOW_SNAPSHOT_FORBIDDEN_SENTINEL_KEY")
        )
        try:
            benchmark = configs["SHADOW_FORMAL_BENCHMARK_REPORT"]
            target_records = [
                item
                for item in benchmark.get("artifacts", ())
                if isinstance(item, Mapping) and item.get("kind") == "target_profile"
            ]
            if (
                len(target_records) != 1
                or benchmark.get("target_profile_digest") != environment_digest
                or target_records[0].get("sha256") != environment_digest
            ):
                raise DomainError(
                    "PREFLIGHT_TARGET_PROFILE_INVALID",
                    "formal benchmark target profile binding is invalid",
                )
            repository_root = Path(__file__).resolve().parents[4]
            target_path = (repository_root / str(target_records[0].get("path", ""))).resolve(
                strict=True
            )
            if repository_root.resolve() not in target_path.parents or target_path.is_symlink():
                raise DomainError(
                    "PREFLIGHT_TARGET_PROFILE_INVALID", "target profile path is unsafe"
                )
            if hashlib.sha256(target_path.read_bytes()).hexdigest() != environment_digest:
                raise DomainError(
                    "PREFLIGHT_TARGET_PROFILE_INVALID", "target profile digest mismatch"
                )
            target_profile = _json_file(str(target_path))
        except Exception:  # noqa: BLE001 - target bindings must fail preflight closed
            target_profile = None
        try:
            s3_control_plane_mutation_authorized = bool(
                target_profile is not None
                and target_profile.get("s3_bucket") == self._value("SHADOW_OBJECT_STORAGE_BUCKET")
                and target_profile.get("s3_probe_prefix")
                == self._value("SHADOW_OBJECT_STORAGE_PREFIX")
                and self._value("SHADOW_PRODUCTION_S3_CONTROL_PLANE_CONFIRMATION")
                == s3_control_plane_mutation_confirmation(
                    bucket=self._value("SHADOW_OBJECT_STORAGE_BUCKET"),
                    prefix=self._value("SHADOW_OBJECT_STORAGE_PREFIX"),
                    acceptance_run_id=self._value("SHADOW_ACCEPTANCE_RUN_ID"),
                    signed_target_profile_digest=environment_digest,
                )
            )
        except DomainError:
            s3_control_plane_mutation_authorized = False
        real_ot_probe_binding_digest = ""
        try:
            ot_binding = configs["SHADOW_OPCUA_PROBE_CONFIG"]
            raw_node_ids = ot_binding.get("node_ids")
            if not isinstance(raw_node_ids, list) or any(
                not isinstance(item, str) for item in raw_node_ids
            ):
                raise DomainError(
                    "PREFLIGHT_OT_BINDING_INVALID",
                    "real-OT probe NodeId allowlist is invalid",
                )
            security_profile, _certificate_path, _key_path, _server_path = (
                normalize_opcua_security_string(
                    self._value("SHADOW_OPCUA_SECURITY_STRING"),
                    code="PREFLIGHT_OT_BINDING_INVALID",
                )
            )
            server_fingerprint = normalize_opcua_fingerprint(
                str(ot_binding.get("certificate_fingerprint", "")),
                code="PREFLIGHT_OT_BINDING_INVALID",
            )
            client_fingerprint = normalize_opcua_fingerprint(
                str(ot_binding.get("client_certificate_fingerprint", "")),
                code="PREFLIGHT_OT_BINDING_INVALID",
            )
            if (
                server_fingerprint
                != normalize_opcua_fingerprint(
                    self._value("SHADOW_CERTIFICATE_FINGERPRINT"),
                    code="PREFLIGHT_OT_BINDING_INVALID",
                )
                or client_fingerprint
                != normalize_opcua_fingerprint(
                    self._value("SHADOW_CLIENT_CERTIFICATE_FINGERPRINT"),
                    code="PREFLIGHT_OT_BINDING_INVALID",
                )
                or ot_binding.get("application_uri") != self._value("SHADOW_OPCUA_APPLICATION_URI")
                or ot_binding.get("client_application_uri")
                != self._value("SHADOW_OPCUA_CLIENT_APPLICATION_URI")
            ):
                raise DomainError(
                    "PREFLIGHT_OT_BINDING_INVALID",
                    "real-OT probe and external-CA coordinates must be identical",
                )
            real_ot_probe_binding_digest = opcua_runtime_binding_digest(
                endpoint_uri=str(ot_binding.get("endpoint_uri", "")),
                application_uri=str(ot_binding.get("application_uri", "")),
                client_application_uri=str(ot_binding.get("client_application_uri", "")),
                namespace_uri=str(ot_binding.get("namespace_uri", "")),
                server_certificate_fingerprint=server_fingerprint,
                client_certificate_fingerprint=client_fingerprint,
                next_client_certificate_fingerprint=self._value(
                    "SHADOW_NEXT_CLIENT_CERTIFICATE_FINGERPRINT"
                ),
                security_profile=security_profile,
                node_ids=tuple(raw_node_ids),
                code="PREFLIGHT_OT_BINDING_INVALID",
            )
        except Exception:  # noqa: BLE001 - OT coordinate drift must fail preflight closed
            real_ot_probe_binding_digest = ""
        urls = (
            self._value("SHADOW_OIDC_ISSUER"),
            self._value("SHADOW_OIDC_JWKS_URL"),
            self._value("SHADOW_OIDC_AUTHORIZATION_URL"),
            self._value("SHADOW_OIDC_TOKEN_URL"),
            self._value("SHADOW_OIDC_END_SESSION_URL"),
            self._value("SHADOW_PRODUCTION_API_URL"),
            self._value("SHADOW_PRODUCTION_WEB_URL"),
            str(configs.get("SHADOW_LOAD_PROBE_CONFIG", {}).get("base_url", "")),
            str(configs.get("SHADOW_KUBERNETES_DRILL_CONFIG", {}).get("readiness_url", "")),
            str(configs.get("SHADOW_KUBERNETES_DRILL_CONFIG", {}).get("web_readiness_url", "")),
        )
        endpoint_placeholders = any(PLACEHOLDER.search(value) for value in urls)
        database_urls = (
            self._value("SHADOW_RESTORE_SOURCE_DATABASE_URL"),
            self._value("SHADOW_RESTORE_TARGET_DATABASE_URL"),
            self._value("SHADOW_RESTORE_APPLICATION_DATABASE_URL"),
            self._value("SHADOW_RESTORE_BACKUP_DATABASE_URL"),
            self._value("SHADOW_DRILL_DATABASE_URL"),
        )
        network = configs.get("SHADOW_NETWORK_PROBE_CONFIG", {})
        chaos = configs.get("SHADOW_CHAOS_DRILL_CONFIG", {})
        rollback = configs.get("SHADOW_KUBERNETES_DRILL_CONFIG", {})
        network_planes = {
            str(item.get("plane", ""))
            for item in network.get("probes", ())
            if isinstance(item, Mapping)
        }
        chaos_categories = {
            str(item.get("category", ""))
            for item in chaos.get("scenarios", ())
            if isinstance(item, Mapping)
        }
        namespace = str(network.get("namespace", ""))
        chaos_namespace = str(chaos.get("namespace", ""))
        rollback_namespace = str(rollback.get("namespace", ""))
        rollback_deployment = str(rollback.get("deployment", ""))
        storage_prefixes = tuple(
            self._value(name)
            for name in (
                "SHADOW_OBJECT_STORAGE_PREFIX",
                "SHADOW_SNAPSHOT_OBJECT_STORAGE_PREFIX",
                "SHADOW_BACKUP_OBJECT_STORAGE_PREFIX",
            )
        )
        storage_segments = tuple(tuple(value.split("/")) for value in storage_prefixes)
        try:
            storage_prefixes_canonical = all(
                validate_object_key(value) == value for value in storage_prefixes
            )
        except DomainError:
            storage_prefixes_canonical = False
        storage_prefixes_isolated = (
            storage_prefixes_canonical
            and len(set(storage_prefixes)) == 3
            and not any(
                left == right[: len(left)] or right == left[: len(right)]
                for index, left in enumerate(storage_segments)
                for right in storage_segments[index + 1 :]
            )
        )
        policy_path = Path(str(network.get("policy_path", "")))
        policy_ready = policy_path.is_file() and not PLACEHOLDER.search(
            policy_path.read_text(encoding="utf-8") if policy_path.is_file() else ""
        )
        plan_binding_ready = (
            deployment_plan is not None
            and target_profile is not None
            and namespace == chaos_namespace == rollback_namespace == deployment_plan.namespace
            and policy_path.resolve() == deployment_plan.bootstrap_manifest.path
            and target_profile.get("snapshot_object_storage_prefix")
            == deployment_plan.snapshot_object_storage_prefix
            and target_profile.get("backup_object_storage_prefix")
            == deployment_plan.backup_object_storage_prefix
            and target_profile.get("snapshot_workload_identity_arn_digest")
            == deployment_plan.snapshot_workload_identity_arn_digest
            and target_profile.get("backup_workload_identity_arn_digest")
            == deployment_plan.backup_workload_identity_arn_digest
            and real_ot_probe_binding_digest == deployment_plan.real_ot_runtime_binding_digest
        )
        checks = (
            GateCheck("required_inputs", not missing, {"missing": len(missing)}),
            GateCheck("input_files", len(existing_files) == len(files), {"files": len(files)}),
            GateCheck(
                "oidc_browser_journey_output_target",
                oidc_browser_journey_output_target_valid,
            ),
            GateCheck(
                "secret_file_permissions",
                len(secure_secret_files) == len(SECRET_FILES),
            ),
            GateCheck(
                "no_placeholders",
                bool(configs) and placeholder_free and not endpoint_placeholders,
            ),
            GateCheck(
                "release_coordinates",
                bool(RELEASE_IMAGE.fullmatch(candidate))
                and not candidate.endswith("@sha256:" + "0" * 64)
                and _release_digest(build_digest)
                and _release_digest(simulator_digest)
                and _release_digest(environment_digest)
                and _release_digest(deployment_plan_digest),
            ),
            GateCheck(
                "deployment_plan",
                deployment_plan is not None,
                {"workloads": len(deployment_plan.workloads) if deployment_plan else 0},
            ),
            GateCheck(
                "kubernetes_probe_identities_isolated",
                kubernetes_contexts_isolated,
                {"contexts": len(set(kubernetes_contexts))},
            ),
            GateCheck(
                "release_candidate",
                release_candidate is not None
                and release_candidate.backend_image == candidate
                and release_candidate.web_image == self._value("SHADOW_WEB_CANDIDATE_IMAGE")
                and release_candidate.source_digest == build_digest
                and release_candidate.source_digest == simulator_digest
                and release_candidate.source_revision
                == self._value("SHADOW_RELEASE_SOURCE_REVISION")
                and deployment_plan is not None
                and deployment_plan.web_image == release_candidate.web_image
                and release_candidate.postgresql_migration_manifest.path
                == Path(self._value("SHADOW_POSTGRESQL_MIGRATION_MANIFEST")).resolve(),
            ),
            GateCheck("https_endpoints", all(value.startswith("https://") for value in urls)),
            GateCheck("postgresql_tls", all(_postgres_tls(value) for value in database_urls)),
            GateCheck(
                "immutable_backup_receipt",
                backup_receipt is not None
                and -300
                <= backup_receipt.age_seconds()
                <= int(self._value("SHADOW_RESTORE_MAXIMUM_RPO_SECONDS") or "0"),
            ),
            GateCheck(
                "restore_target_disposable",
                "restore_drill"
                in urlsplit(
                    self._value("SHADOW_RESTORE_TARGET_DATABASE_URL").replace(
                        "postgresql+psycopg://", "postgresql://", 1
                    )
                ).path
                and self._value("SHADOW_RESTORE_SOURCE_DATABASE_URL")
                != self._value("SHADOW_RESTORE_TARGET_DATABASE_URL"),
            ),
            GateCheck(
                "managed_postgresql_coordinates",
                self._value("SHADOW_MANAGED_POSTGRESQL_PROVIDER").lower()
                not in {"", "local", "localhost", "self-managed"}
                and bool(
                    DIGEST.fullmatch(self._value("SHADOW_MANAGED_POSTGRESQL_INSTANCE_DIGEST"))
                ),
            ),
            GateCheck(
                "aws_coordinates",
                bool(re.fullmatch(r"\d{12}", self._value("SHADOW_AWS_ACCOUNT_ID")))
                and bool(
                    re.fullmatch(
                        rf"arn:(?:aws|aws-us-gov|aws-cn):kms:"
                        rf"{re.escape(self._value('SHADOW_OBJECT_STORAGE_REGION'))}:"
                        rf"{re.escape(self._value('SHADOW_AWS_ACCOUNT_ID'))}:key/[A-Za-z0-9/_-]+",
                        self._value("SHADOW_OBJECT_STORAGE_KMS_KEY_ID"),
                    )
                )
                and self._value("SHADOW_REQUIRE_OBJECT_LOCK") == "true"
                and not self._value("SHADOW_OBJECT_STORAGE_ENDPOINT"),
            ),
            GateCheck(
                "storage_prefix_isolation",
                storage_prefixes_isolated
                and self._value("SHADOW_BACKUP_WORKLOAD_IDENTITY_ARN")
                != self._value("SHADOW_SNAPSHOT_WORKLOAD_IDENTITY_ARN"),
            ),
            GateCheck(
                "s3_control_plane_mutation_authorization",
                s3_control_plane_mutation_authorized,
            ),
            GateCheck(
                "signed_cloud_coordinates",
                target_profile is not None
                and target_profile.get("candidate_image") == candidate
                and target_profile.get("build_digest") == build_digest
                and target_profile.get("simulator_build_digest") == simulator_digest
                and target_profile.get("deployment_plan_digest") == deployment_plan_digest
                and target_profile.get("aws_account_id") == self._value("SHADOW_AWS_ACCOUNT_ID")
                and target_profile.get("aws_region") == self._value("SHADOW_OBJECT_STORAGE_REGION")
                and target_profile.get("s3_bucket") == self._value("SHADOW_OBJECT_STORAGE_BUCKET")
                and target_profile.get("s3_probe_prefix")
                == self._value("SHADOW_OBJECT_STORAGE_PREFIX")
                and target_profile.get("snapshot_object_storage_prefix")
                == self._value("SHADOW_SNAPSHOT_OBJECT_STORAGE_PREFIX")
                and target_profile.get("backup_object_storage_prefix")
                == self._value("SHADOW_BACKUP_OBJECT_STORAGE_PREFIX")
                and target_profile.get("kms_key_id_digest")
                == canonical_digest({"kms_key_id": self._value("SHADOW_OBJECT_STORAGE_KMS_KEY_ID")})
                and target_profile.get("backup_workload_identity_arn_digest")
                == canonical_digest(
                    {"workload_identity_arn": self._value("SHADOW_BACKUP_WORKLOAD_IDENTITY_ARN")}
                )
                and target_profile.get("snapshot_workload_identity_arn_digest")
                == canonical_digest(
                    {"workload_identity_arn": self._value("SHADOW_SNAPSHOT_WORKLOAD_IDENTITY_ARN")}
                )
                and backup_receipt is not None
                and target_profile.get("backup_restore_receipt_digest")
                == backup_receipt.receipt_digest
                and target_profile.get("oidc_issuer")
                == self._value("SHADOW_OIDC_ISSUER").rstrip("/")
                and target_profile.get("oidc_audience_digest")
                == canonical_digest({"audience": self._value("SHADOW_OIDC_AUDIENCE")})
                and target_profile.get("oidc_human_client_id_digest")
                == canonical_digest({"client_id": self._value("SHADOW_OIDC_CLIENT_ID")})
                and target_profile.get("oidc_service_client_ids_digest")
                == canonical_digest(
                    sorted(
                        item.strip()
                        for item in self._value("SHADOW_OIDC_SERVICE_CLIENT_IDS").split(",")
                        if item.strip()
                    )
                )
                and target_profile.get("managed_postgresql_provider")
                == self._value("SHADOW_MANAGED_POSTGRESQL_PROVIDER")
                and target_profile.get("managed_postgresql_source_resource_digest")
                == canonical_digest(
                    {
                        "provider": "aws-rds",
                        "resource_arn": self._value(
                            "SHADOW_MANAGED_POSTGRESQL_SOURCE_RESOURCE_ARN"
                        ),
                    }
                )
                and target_profile.get("managed_postgresql_restore_resource_digest")
                == canonical_digest(
                    {
                        "provider": "aws-rds",
                        "resource_arn": self._value(
                            "SHADOW_MANAGED_POSTGRESQL_RESTORE_RESOURCE_ARN"
                        ),
                    }
                ),
            ),
            GateCheck(
                "target_pod_workload_identity_contract",
                workload_identity_probe_contract_valid
                and self._value("SHADOW_BACKUP_FORBIDDEN_SENTINEL_KEY").startswith(
                    self._value("SHADOW_SNAPSHOT_OBJECT_STORAGE_PREFIX").rstrip("/") + "/"
                )
                and self._value("SHADOW_SNAPSHOT_FORBIDDEN_SENTINEL_KEY").startswith(
                    self._value("SHADOW_BACKUP_OBJECT_STORAGE_PREFIX").rstrip("/") + "/"
                ),
            ),
            GateCheck(
                "certificate_fingerprints",
                all(
                    bool(DIGEST.fullmatch(self._value(name).replace(":", "").lower()))
                    for name in (
                        "SHADOW_CERTIFICATE_FINGERPRINT",
                        "SHADOW_CLIENT_CERTIFICATE_FINGERPRINT",
                        "SHADOW_NEXT_SERVER_CERTIFICATE_FINGERPRINT",
                        "SHADOW_NEXT_CLIENT_CERTIFICATE_FINGERPRINT",
                    )
                ),
            ),
            GateCheck(
                "destructive_confirmations",
                self._value("SHADOW_ALLOW_DESTRUCTIVE_RESTORE_DRILL") == "true"
                and self._value("SHADOW_PRODUCTION_NETWORK_PROBE_CONFIRMATION")
                == f"{namespace}:network-policy"
                and self._value("SHADOW_PRODUCTION_CHAOS_CONFIRMATION")
                == f"{chaos_namespace}:chaos"
                and self._value("SHADOW_PRODUCTION_DRILL_CONFIRMATION")
                == f"{rollback_namespace}:{rollback_deployment}",
            ),
            GateCheck(
                "probe_coverage",
                {
                    "control-api",
                    "action-executor",
                    "real-ot-collector",
                    "simulator-collector",
                }.issubset(network_planes)
                and chaos_categories == {"api", "worker", "collector", "simulator"},
            ),
            GateCheck("production_network_policy_manifest", bool(policy_ready)),
            GateCheck("kubernetes_plan_binding", plan_binding_ready),
            GateCheck(
                "trusted_signer_coverage",
                trust_store is not None
                and trust_store.required_purposes_present(
                    (
                        "security_assessment",
                        "privacy_assessment",
                        "accessibility_assessment",
                        "formal_measurement",
                        "closure_release_owner",
                        "closure_security_owner",
                    )
                )
                and trust_store.purposes_have_distinct_keys(
                    ("closure_release_owner", "closure_security_owner")
                ),
            ),
            GateCheck(
                "required_binaries",
                all(
                    shutil.which(name)
                    for name in ("pg_dump", "pg_restore", "psql", "kubectl", "openssl", "gh")
                )
                and _docker_scout_available(),
            ),
        )
        return complete(
            "preflight",
            started_at=started,
            coordinates={
                "input_contract_digest": canonical_digest(sorted(REQUIRED_ENV)),
                "config_digests": {
                    name: canonical_digest(value) for name, value in sorted(configs.items())
                },
                "oidc_browser_journey_target_digest": canonical_digest(
                    {
                        "acceptance_run_id": self._value("SHADOW_ACCEPTANCE_RUN_ID"),
                        "path": self._value("SHADOW_OIDC_BROWSER_JOURNEY"),
                    }
                ),
                "trust_store_digest": trust_store.digest if trust_store else "invalid",
            },
            checks=checks,
            metrics={
                "required_inputs": len(REQUIRED_ENV),
                "config_files": len(configs),
                "oidc_browser_journey_output_targets": 1,
                "network_planes": len(network_planes),
                "chaos_categories": len(chaos_categories),
            },
        )
