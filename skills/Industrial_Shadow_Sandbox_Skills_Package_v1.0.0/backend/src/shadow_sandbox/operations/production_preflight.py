from __future__ import annotations

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

from .evidence import GateCheck, GateEvidence, complete
from .production_deployment import ProductionDeploymentPlan
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
    "SHADOW_BUILD_DIGEST",
    "SHADOW_SIMULATOR_BUILD_DIGEST",
    "SHADOW_PRODUCTION_ENVIRONMENT_DIGEST",
    "SHADOW_DEPLOYMENT_PLAN_DIGEST",
    "SHADOW_PRODUCTION_DEPLOYMENT_PLAN",
    "SHADOW_ASSESSOR_TRUST_STORE",
    "SHADOW_OIDC_ISSUER",
    "SHADOW_OIDC_AUDIENCE",
    "SHADOW_OIDC_JWKS_URL",
    "SHADOW_OIDC_CLIENT_ID",
    "SHADOW_OIDC_AUTHORIZATION_URL",
    "SHADOW_OIDC_TOKEN_URL",
    "SHADOW_PRODUCTION_API_URL",
    "SHADOW_OIDC_PROBE_SECRETS_FILE",
    "SHADOW_OBJECT_STORAGE_BUCKET",
    "SHADOW_OBJECT_STORAGE_REGION",
    "SHADOW_OBJECT_STORAGE_KMS_KEY_ID",
    "SHADOW_AWS_ACCOUNT_ID",
    "SHADOW_REQUIRE_OBJECT_LOCK",
    "SHADOW_RESTORE_SOURCE_DATABASE_URL",
    "SHADOW_RESTORE_TARGET_DATABASE_URL",
    "SHADOW_RESTORE_APPLICATION_DATABASE_URL",
    "SHADOW_RESTORE_BACKUP_DATABASE_URL",
    "SHADOW_RESTORE_MAXIMUM_SECONDS",
    "SHADOW_RESTORE_MAXIMUM_ARCHIVE_BYTES",
    "SHADOW_MANAGED_POSTGRESQL_PROVIDER",
    "SHADOW_MANAGED_POSTGRESQL_INSTANCE_DIGEST",
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
    "SHADOW_OPCUA_SERVER_CERTIFICATE",
    "SHADOW_OPCUA_CLIENT_CERTIFICATE",
    "SHADOW_OPCUA_NEXT_SERVER_CERTIFICATE",
    "SHADOW_OPCUA_NEXT_CLIENT_CERTIFICATE",
    "SHADOW_OPCUA_CA_BUNDLE",
    "SHADOW_OPCUA_CRL_FILE",
)
SECRET_FILES = (
    "SHADOW_OIDC_PROBE_SECRETS_FILE",
    "SHADOW_LOAD_PROBE_SECRETS_FILE",
    "SHADOW_OPCUA_CLIENT_PRIVATE_KEY",
    "SHADOW_OPCUA_NEXT_CLIENT_PRIVATE_KEY",
    "SHADOW_DOCKER_SCOUT_CREDENTIALS_FILE",
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
    return parsed.scheme == "postgresql" and query.get("sslmode", [""])[0] in {
        "require",
        "verify-ca",
        "verify-full",
    }


def _release_digest(value: str) -> bool:
    return bool(DIGEST.fullmatch(value) and value != "0" * 64)


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
        files = [*CONFIG_PATHS, *PUBLIC_FILES, *SECRET_FILES, "SHADOW_ASSESSOR_TRUST_STORE"]
        existing_files = [name for name in files if Path(self._value(name)).is_file()]
        secret_modes = [
            stat.S_IMODE(Path(self._value(name)).stat().st_mode)
            for name in SECRET_FILES
            if Path(self._value(name)).is_file()
        ]
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
            trust_store = SignerTrustStore.load(self._value("SHADOW_ASSESSOR_TRUST_STORE"))
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
        deployment_plan: ProductionDeploymentPlan | None = None
        try:
            deployment_plan = ProductionDeploymentPlan.load(
                Path(__file__).resolve().parents[4],
                self._value("SHADOW_PRODUCTION_DEPLOYMENT_PLAN"),
                candidate_image=candidate,
                expected_digest=deployment_plan_digest,
            )
        except Exception:  # noqa: BLE001 - invalid deployment plans must fail preflight
            deployment_plan = None
        urls = (
            self._value("SHADOW_OIDC_ISSUER"),
            self._value("SHADOW_OIDC_JWKS_URL"),
            self._value("SHADOW_OIDC_AUTHORIZATION_URL"),
            self._value("SHADOW_OIDC_TOKEN_URL"),
            self._value("SHADOW_PRODUCTION_API_URL"),
            str(configs.get("SHADOW_LOAD_PROBE_CONFIG", {}).get("base_url", "")),
            str(configs.get("SHADOW_KUBERNETES_DRILL_CONFIG", {}).get("readiness_url", "")),
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
        policy_path = Path(str(network.get("policy_path", "")))
        policy_ready = policy_path.is_file() and not PLACEHOLDER.search(
            policy_path.read_text(encoding="utf-8") if policy_path.is_file() else ""
        )
        checks = (
            GateCheck("required_inputs", not missing, {"missing": len(missing)}),
            GateCheck("input_files", len(existing_files) == len(files), {"files": len(files)}),
            GateCheck(
                "secret_file_permissions",
                bool(secret_modes) and all(not mode & 0o077 for mode in secret_modes),
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
            GateCheck("https_endpoints", all(value.startswith("https://") for value in urls)),
            GateCheck("postgresql_tls", all(_postgres_tls(value) for value in database_urls)),
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
                and self._value("SHADOW_OBJECT_STORAGE_KMS_KEY_ID").startswith("arn:aws:kms:")
                and self._value("SHADOW_REQUIRE_OBJECT_LOCK") == "true",
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
                {"control-api", "action-executor", "collector"}.issubset(network_planes)
                and chaos_categories == {"api", "worker", "collector", "simulator"},
            ),
            GateCheck("production_network_policy_manifest", bool(policy_ready)),
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
                ),
            ),
            GateCheck(
                "required_binaries",
                all(
                    shutil.which(name)
                    for name in ("pg_dump", "pg_restore", "psql", "kubectl", "openssl")
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
                "trust_store_digest": trust_store.digest if trust_store else "invalid",
            },
            checks=checks,
            metrics={
                "required_inputs": len(REQUIRED_ENV),
                "config_files": len(configs),
                "network_planes": len(network_planes),
                "chaos_categories": len(chaos_categories),
            },
        )
