from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

import yaml  # pyright: ignore[reportMissingModuleSource]

from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now
from shadow_sandbox.common.opcua_readonly import (
    opcua_node_allowlist_digest,
    opcua_runtime_binding_digest,
    validate_collector_node_allowlist,
)

from .evidence import GateCheck, GateEvidence, complete

IMAGE_DIGEST = re.compile(r"^[^@\s]+@sha256:[a-f0-9]{64}$")
DIGEST = re.compile(r"^[a-f0-9]{64}$")
KUBERNETES_NAME = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
PLACEHOLDER = re.compile(
    r"(?:\.invalid\b|\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\."
    r"|sha256:0{64}\b)",
    re.IGNORECASE,
)
OBJECT_STORAGE_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")
PLAN_KEYS = frozenset(
    {
        "schema_version",
        "plan_id",
        "namespace",
        "backend_image",
        "web_image",
        "bootstrap_manifest",
        "migration_manifest",
        "runtime_manifest",
        "rollback_manifest",
        "migration_job",
        "workloads",
        "digest",
    }
)
MANIFEST_KEYS = frozenset({"path", "sha256"})
WORKLOAD_KEYS = frozenset({"kind", "name", "container", "image", "readiness_url"})
EXPECTED_WORKLOADS = frozenset(
    {
        ("deployment", "control-api", "api", "backend"),
        ("deployment", "worker", "worker", "backend"),
        ("deployment", "action-executor", "action-executor", "backend"),
        ("statefulset", "simulator", "simulator", "backend"),
        ("deployment", "real-ot-collector", "real-ot-collector", "backend"),
        ("deployment", "simulator-collector", "simulator-collector", "backend"),
        ("deployment", "web", "web", "web"),
    }
)
PHASE_KINDS = {
    "bootstrap_manifest": frozenset(
        {"ConfigMap", "ServiceAccount", "Service", "NetworkPolicy", "CronJob"}
    ),
    "migration_manifest": frozenset({"Job"}),
    "runtime_manifest": frozenset({"Deployment", "StatefulSet", "Service"}),
    "rollback_manifest": frozenset(
        {
            "ConfigMap",
            "ServiceAccount",
            "Service",
            "NetworkPolicy",
            "CronJob",
            "Deployment",
            "StatefulSet",
        }
    ),
}
POD_KINDS = frozenset({"Deployment", "StatefulSet", "Job", "CronJob"})
SYSTEM_NAMESPACES = frozenset({"default", "kube-system", "kube-public", "kube-node-lease"})
EXPECTED_SERVICE_ACCOUNTS = {
    "control-api": "shadow-control-api",
    "worker": "shadow-worker",
    "action-executor": "shadow-action-executor",
    "simulator": "shadow-simulator-storage",
    "real-ot-collector": "shadow-real-ot-collector",
    "simulator-collector": "shadow-simulator-collector",
    "web": "shadow-web",
    "shadow-migrate": "shadow-migration",
    "shadow-postgres-backup": "shadow-backup-storage",
}
TOKEN_SERVICE_ACCOUNTS = frozenset({"shadow-simulator-storage", "shadow-backup-storage"})
STORAGE_SERVICE_ACCOUNTS = {
    "snapshot": "shadow-simulator-storage",
    "backup": "shadow-backup-storage",
}
WORKLOAD_IDENTITY_ANNOTATION = "eks.amazonaws.com/role-arn"
IAM_ROLE_ARN = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]+$"
)
EXPECTED_ARGS: dict[str, tuple[str, ...]] = {
    "control-api": (
        "uvicorn",
        "shadow_sandbox.main:create_app",
        "--factory",
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
        "--proxy-headers",
    ),
    "worker": ("python", "-m", "shadow_sandbox.worker"),
    "action-executor": (
        "uvicorn",
        "shadow_sandbox.action_api:create_app",
        "--factory",
        "--host",
        "0.0.0.0",
        "--port",
        "8020",
    ),
    "simulator": (
        "uvicorn",
        "shadow_simulator.api:create_app",
        "--factory",
        "--host",
        "0.0.0.0",
        "--port",
        "8010",
    ),
    "real-ot-collector": ("python", "-m", "shadow_collector.runner"),
    "simulator-collector": ("python", "-m", "shadow_collector.runner"),
    "web": (),
    "shadow-migrate": ("python", "-m", "shadow_sandbox.operations.database_roles"),
    "shadow-postgres-backup": ("python", "-m", "shadow_sandbox.operations.backup_job"),
}
EXPECTED_ENV_FROM: dict[str, frozenset[tuple[str, str]]] = {
    "control-api": frozenset(
        {
            ("configMapRef", "shadow-runtime"),
            ("configMapRef", "shadow-release-coordinates"),
        }
    ),
    "worker": frozenset(
        {
            ("configMapRef", "shadow-runtime"),
            ("configMapRef", "shadow-release-coordinates"),
        }
    ),
    "action-executor": frozenset(
        {
            ("configMapRef", "shadow-runtime"),
            ("configMapRef", "shadow-release-coordinates"),
        }
    ),
    "simulator": frozenset(
        {
            ("configMapRef", "shadow-runtime"),
            ("configMapRef", "shadow-release-coordinates"),
        }
    ),
    "real-ot-collector": frozenset(
        {
            ("configMapRef", "shadow-runtime"),
            ("configMapRef", "shadow-real-ot-collector-binding"),
        }
    ),
    "simulator-collector": frozenset(
        {
            ("configMapRef", "shadow-runtime"),
            ("configMapRef", "shadow-simulator-collector-binding"),
        }
    ),
    "web": frozenset(),
    "shadow-migrate": frozenset({("configMapRef", "shadow-database-roles")}),
    "shadow-postgres-backup": frozenset({("configMapRef", "shadow-runtime")}),
}
EXPECTED_SECRET_VOLUMES: dict[str, frozenset[str]] = {
    "control-api": frozenset(),
    "worker": frozenset(),
    "action-executor": frozenset(),
    "simulator": frozenset({"shadow-simulator-pki"}),
    "real-ot-collector": frozenset(
        {"shadow-real-ot-collector-pki-current", "shadow-real-ot-collector-pki-next"}
    ),
    "simulator-collector": frozenset(
        {"shadow-simulator-collector-pki-current", "shadow-simulator-collector-pki-next"}
    ),
    "web": frozenset(),
    "shadow-migrate": frozenset(),
    "shadow-postgres-backup": frozenset(),
}
EXPECTED_LITERAL_ENV: dict[str, Mapping[str, str]] = {
    **{name: {} for name in EXPECTED_ARGS},
    "simulator": {
        "SHADOW_DATABASE_PATH": "/var/lib/shadow/simulator.db",
        "SHADOW_OPCUA_CERTIFICATE_PATH": "/var/run/shadow-pki/server.crt",
        "SHADOW_OPCUA_PRIVATE_KEY_PATH": "/var/run/shadow-pki/server.key",
    },
}
EXPECTED_SECRET_ENV: dict[str, Mapping[str, tuple[str, str]]] = {
    "control-api": {
        "SHADOW_DATABASE_URL": ("shadow-api-secrets", "SHADOW_DATABASE_URL"),
        "SHADOW_INTERNAL_SERVICE_TOKEN": (
            "shadow-api-secrets",
            "SHADOW_INTERNAL_SERVICE_TOKEN",
        ),
    },
    "worker": {
        "SHADOW_DATABASE_URL": ("shadow-worker-secrets", "SHADOW_DATABASE_URL"),
    },
    "action-executor": {
        "SHADOW_DATABASE_URL": ("shadow-action-secrets", "SHADOW_DATABASE_URL"),
        "SHADOW_INTERNAL_SERVICE_TOKEN": (
            "shadow-action-secrets",
            "SHADOW_INTERNAL_SERVICE_TOKEN",
        ),
    },
    "simulator": {
        "SHADOW_INTERNAL_SERVICE_TOKEN": (
            "shadow-simulator-secrets",
            "SHADOW_INTERNAL_SERVICE_TOKEN",
        ),
    },
    "real-ot-collector": {
        "SHADOW_DATABASE_URL": (
            "shadow-real-ot-collector-secrets",
            "SHADOW_DATABASE_URL",
        ),
    },
    "simulator-collector": {
        "SHADOW_DATABASE_URL": (
            "shadow-simulator-collector-secrets",
            "SHADOW_DATABASE_URL",
        ),
    },
    "web": {},
    "shadow-migrate": {
        "SHADOW_DATABASE_URL": ("shadow-migration-secrets", "SHADOW_DATABASE_URL"),
    },
    "shadow-postgres-backup": {
        "SHADOW_DATABASE_URL": ("shadow-backup-secrets", "SHADOW_DATABASE_URL"),
    },
}
EXPECTED_SERVICES: dict[str, tuple[Mapping[str, str], tuple[tuple[str, int, str], ...]]] = {
    "control-api": ({"app": "control-api"}, (("http", 8000, "http"),)),
    "action-executor": ({"app": "action-executor"}, (("http", 8020, "http"),)),
    "simulator": ({"app": "simulator"}, (("http", 8010, "http"), ("opcua", 4840, "opcua"))),
    "web": ({"app": "web"}, (("http", 80, "http"),)),
}
EXPECTED_WORKLOAD_LABELS: dict[str, Mapping[str, str]] = {
    "control-api": {"app": "control-api", "plane": "control"},
    "worker": {"app": "worker", "plane": "data"},
    "action-executor": {"app": "action-executor", "plane": "action"},
    "simulator": {"app": "simulator", "plane": "simulator"},
    "real-ot-collector": {
        "app": "real-ot-collector",
        "plane": "collector",
        "collector-target": "real-ot",
    },
    "simulator-collector": {
        "app": "simulator-collector",
        "plane": "collector",
        "collector-target": "simulator",
    },
    "web": {"app": "web", "plane": "ingress"},
}
EXPECTED_NETWORK_POLICIES = frozenset(
    {
        "default-deny",
        "dns-egress",
        "web-ingress-and-api",
        "control-api-ingress",
        "action-plane",
        "simulator-plane",
        "real-ot-collector-read-only-egress",
        "simulator-collector-read-only-egress",
        "data-jobs-egress",
    }
)
PUBLISH_RBAC = frozenset(
    (group, resource, verb)
    for group, resource, verbs in (
        ("apps", "deployments", ("get", "list", "watch", "create", "patch")),
        ("apps", "statefulsets", ("get", "list", "watch", "create", "patch")),
        ("apps", "replicasets", ("get", "list")),
        ("batch", "jobs", ("get", "list", "watch", "create", "patch", "delete")),
        ("batch", "cronjobs", ("get", "create", "patch")),
        ("", "pods", ("get", "list", "watch")),
        ("", "configmaps", ("get", "create", "patch")),
        ("", "services", ("get", "create", "patch")),
        ("", "serviceaccounts", ("get", "create", "patch")),
        ("networking.k8s.io", "networkpolicies", ("get", "create", "patch")),
    )
    for verb in verbs
)

CommandRunner = Callable[[Sequence[str], int], str]
ReadinessProbe = Callable[[str], bool]


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def _safe_context(value: str) -> str:
    if not value or len(value) > 253 or any(character.isspace() for character in value):
        raise DomainError(
            "KUBERNETES_CONTEXT_INVALID", "an explicit Kubernetes context is required"
        )
    return value


def _repository_file(root: Path, value: str | Path, code: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        raise DomainError(code, "repository artifact path is unsafe")
    current = root
    for part in candidate.parts:
        current = current / part
        if current.is_symlink():
            raise DomainError(code, "repository artifact path contains a symlink")
    resolved = current.resolve(strict=True)
    if root not in resolved.parents or not resolved.is_file():
        raise DomainError(code, "repository artifact is outside the repository")
    return resolved


def cluster_identity(runner: CommandRunner, context: str) -> tuple[str, str]:
    """Return a privacy-safe identity derived from immutable cluster coordinates."""
    context = _safe_context(context)
    namespace = json.loads(
        runner(
            ("kubectl", "--context", context, "get", "namespace", "kube-system", "-o", "json"), 60
        )
    )
    namespace_uid = str(namespace.get("metadata", {}).get("uid", ""))
    config = json.loads(
        runner(
            ("kubectl", "--context", context, "config", "view", "--raw", "--minify", "-o", "json"),
            60,
        )
    )
    clusters = config.get("clusters", ())
    if not namespace_uid or not isinstance(clusters, list) or len(clusters) != 1:
        raise DomainError("KUBERNETES_CLUSTER_IDENTITY_INVALID", "cluster identity is incomplete")
    cluster = clusters[0].get("cluster", {}) if isinstance(clusters[0], Mapping) else {}
    if not isinstance(cluster, Mapping) or cluster.get("insecure-skip-tls-verify") is True:
        raise DomainError(
            "KUBERNETES_CLUSTER_IDENTITY_INVALID", "verified API server TLS is required"
        )
    encoded = str(cluster.get("certificate-authority-data", ""))
    ca_path = str(cluster.get("certificate-authority", ""))
    try:
        if encoded:
            ca_bytes = base64.b64decode(encoded, validate=True)
        elif ca_path:
            resolved = Path(ca_path).resolve(strict=True)
            if resolved.is_symlink() or not resolved.is_file():
                raise OSError("unsafe CA path")
            ca_bytes = resolved.read_bytes()
        else:
            raise ValueError("missing CA")
    except (OSError, ValueError) as error:
        raise DomainError(
            "KUBERNETES_CLUSTER_IDENTITY_INVALID", "API server CA is unavailable"
        ) from error
    if not ca_bytes or not str(cluster.get("server", "")).startswith("https://"):
        raise DomainError(
            "KUBERNETES_CLUSTER_IDENTITY_INVALID", "API server coordinates are invalid"
        )
    ca_digest = hashlib.sha256(ca_bytes).hexdigest()
    identity = canonical_digest(
        {"api_server_ca_sha256": ca_digest, "kube_system_namespace_uid": namespace_uid}
    )
    return identity, ca_digest


def validate_exact_rbac(
    payload: Mapping[str, Any], expected: frozenset[tuple[str, str, str]]
) -> bool:
    if payload.get("kind") == "SelfSubjectRulesReview":
        if payload.get("apiVersion") != "authorization.k8s.io/v1":
            return False
        status = payload.get("status")
        if not isinstance(status, Mapping):
            return False
        payload = status
    if payload.get("incomplete") is True or payload.get("evaluationError"):
        return False
    if payload.get("nonResourceRules") not in (None, []):
        return False
    observed: set[tuple[str, str, str]] = set()
    rules = payload.get("resourceRules")
    if not isinstance(rules, list):
        return False
    for rule in rules:
        if not isinstance(rule, Mapping) or rule.get("resourceNames") not in (None, []):
            return False
        groups = rule.get("apiGroups", [])
        resources = rule.get("resources", [])
        verbs = rule.get("verbs", [])
        if not all(isinstance(item, list) and item for item in (groups, resources, verbs)):
            return False
        if "*" in (*groups, *resources, *verbs) or any(
            verb in {"impersonate", "escalate", "bind"} for verb in verbs
        ):
            return False
        observed.update(
            (str(group), str(resource), str(verb))
            for group in groups
            for resource in resources
            for verb in verbs
        )
    return observed == set(expected)


def _manifest_objects(text: str) -> list[Mapping[str, Any]]:
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as error:
        raise DomainError(
            "DEPLOYMENT_ARTIFACT_INVALID", "deployment artifact is not valid YAML"
        ) from error
    objects: list[Mapping[str, Any]] = []

    def append(value: Any) -> None:
        if not isinstance(value, Mapping):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_INVALID",
                "deployment artifact contains an invalid Kubernetes object",
            )
        if value.get("kind") == "List":
            items = value.get("items")
            if not isinstance(items, list) or not items:
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_INVALID",
                    "Kubernetes List artifacts require non-empty items",
                )
            for item in items:
                append(item)
            return
        objects.append(value)

    for document in documents:
        if document is not None:
            append(document)
    if not objects:
        raise DomainError("DEPLOYMENT_ARTIFACT_INVALID", "deployment artifact contains no objects")
    return objects


def _pod_spec(value: Mapping[str, Any]) -> Mapping[str, Any] | None:
    kind = value.get("kind")
    spec = value.get("spec")
    if not isinstance(spec, Mapping):
        return None
    if kind in {"Deployment", "StatefulSet", "Job"}:
        template = spec.get("template")
    elif kind == "CronJob":
        job_template = spec.get("jobTemplate")
        job_spec = job_template.get("spec") if isinstance(job_template, Mapping) else None
        template = job_spec.get("template") if isinstance(job_spec, Mapping) else None
    else:
        return None
    template_spec = template.get("spec") if isinstance(template, Mapping) else None
    return template_spec if isinstance(template_spec, Mapping) else None


def _pod_name(value: Mapping[str, Any]) -> str:
    metadata = value.get("metadata")
    return str(metadata.get("name", "")) if isinstance(metadata, Mapping) else ""


def _references(value: Any) -> frozenset[tuple[str, str]]:
    if value in (None, []):
        return frozenset()
    if not isinstance(value, list):
        raise DomainError("DEPLOYMENT_ARTIFACT_INVALID", "environment references are invalid")
    references: set[tuple[str, str]] = set()
    for item in value:
        if not isinstance(item, Mapping) or len(item) != 1:
            raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "environment references must be exact")
        kind, target = next(iter(item.items()))
        if (
            kind not in {"configMapRef", "secretRef"}
            or not isinstance(target, Mapping)
            or set(target) != {"name"}
        ):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_UNSAFE", "arbitrary environment references are forbidden"
            )
        references.add((str(kind), str(target["name"])))
    if len(references) != len(value):
        raise DomainError(
            "DEPLOYMENT_ARTIFACT_UNSAFE", "duplicate environment references are forbidden"
        )
    return frozenset(references)


def _validate_pod_security(value: Mapping[str, Any], allowed_images: frozenset[str] | None) -> None:
    pod_spec = _pod_spec(value)
    if pod_spec is None:
        raise DomainError("DEPLOYMENT_ARTIFACT_INVALID", "workload Pod specification is missing")
    workload_name = _pod_name(value)
    contract_name = "shadow-migrate" if value.get("kind") == "Job" else workload_name
    expected_account = EXPECTED_SERVICE_ACCOUNTS.get(contract_name)
    if expected_account is None or pod_spec.get("serviceAccountName") != expected_account:
        raise DomainError(
            "DEPLOYMENT_ARTIFACT_UNSAFE",
            "every workload must use its exact dedicated ServiceAccount",
        )
    expected_token = expected_account in TOKEN_SERVICE_ACCOUNTS
    if pod_spec.get("automountServiceAccountToken") is not expected_token:
        raise DomainError(
            "DEPLOYMENT_ARTIFACT_UNSAFE",
            "ServiceAccount token automount must match the sealed workload identity contract",
        )
    if any(pod_spec.get(name) is True for name in ("hostNetwork", "hostPID", "hostIPC")):
        raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "host namespace access is forbidden")
    security = pod_spec.get("securityContext")
    seccomp = security.get("seccompProfile") if isinstance(security, Mapping) else None
    if (
        not isinstance(security, Mapping)
        or security.get("runAsNonRoot") is not True
        or not isinstance(seccomp, Mapping)
        or seccomp.get("type") not in {"RuntimeDefault", "Localhost"}
    ):
        raise DomainError(
            "DEPLOYMENT_ARTIFACT_UNSAFE",
            "restricted Pod security context is required",
        )
    volumes = pod_spec.get("volumes", [])
    if not isinstance(volumes, list) or any(
        isinstance(volume, Mapping) and "hostPath" in volume for volume in volumes
    ):
        raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "hostPath volumes are forbidden")
    secret_volumes = frozenset(
        str(volume["secret"].get("secretName", ""))
        for volume in volumes
        if isinstance(volume, Mapping) and isinstance(volume.get("secret"), Mapping)
    )
    if secret_volumes != EXPECTED_SECRET_VOLUMES[contract_name]:
        raise DomainError(
            "DEPLOYMENT_ARTIFACT_UNSAFE", "workload Secret volume references are not exact"
        )
    containers: list[Any] = []
    for field in ("initContainers", "containers"):
        raw = pod_spec.get(field, [])
        if not isinstance(raw, list):
            raise DomainError("DEPLOYMENT_ARTIFACT_INVALID", "workload containers are invalid")
        containers.extend(raw)
    if not containers:
        raise DomainError("DEPLOYMENT_ARTIFACT_INVALID", "workload containers are missing")
    if pod_spec.get("initContainers") not in (None, []):
        raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "undeclared init containers are forbidden")
    if len(containers) != 1:
        raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "each sealed workload has one container")
    for container in containers:
        image = str(container.get("image", "")) if isinstance(container, Mapping) else ""
        if (
            not isinstance(container, Mapping)
            or not IMAGE_DIGEST.fullmatch(image)
            or (allowed_images is not None and image not in allowed_images)
        ):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_IMAGE_INVALID",
                "every workload image must be closure-bound and scanned",
            )
        if (
            "command" in container
            or tuple(container.get("args", ())) != EXPECTED_ARGS[contract_name]
        ):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_UNSAFE",
                "container command and arguments do not match the sealed entrypoint",
            )
        if _references(container.get("envFrom")) != EXPECTED_ENV_FROM[contract_name]:
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_UNSAFE", "workload environment references are not exact"
            )
        environment = container.get("env", [])
        if not isinstance(environment, list):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_UNSAFE",
                "workload environment variables must be a list",
            )
        literal_environment: dict[str, str] = {}
        secret_environment: dict[str, tuple[str, str]] = {}
        for item in environment:
            if not isinstance(item, Mapping) or not isinstance(item.get("name"), str):
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_UNSAFE", "malformed environment variable is forbidden"
                )
            name = item["name"]
            if not name or name in literal_environment or name in secret_environment:
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_UNSAFE",
                    "duplicate or empty environment variable names are forbidden",
                )
            if set(item) == {"name", "value"} and isinstance(item.get("value"), str):
                literal_environment[name] = item["value"]
                continue
            value_from = item.get("valueFrom")
            if set(item) != {"name", "valueFrom"} or not isinstance(value_from, Mapping):
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_UNSAFE",
                    "only exact literal or Secret-key environment variables are allowed",
                )
            secret_key_ref = value_from.get("secretKeyRef")
            if (
                set(value_from) != {"secretKeyRef"}
                or not isinstance(secret_key_ref, Mapping)
                or set(secret_key_ref) != {"name", "key"}
                or not isinstance(secret_key_ref.get("name"), str)
                or not isinstance(secret_key_ref.get("key"), str)
                or not secret_key_ref["name"]
                or not secret_key_ref["key"]
            ):
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_UNSAFE",
                    "Secret environment references must bind one exact required key",
                )
            secret_environment[name] = (secret_key_ref["name"], secret_key_ref["key"])
        if literal_environment != EXPECTED_LITERAL_ENV[contract_name]:
            raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "literal environment is not exact")
        if secret_environment != EXPECTED_SECRET_ENV[contract_name]:
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_UNSAFE", "Secret-key environment references are not exact"
            )
        ports = container.get("ports", [])
        if not isinstance(ports, list) or any(
            isinstance(port, Mapping) and "hostPort" in port for port in ports
        ):
            raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "host ports are forbidden")
        container_security = container.get("securityContext")
        capabilities = (
            container_security.get("capabilities")
            if isinstance(container_security, Mapping)
            else None
        )
        drops = capabilities.get("drop", ()) if isinstance(capabilities, Mapping) else ()
        additions = capabilities.get("add", ()) if isinstance(capabilities, Mapping) else ()
        if (
            not isinstance(container_security, Mapping)
            or container_security.get("privileged") is True
            or container_security.get("allowPrivilegeEscalation") is not False
            or container_security.get("readOnlyRootFilesystem") is not True
            or not isinstance(drops, list)
            or "ALL" not in drops
            or bool(additions)
        ):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_UNSAFE",
                "restricted container security context is required",
            )


def _validate_service(value: Mapping[str, Any]) -> None:
    name = _pod_name(value)
    expected = EXPECTED_SERVICES.get(name)
    spec = value.get("spec")
    if expected is None or not isinstance(spec, Mapping):
        raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "undeclared Service is forbidden")
    forbidden = {
        "externalIPs",
        "loadBalancerIP",
        "loadBalancerClass",
        "externalName",
        "healthCheckNodePort",
    }
    if any(key in spec for key in forbidden) or spec.get("type", "ClusterIP") != "ClusterIP":
        raise DomainError(
            "DEPLOYMENT_ARTIFACT_UNSAFE", "only internal ClusterIP Services are allowed"
        )
    if spec.get("clusterIP") == "None" or spec.get("publishNotReadyAddresses") is True:
        raise DomainError(
            "DEPLOYMENT_ARTIFACT_UNSAFE", "headless or not-ready Service publication is forbidden"
        )
    selector, expected_ports = expected
    ports = spec.get("ports")
    if spec.get("selector") != selector or not isinstance(ports, list):
        raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "Service selector is not exact")
    observed: list[tuple[str, int, str]] = []
    for port in ports:
        if (
            not isinstance(port, Mapping)
            or "nodePort" in port
            or port.get("protocol", "TCP") != "TCP"
        ):
            raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "Service port contract is unsafe")
        observed.append(
            (str(port.get("name", "")), int(port.get("port", 0)), str(port.get("targetPort", "")))
        )
    if tuple(observed) != expected_ports:
        raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "Service ports are not exact")


def _validate_network_policies(values: Sequence[Mapping[str, Any]]) -> None:
    policies = [value for value in values if value.get("kind") == "NetworkPolicy"]
    names = {_pod_name(value) for value in policies}
    if names != EXPECTED_NETWORK_POLICIES or len(names) != len(policies):
        raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "NetworkPolicy inventory is not exact")
    for policy in policies:
        spec = policy.get("spec")
        if not isinstance(spec, Mapping) or not isinstance(spec.get("podSelector"), Mapping):
            raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "NetworkPolicy selector is invalid")
        for direction, peer_key in (("ingress", "from"), ("egress", "to")):
            rules = spec.get(direction, [])
            if not isinstance(rules, list):
                raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "NetworkPolicy rules are invalid")
            for rule in rules:
                peers = rule.get(peer_key, []) if isinstance(rule, Mapping) else None
                if not isinstance(peers, list) or not peers:
                    raise DomainError(
                        "DEPLOYMENT_ARTIFACT_UNSAFE", "world-open NetworkPolicy rules are forbidden"
                    )
                for peer in peers:
                    if (
                        not isinstance(peer, Mapping)
                        or not peer
                        or not set(peer).issubset({"podSelector", "namespaceSelector", "ipBlock"})
                    ):
                        raise DomainError(
                            "DEPLOYMENT_ARTIFACT_UNSAFE", "NetworkPolicy peer is invalid"
                        )
                    block = peer.get("ipBlock")
                    if isinstance(block, Mapping):
                        try:
                            network = ipaddress.ip_network(str(block.get("cidr", "")))
                        except ValueError as error:
                            raise DomainError(
                                "DEPLOYMENT_ARTIFACT_UNSAFE", "NetworkPolicy CIDR is invalid"
                            ) from error
                        if network.prefixlen == 0:
                            raise DomainError(
                                "DEPLOYMENT_ARTIFACT_UNSAFE", "world CIDRs are forbidden"
                            )


def _run(command: Sequence[str], timeout: int) -> str:
    import subprocess

    completed = subprocess.run(
        list(command),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode:
        raise DomainError(
            "PRODUCTION_DEPLOY_COMMAND_FAILED",
            "production deployment command failed",
            {
                "verb": command[1] if len(command) > 1 else "unknown",
                "exit_code": completed.returncode,
            },
            status=503,
        )
    return completed.stdout


def _ready(url: str) -> bool:
    if not url:
        return True
    try:
        with build_opener(_NoRedirect()).open(Request(url, method="GET"), timeout=15) as response:
            return int(response.status) == 200
    except (HTTPError, OSError):
        return False


@dataclass(frozen=True, slots=True)
class DeploymentArtifact:
    path: Path
    sha256: str


@dataclass(frozen=True, slots=True)
class DeploymentWorkload:
    kind: str
    name: str
    container: str
    image: str
    readiness_url: str


@dataclass(frozen=True, slots=True)
class ProductionDeploymentPlan:
    plan_id: str
    namespace: str
    backend_image: str
    web_image: str
    bootstrap_manifest: DeploymentArtifact
    migration_manifest: DeploymentArtifact
    runtime_manifest: DeploymentArtifact
    rollback_manifest: DeploymentArtifact
    migration_job: str
    workloads: tuple[DeploymentWorkload, ...]
    rollback_images: tuple[str, ...]
    snapshot_object_storage_prefix: str
    backup_object_storage_prefix: str
    snapshot_workload_identity_arn_digest: str
    backup_workload_identity_arn_digest: str
    real_ot_runtime_binding_digest: str
    real_ot_node_allowlist_digest: str
    digest: str

    @classmethod
    def load(
        cls,
        repository_root: str | Path,
        path: str | Path,
        *,
        candidate_image: str,
        expected_digest: str,
    ) -> ProductionDeploymentPlan:
        root = Path(repository_root).resolve(strict=True)
        source_path = Path(path)
        if source_path.is_absolute():
            try:
                source_path = source_path.relative_to(root)
            except ValueError as error:
                raise DomainError(
                    "DEPLOYMENT_PLAN_INVALID", "deployment plan must be inside the repository"
                ) from error
        resolved_source = _repository_file(root, source_path, "DEPLOYMENT_PLAN_INVALID")
        try:
            payload = json.loads(resolved_source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise DomainError(
                "DEPLOYMENT_PLAN_INVALID", "deployment plan is not valid JSON"
            ) from error
        if (
            not isinstance(payload, Mapping)
            or set(payload) != PLAN_KEYS
            or payload.get("schema_version") != 1
        ):
            raise DomainError("DEPLOYMENT_PLAN_INVALID", "deployment plan fields are invalid")
        claimed_digest = str(payload.get("digest", ""))
        if (
            not DIGEST.fullmatch(claimed_digest)
            or claimed_digest != canonical_digest({**payload, "digest": ""})
            or claimed_digest != expected_digest
        ):
            raise DomainError("DEPLOYMENT_PLAN_DIGEST_INVALID", "deployment plan digest mismatch")
        plan_id = str(payload.get("plan_id", ""))
        namespace = str(payload.get("namespace", ""))
        backend_image = str(payload.get("backend_image", ""))
        web_image = str(payload.get("web_image", ""))
        migration_job = str(payload.get("migration_job", ""))
        if (
            not KUBERNETES_NAME.fullmatch(plan_id)
            or not KUBERNETES_NAME.fullmatch(namespace)
            or namespace in {"default", "kube-system", "kube-public", "kube-node-lease"}
            or not KUBERNETES_NAME.fullmatch(migration_job)
            or plan_id not in migration_job
            or backend_image != candidate_image
            or not IMAGE_DIGEST.fullmatch(backend_image)
            or not IMAGE_DIGEST.fullmatch(web_image)
        ):
            raise DomainError(
                "DEPLOYMENT_PLAN_INVALID",
                "deployment identifiers or immutable images are invalid",
            )

        def artifact(name: str) -> DeploymentArtifact:
            value = payload.get(name)
            if not isinstance(value, Mapping) or set(value) != MANIFEST_KEYS:
                raise DomainError(
                    "DEPLOYMENT_PLAN_INVALID", "deployment artifact fields are invalid"
                )
            expected = str(value.get("sha256", ""))
            artifact_path = _repository_file(
                root, str(value.get("path", "")), "DEPLOYMENT_ARTIFACT_INVALID"
            )
            if (
                not DIGEST.fullmatch(expected)
                or hashlib.sha256(artifact_path.read_bytes()).hexdigest() != expected
            ):
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_INVALID",
                    "deployment artifact is missing, unsafe, or digest-mismatched",
                )
            return DeploymentArtifact(artifact_path, expected)

        artifacts = {
            name: artifact(name)
            for name in (
                "bootstrap_manifest",
                "migration_manifest",
                "runtime_manifest",
                "rollback_manifest",
            )
        }
        if len({value.path for value in artifacts.values()}) != len(artifacts):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_INVALID", "deployment artifacts must be distinct"
            )
        manifest_text = {
            name: value.path.read_text(encoding="utf-8") for name, value in artifacts.items()
        }
        if any(PLACEHOLDER.search(value) for value in manifest_text.values()) or any(
            re.search(r"(?m)^kind:\s*Secret\s*$", value) for value in manifest_text.values()
        ):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_INVALID",
                "deployment artifacts contain non-production placeholders",
            )
        manifest_objects: dict[str, list[Mapping[str, Any]]] = {}
        for phase, text in manifest_text.items():
            objects = _manifest_objects(text)
            identities: set[tuple[str, str]] = set()
            for value in objects:
                kind = str(value.get("kind", ""))
                api_version = str(value.get("apiVersion", ""))
                metadata = value.get("metadata")
                name = str(metadata.get("name", "")) if isinstance(metadata, Mapping) else ""
                object_namespace = (
                    str(metadata.get("namespace", "")) if isinstance(metadata, Mapping) else ""
                )
                identity = (kind, name)
                if (
                    kind not in PHASE_KINDS[phase]
                    or not api_version
                    or not isinstance(metadata, Mapping)
                    or "generateName" in metadata
                    or not KUBERNETES_NAME.fullmatch(name)
                    or object_namespace not in {"", namespace}
                    or identity in identities
                ):
                    raise DomainError(
                        "DEPLOYMENT_ARTIFACT_SCOPE_INVALID",
                        "deployment artifact contains an undeclared or out-of-scope object",
                    )
                identities.add(identity)
                if kind in POD_KINDS:
                    _validate_pod_security(
                        value,
                        None
                        if phase == "rollback_manifest"
                        else frozenset({backend_image, web_image}),
                    )
                elif kind == "Service":
                    _validate_service(value)
                elif kind == "ServiceAccount":
                    if name not in set(EXPECTED_SERVICE_ACCOUNTS.values()):
                        raise DomainError(
                            "DEPLOYMENT_ARTIFACT_UNSAFE", "undeclared ServiceAccount is forbidden"
                        )
                    expected_token = name in TOKEN_SERVICE_ACCOUNTS
                    if value.get("automountServiceAccountToken") is not expected_token:
                        raise DomainError(
                            "DEPLOYMENT_ARTIFACT_UNSAFE", "ServiceAccount token policy is not exact"
                        )
            manifest_objects[phase] = objects
        bootstrap_accounts = {
            _pod_name(value)
            for value in manifest_objects["bootstrap_manifest"]
            if value.get("kind") == "ServiceAccount"
        }
        if bootstrap_accounts != set(EXPECTED_SERVICE_ACCOUNTS.values()):
            raise DomainError(
                "DEPLOYMENT_PLAN_COVERAGE_INCOMPLETE",
                "bootstrap must define every dedicated ServiceAccount exactly once",
            )

        def workload_identity_digests(
            objects: Sequence[Mapping[str, Any]], *, phase: str
        ) -> dict[str, str]:
            accounts = {
                _pod_name(value): value
                for value in objects
                if value.get("kind") == "ServiceAccount"
            }
            result: dict[str, str] = {}
            for identity, account_name in STORAGE_SERVICE_ACCOUNTS.items():
                account = accounts.get(account_name)
                metadata = account.get("metadata") if isinstance(account, Mapping) else None
                annotations = (
                    metadata.get("annotations") if isinstance(metadata, Mapping) else None
                )
                if (
                    not isinstance(annotations, Mapping)
                    or set(annotations) != {WORKLOAD_IDENTITY_ANNOTATION}
                ):
                    raise DomainError(
                        "DEPLOYMENT_ARTIFACT_UNSAFE",
                        f"{phase} {identity} ServiceAccount identity annotation is not exact",
                    )
                role_arn = str(annotations.get(WORKLOAD_IDENTITY_ANNOTATION, ""))
                if not IAM_ROLE_ARN.fullmatch(role_arn):
                    raise DomainError(
                        "DEPLOYMENT_ARTIFACT_UNSAFE",
                        f"{phase} {identity} ServiceAccount role ARN is invalid",
                    )
                result[identity] = canonical_digest(
                    {"workload_identity_arn": role_arn}
                )
            return result

        workload_identity_bindings = workload_identity_digests(
            manifest_objects["bootstrap_manifest"], phase="candidate"
        )
        rollback_workload_identity_bindings = workload_identity_digests(
            manifest_objects["rollback_manifest"], phase="rollback"
        )
        if rollback_workload_identity_bindings != workload_identity_bindings:
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_UNSAFE",
                "rollback ServiceAccount workload identities differ from the candidate bundle",
            )
        _validate_network_policies(manifest_objects["bootstrap_manifest"])
        _validate_network_policies(manifest_objects["rollback_manifest"])

        def runtime_storage_prefixes(
            objects: Sequence[Mapping[str, Any]], *, phase: str
        ) -> tuple[str, str]:
            configs = [
                value
                for value in objects
                if value.get("kind") == "ConfigMap"
                and _pod_name(value) == "shadow-runtime"
            ]
            if len(configs) != 1:
                raise DomainError(
                    "DEPLOYMENT_PLAN_COVERAGE_INCOMPLETE",
                    f"{phase} sealed runtime configuration is required exactly once",
                )
            runtime_data = configs[0].get("data")
            if not isinstance(runtime_data, Mapping):
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_INVALID", "runtime configuration data is invalid"
                )
            values = (
                str(runtime_data.get("SHADOW_SNAPSHOT_OBJECT_STORAGE_PREFIX", "")),
                str(runtime_data.get("SHADOW_BACKUP_OBJECT_STORAGE_PREFIX", "")),
            )
            if (
                any(
                    not OBJECT_STORAGE_PREFIX.fullmatch(value)
                    or value != value.strip("/")
                    or "//" in value
                    or any(segment in {".", ".."} for segment in value.split("/"))
                    for value in values
                )
                or len(set(values)) != len(values)
            ):
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_INVALID",
                    "snapshot and backup object-storage prefixes must be canonical and distinct",
                )
            return values

        snapshot_object_storage_prefix, backup_object_storage_prefix = (
            runtime_storage_prefixes(
                manifest_objects["bootstrap_manifest"], phase="candidate"
            )
        )
        rollback_storage_prefixes = runtime_storage_prefixes(
            manifest_objects["rollback_manifest"], phase="rollback"
        )
        if rollback_storage_prefixes != (
            snapshot_object_storage_prefix,
            backup_object_storage_prefix,
        ):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_UNSAFE",
                "rollback runtime object-storage prefixes differ from the candidate bundle",
            )
        def real_ot_runtime_binding(
            objects: Sequence[Mapping[str, Any]], *, phase: str
        ) -> tuple[str, str]:
            bindings = [
                value
                for value in objects
                if value.get("kind") == "ConfigMap"
                and _pod_name(value) == "shadow-real-ot-collector-binding"
            ]
            if len(bindings) != 1:
                raise DomainError(
                    "DEPLOYMENT_PLAN_COVERAGE_INCOMPLETE",
                    f"{phase} sealed real-OT Collector binding is required exactly once",
                )
            data = bindings[0].get("data")
            if not isinstance(data, Mapping):
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_INVALID",
                    f"{phase} real-OT Collector binding data is invalid",
                )
            try:
                maximum_nodes = int(str(data.get("SHADOW_MAXIMUM_NODES", "500")))
                mappings = validate_collector_node_allowlist(
                    json.loads(str(data["SHADOW_NODE_ALLOWLIST"])),
                    maximum_nodes=maximum_nodes,
                    code="DEPLOYMENT_ARTIFACT_INVALID",
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_INVALID",
                    f"{phase} real-OT NodeId allowlist is invalid",
                ) from error
            node_ids = tuple(str(item["node_id"]) for item in mappings)
            node_digest = opcua_node_allowlist_digest(
                node_ids, code="DEPLOYMENT_ARTIFACT_INVALID"
            )
            digest = opcua_runtime_binding_digest(
                endpoint_uri=str(data.get("SHADOW_ENDPOINT_URI", "")),
                application_uri=str(data.get("SHADOW_APPLICATION_URI", "")),
                client_application_uri=str(
                    data.get("SHADOW_CLIENT_APPLICATION_URI", "")
                ),
                namespace_uri=str(data.get("SHADOW_NAMESPACE_URI", "")),
                server_certificate_fingerprint=str(
                    data.get("SHADOW_CERTIFICATE_FINGERPRINT", "")
                ),
                client_certificate_fingerprint=str(
                    data.get("SHADOW_CLIENT_CERTIFICATE_FINGERPRINT", "")
                ),
                next_client_certificate_fingerprint=str(
                    data.get("SHADOW_NEXT_CLIENT_CERTIFICATE_FINGERPRINT", "")
                ),
                security_profile=str(data.get("SHADOW_OPCUA_SECURITY_PROFILE", "")),
                node_ids=node_ids,
                code="DEPLOYMENT_ARTIFACT_INVALID",
            )
            return digest, node_digest

        real_ot_runtime_binding_digest, real_ot_node_allowlist_digest = (
            real_ot_runtime_binding(
                manifest_objects["bootstrap_manifest"], phase="candidate"
            )
        )
        rollback_real_ot_binding = real_ot_runtime_binding(
            manifest_objects["rollback_manifest"], phase="rollback"
        )
        if rollback_real_ot_binding != (
            real_ot_runtime_binding_digest,
            real_ot_node_allowlist_digest,
        ):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_UNSAFE",
                "rollback real-OT Collector binding differs from the candidate bundle",
            )
        if (
            migration_job not in manifest_text["migration_manifest"]
            or backend_image not in manifest_text["migration_manifest"]
            or backend_image not in manifest_text["runtime_manifest"]
            or web_image not in manifest_text["runtime_manifest"]
            or "@sha256:" not in manifest_text["rollback_manifest"]
        ):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_INVALID",
                "phased manifests do not carry the declared release images and Job",
            )
        raw_workloads = payload.get("workloads")
        if not isinstance(raw_workloads, list) or any(
            not isinstance(item, Mapping) or set(item) != WORKLOAD_KEYS for item in raw_workloads
        ):
            raise DomainError("DEPLOYMENT_PLAN_INVALID", "deployment workloads are invalid")
        workloads: list[DeploymentWorkload] = []
        observed: set[tuple[str, str, str, str]] = set()
        for item in raw_workloads:
            kind = str(item["kind"])
            name = str(item["name"])
            container = str(item["container"])
            image_role = str(item["image"])
            readiness_url = str(item["readiness_url"])
            identity = (kind, name, container, image_role)
            if (
                identity not in EXPECTED_WORKLOADS
                or not KUBERNETES_NAME.fullmatch(name)
                or not KUBERNETES_NAME.fullmatch(container)
                or (readiness_url and not readiness_url.startswith("https://"))
                or bool(PLACEHOLDER.search(readiness_url))
            ):
                raise DomainError("DEPLOYMENT_PLAN_INVALID", "deployment workload is invalid")
            observed.add(identity)
            workloads.append(
                DeploymentWorkload(
                    kind,
                    name,
                    container,
                    backend_image if image_role == "backend" else web_image,
                    readiness_url,
                )
            )
        if observed != EXPECTED_WORKLOADS or len(workloads) != len(observed):
            raise DomainError(
                "DEPLOYMENT_PLAN_COVERAGE_INCOMPLETE",
                "deployment plan must cover every production workload exactly once",
            )
        expected_resources = {(kind, name) for kind, name, _container, _role in observed}
        runtime_resources = {
            (str(value["kind"]).lower(), str(value["metadata"]["name"]))
            for value in manifest_objects["runtime_manifest"]
            if value["kind"] in {"Deployment", "StatefulSet"}
        }
        bootstrap_resources = {
            (str(value["kind"]), str(value["metadata"]["name"]))
            for value in manifest_objects["bootstrap_manifest"]
        }
        runtime_all_resources = {
            (str(value["kind"]), str(value["metadata"]["name"]))
            for value in manifest_objects["runtime_manifest"]
        }
        rollback_resources = {
            (str(value["kind"]), str(value["metadata"]["name"]))
            for value in manifest_objects["rollback_manifest"]
        }
        migration_jobs = {
            str(value["metadata"]["name"]) for value in manifest_objects["migration_manifest"]
        }
        if (
            runtime_resources != expected_resources
            or bootstrap_resources & runtime_all_resources
            or rollback_resources != bootstrap_resources | runtime_all_resources
            or migration_jobs != {migration_job}
        ):
            raise DomainError(
                "DEPLOYMENT_PLAN_COVERAGE_INCOMPLETE",
                "phased manifests must exactly cover the declared Job and workloads",
            )
        runtime_services = {
            _pod_name(value)
            for value in manifest_objects["runtime_manifest"]
            if value.get("kind") == "Service"
        }
        rollback_services = {
            _pod_name(value)
            for value in manifest_objects["rollback_manifest"]
            if value.get("kind") == "Service"
        }
        if runtime_services != set(EXPECTED_SERVICES) or rollback_services != set(
            EXPECTED_SERVICES
        ):
            raise DomainError(
                "DEPLOYMENT_PLAN_COVERAGE_INCOMPLETE", "internal Service inventory must be exact"
            )
        runtime_objects = {
            (str(value["kind"]).lower(), str(value["metadata"]["name"])): value
            for value in manifest_objects["runtime_manifest"]
            if value["kind"] in {"Deployment", "StatefulSet"}
        }
        rollback_objects = {
            (str(value["kind"]).lower(), str(value["metadata"]["name"])): value
            for value in manifest_objects["rollback_manifest"]
        }

        def declared_image(value: Mapping[str, Any], container_name: str) -> str:
            pod_spec = _pod_spec(value)
            containers = pod_spec.get("containers", []) if pod_spec else []
            if not isinstance(containers, list) or len(containers) != 1:
                raise DomainError(
                    "DEPLOYMENT_PLAN_COVERAGE_INCOMPLETE",
                    "declared workloads must contain exactly one runtime container",
                )
            container = containers[0]
            if not isinstance(container, Mapping) or container.get("name") != container_name:
                raise DomainError(
                    "DEPLOYMENT_PLAN_COVERAGE_INCOMPLETE",
                    "manifest container does not match the declared workload",
                )
            return str(container.get("image", ""))

        rollback_images: list[str] = []
        rollback_roles: dict[str, set[str]] = {"backend": set(), "web": set()}
        for workload, raw in zip(workloads, raw_workloads, strict=True):
            identity = (workload.kind, workload.name)
            runtime_object = runtime_objects[identity]
            runtime_spec = runtime_object.get("spec", {})
            template = runtime_spec.get("template", {}) if isinstance(runtime_spec, Mapping) else {}
            template_metadata = (
                template.get("metadata", {}) if isinstance(template, Mapping) else {}
            )
            selector = runtime_spec.get("selector", {}) if isinstance(runtime_spec, Mapping) else {}
            if (
                not isinstance(selector, Mapping)
                or selector.get("matchLabels") != {"app": workload.name}
                or not isinstance(template_metadata, Mapping)
                or template_metadata.get("labels") != EXPECTED_WORKLOAD_LABELS[workload.name]
            ):
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_UNSAFE",
                    "workload selector and Pod labels are not exact",
                )
            if declared_image(runtime_objects[identity], workload.container) != workload.image:
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_IMAGE_INVALID",
                    "runtime manifest image does not match the deployment plan",
                )
            rollback_image = declared_image(rollback_objects[identity], workload.container)
            if not IMAGE_DIGEST.fullmatch(rollback_image):
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_IMAGE_INVALID",
                    "rollback workload image must be immutable",
                )
            rollback_images.append(rollback_image)
            rollback_roles[str(raw["image"])].add(rollback_image)
        if any(len(images) != 1 for images in rollback_roles.values()):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_IMAGE_INVALID",
                "rollback backend and Web workloads must each use one exact image",
            )
        if not all(item.readiness_url for item in workloads if item.name in {"control-api", "web"}):
            raise DomainError(
                "DEPLOYMENT_PLAN_COVERAGE_INCOMPLETE",
                "API and web readiness URLs are required",
            )
        return cls(
            plan_id,
            namespace,
            backend_image,
            web_image,
            artifacts["bootstrap_manifest"],
            artifacts["migration_manifest"],
            artifacts["runtime_manifest"],
            artifacts["rollback_manifest"],
            migration_job,
            tuple(workloads),
            tuple(rollback_images),
            snapshot_object_storage_prefix,
            backup_object_storage_prefix,
            workload_identity_bindings["snapshot"],
            workload_identity_bindings["backup"],
            real_ot_runtime_binding_digest,
            real_ot_node_allowlist_digest,
            claimed_digest,
        )


class KubernetesProductionPublisher:
    """Apply an approved phased manifest bundle and restore the prior bundle on failure."""

    def __init__(
        self,
        plan: ProductionDeploymentPlan,
        *,
        confirmation: str,
        context: str,
        expected_cluster_uid_digest: str,
        expected_kubernetes_api_ca_digest: str,
        journal_path: str | Path | None = None,
        runner: CommandRunner = _run,
        readiness_probe: ReadinessProbe = _ready,
    ) -> None:
        if confirmation != f"{plan.namespace}:{plan.plan_id}:deploy":
            raise DomainError(
                "PRODUCTION_DEPLOY_CONFIRMATION_REQUIRED",
                "exact production deployment confirmation is required",
            )
        if not DIGEST.fullmatch(expected_cluster_uid_digest) or not DIGEST.fullmatch(
            expected_kubernetes_api_ca_digest
        ):
            raise DomainError(
                "KUBERNETES_CLUSTER_IDENTITY_INVALID",
                "signed target cluster identity digest is required",
            )
        self.plan = plan
        self.context = _safe_context(context)
        self.expected_cluster_uid_digest = expected_cluster_uid_digest
        self.expected_kubernetes_api_ca_digest = expected_kubernetes_api_ca_digest
        self.runner = runner
        self.readiness_probe = readiness_probe
        self.journal_path = Path(journal_path) if journal_path is not None else None
        self._journal_entries: list[Mapping[str, Any]] = []
        self.cluster_uid_digest = ""
        self.kubernetes_api_ca_digest = ""

    def _kubectl(self, arguments: Sequence[str], timeout: int = 900) -> str:
        return self.runner(
            ("kubectl", "--context", self.context, "-n", self.plan.namespace, *arguments),
            timeout,
        )

    def _journal(self, phase: str, **details: Any) -> None:
        entry = {
            "at": utc_now(),
            "phase": phase,
            "plan_id": self.plan.plan_id,
            "plan_digest": self.plan.digest,
            "namespace": self.plan.namespace,
            "cluster_uid_digest": self.cluster_uid_digest,
            **details,
        }
        self._journal_entries.append(entry)
        if self.journal_path is None:
            return
        path = self.journal_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise DomainError(
                "PRODUCTION_DEPLOY_JOURNAL_INVALID", "journal path cannot be a symlink"
            )
        descriptor, temporary = tempfile.mkstemp(prefix=".deployment-journal-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(self._journal_entries, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o644)
            os.replace(temporary, path)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    def _verify_cluster(self) -> None:
        observed, api_ca_digest = cluster_identity(self.runner, self.context)
        if (
            observed != self.expected_cluster_uid_digest
            or api_ca_digest != self.expected_kubernetes_api_ca_digest
        ):
            raise DomainError(
                "KUBERNETES_CLUSTER_IDENTITY_MISMATCH",
                "runtime cluster does not match the signed target profile",
            )
        self.cluster_uid_digest = observed
        self.kubernetes_api_ca_digest = api_ca_digest
        self._journal("cluster_identity_verified", kubernetes_api_ca_digest=api_ca_digest)

    def _verify_rbac(self) -> None:
        payload = json.loads(self._kubectl(("auth", "can-i", "--list", "-o", "json"), 60))
        if not isinstance(payload, Mapping) or not validate_exact_rbac(payload, PUBLISH_RBAC):
            raise DomainError(
                "PRODUCTION_DEPLOY_RBAC_OVERBROAD",
                "deployment runner RBAC is not the exact release-publisher allowlist",
            )
        self._journal("rbac_verified", permission_count=len(PUBLISH_RBAC))

    def _apply(self, artifact: DeploymentArtifact) -> None:
        self._kubectl(
            (
                "apply",
                "--server-side",
                "--field-manager=industrial-shadow-release",
                "-f",
                str(artifact.path),
            )
        )
        self._journal("manifest_applied", artifact_sha256=artifact.sha256)

    def _rollouts(self) -> None:
        for workload in self.plan.workloads:
            self._kubectl(
                (
                    "rollout",
                    "status",
                    f"{workload.kind}/{workload.name}",
                    "--timeout=10m",
                )
            )

    def _observed_workloads(
        self, expected_images: Mapping[str, str] | None = None
    ) -> tuple[dict[str, str], dict[str, bool], dict[str, str]]:
        observed_images: dict[str, str] = {}
        readiness: dict[str, bool] = {}
        revisions: dict[str, str] = {}
        for workload in self.plan.workloads:
            expected_image = (
                workload.image
                if expected_images is None
                else str(expected_images.get(workload.name, ""))
            )
            state = json.loads(
                self._kubectl(("get", workload.kind, workload.name, "-o", "json"), 60)
            )
            metadata = state.get("metadata", {})
            spec = state.get("spec", {})
            status = state.get("status", {})
            generation = int(metadata.get("generation", 0))
            desired = int(spec.get("replicas", 0))
            observed_generation = int(status.get("observedGeneration", 0))
            containers = spec.get("template", {}).get("spec", {}).get("containers", ())
            observed_images[workload.name] = next(
                (
                    str(item.get("image"))
                    for item in containers
                    if item.get("name") == workload.container
                ),
                "",
            )
            if workload.kind == "deployment":
                replicas_ready = (
                    all(
                        int(status.get(field, 0)) == desired
                        for field in ("updatedReplicas", "readyReplicas", "availableReplicas")
                    )
                    and int(status.get("unavailableReplicas", 0)) == 0
                )
                revision = str(
                    metadata.get("annotations", {}).get("deployment.kubernetes.io/revision", "")
                )
                replica_sets = json.loads(
                    self._kubectl(
                        ("get", "replicasets", "-l", f"app={workload.name}", "-o", "json"), 60
                    )
                ).get("items", ())
                current_replica_sets = [
                    item
                    for item in replica_sets
                    if item.get("metadata", {})
                    .get("annotations", {})
                    .get("deployment.kubernetes.io/revision")
                    == revision
                    and any(
                        owner.get("uid") == metadata.get("uid") and owner.get("controller") is True
                        for owner in item.get("metadata", {}).get("ownerReferences", ())
                    )
                    and int(item.get("spec", {}).get("replicas", 0)) == desired
                    and int(item.get("status", {}).get("readyReplicas", 0)) == desired
                ]
                accepted_owner_uids = {
                    str(item.get("metadata", {}).get("uid")) for item in current_replica_sets
                }
                replicas_ready = replicas_ready and len(accepted_owner_uids) == 1
            else:
                replicas_ready = (
                    all(
                        int(status.get(field, 0)) == desired
                        for field in ("currentReplicas", "updatedReplicas", "readyReplicas")
                    )
                    and bool(status.get("currentRevision"))
                    and status.get("currentRevision") == status.get("updateRevision")
                )
                revision = str(status.get("currentRevision", ""))
                accepted_owner_uids = {str(metadata.get("uid", ""))}
            pods = json.loads(
                self._kubectl(("get", "pods", "-l", f"app={workload.name}", "-o", "json"), 60)
            ).get("items", ())
            ready_pods = 0
            for pod in pods if isinstance(pods, list) else ():
                pod_metadata = pod.get("metadata", {})
                pod_status = pod.get("status", {})
                owners = pod_metadata.get("ownerReferences", ())
                container_statuses = pod_status.get("containerStatuses", ())
                status_item = next(
                    (item for item in container_statuses if item.get("name") == workload.container),
                    {},
                )
                image_id = str(status_item.get("imageID", ""))
                normalized_image_id = image_id.split("://", 1)[-1]
                pod_ready = any(
                    item.get("type") == "Ready" and item.get("status") == "True"
                    for item in pod_status.get("conditions", ())
                )
                if (
                    pod_metadata.get("deletionTimestamp") is None
                    and pod_status.get("phase") == "Running"
                    and any(
                        owner.get("uid") in accepted_owner_uids and owner.get("controller") is True
                        for owner in owners
                    )
                    and status_item.get("ready") is True
                    and pod_ready
                    and normalized_image_id == expected_image
                ):
                    ready_pods += 1
            readiness[workload.name] = (
                generation > 0
                and observed_generation == generation
                and desired > 0
                and replicas_ready
                and ready_pods == desired
                and self.readiness_probe(workload.readiness_url)
            )
            revisions[workload.name] = revision
        return observed_images, readiness, revisions

    def _stop_migration(self) -> None:
        self._journal("migration_stop_attempted", resource=f"job/{self.plan.migration_job}")
        self._kubectl(
            (
                "delete",
                "job",
                self.plan.migration_job,
                "--cascade=foreground",
                "--wait=true",
                "--ignore-not-found=true",
            ),
            600,
        )
        pods = json.loads(
            self._kubectl(
                ("get", "pods", "-l", f"job-name={self.plan.migration_job}", "-o", "json"), 60
            )
        ).get("items", ())
        if pods:
            raise DomainError(
                "PRODUCTION_DEPLOY_MIGRATION_STOP_FAILED",
                "migration Job pods are still present before rollback",
            )
        self._journal("migration_stopped", resource=f"job/{self.plan.migration_job}")

    def _prune_candidate_only(self) -> None:
        rollback = {
            (str(value.get("kind", "")).lower(), _pod_name(value))
            for value in _manifest_objects(
                self.plan.rollback_manifest.path.read_text(encoding="utf-8")
            )
        }
        candidate: set[tuple[str, str]] = set()
        for artifact in (self.plan.bootstrap_manifest, self.plan.runtime_manifest):
            candidate.update(
                (str(value.get("kind", "")).lower(), _pod_name(value))
                for value in _manifest_objects(artifact.path.read_text(encoding="utf-8"))
            )
        inventory = sorted(candidate - rollback)
        for kind, name in inventory:
            self._kubectl(
                ("delete", f"{kind}/{name}", "--ignore-not-found=true", "--wait=true"), 300
            )
        self._journal(
            "candidate_inventory_pruned", resources=[f"{kind}/{name}" for kind, name in inventory]
        )

    def _rollback(self) -> None:
        self._journal("rollback_attempted", attempted=True, succeeded=False)
        self._stop_migration()
        self._apply(self.plan.rollback_manifest)
        self._prune_candidate_only()
        self._rollouts()
        expected = {
            workload.name: image
            for workload, image in zip(self.plan.workloads, self.plan.rollback_images, strict=True)
        }
        observed_images, readiness, revisions = self._observed_workloads(expected)
        if observed_images != expected or not all(readiness.values()):
            raise DomainError(
                "PRODUCTION_DEPLOY_ROLLBACK_VERIFICATION_FAILED",
                "prior images or readiness were not restored",
                status=503,
            )
        self._journal(
            "rollback_succeeded",
            attempted=True,
            succeeded=True,
            revisions=revisions,
            resources=[f"{item.kind}/{item.name}" for item in self.plan.workloads],
        )

    def resume_rollback(self) -> GateEvidence:
        started = utc_now()
        self._verify_cluster()
        self._verify_rbac()
        self._rollback()
        return complete(
            "production_rollback",
            started_at=started,
            coordinates={
                "plan_digest": self.plan.digest,
                "namespace": self.plan.namespace,
                "cluster_uid_digest": self.cluster_uid_digest,
                "kubernetes_api_ca_digest": self.kubernetes_api_ca_digest,
            },
            checks=(GateCheck("prior_bundle_restored", True),),
            metrics={"workloads": len(self.plan.workloads)},
        )

    def run(self) -> GateEvidence:
        started = utc_now()
        self._verify_cluster()
        self._verify_rbac()
        for artifact in (
            self.plan.bootstrap_manifest,
            self.plan.migration_manifest,
            self.plan.runtime_manifest,
            self.plan.rollback_manifest,
        ):
            self._kubectl(
                (
                    "apply",
                    "--server-side",
                    "--dry-run=server",
                    "-f",
                    str(artifact.path),
                    "-o",
                    "name",
                )
            )
        self._journal("server_dry_run_completed")
        mutation_attempted = False
        rollback_completed = False
        try:
            mutation_attempted = True
            self._apply(self.plan.bootstrap_manifest)
            self._apply(self.plan.migration_manifest)
            self._kubectl(
                (
                    "wait",
                    "--for=condition=complete",
                    f"job/{self.plan.migration_job}",
                    "--timeout=10m",
                )
            )
            migration = json.loads(
                self._kubectl(("get", "job", self.plan.migration_job, "-o", "json"), 60)
            )
            migration_containers = (
                migration.get("spec", {}).get("template", {}).get("spec", {}).get("containers", ())
            )
            complete_condition = any(
                item.get("type") == "Complete" and item.get("status") == "True"
                for item in migration.get("status", {}).get("conditions", ())
            )
            if (
                not isinstance(migration_containers, list)
                or len(migration_containers) != 1
                or migration_containers[0].get("name") != "migrate"
                or migration_containers[0].get("image") != self.plan.backend_image
                or not complete_condition
                or int(migration.get("status", {}).get("succeeded", 0)) != 1
                or int(migration.get("status", {}).get("failed", 0)) != 0
            ):
                raise DomainError(
                    "PRODUCTION_DEPLOY_MIGRATION_INVALID",
                    "migration Job does not exclusively use the closure-bound backend image",
                )
            self._apply(self.plan.runtime_manifest)
            self._rollouts()
            observed_images, readiness, revisions = self._observed_workloads()
            checks = (
                GateCheck("exact_rbac", True),
                GateCheck("signed_cluster_identity", True),
                GateCheck("server_side_dry_run", True),
                GateCheck("candidate_migration_completed", True),
                GateCheck(
                    "exact_workload_images",
                    all(observed_images[item.name] == item.image for item in self.plan.workloads),
                ),
                GateCheck("all_rollouts_ready", all(readiness.values())),
            )
            evidence = complete(
                "production_deployment",
                started_at=started,
                coordinates={
                    "plan_digest": self.plan.digest,
                    "namespace": self.plan.namespace,
                    "backend_image": self.plan.backend_image,
                    "web_image": self.plan.web_image,
                    "cluster_uid_digest": self.cluster_uid_digest,
                    "kubernetes_api_ca_digest": self.kubernetes_api_ca_digest,
                    "revisions": revisions,
                },
                checks=checks,
                metrics={
                    "workloads": len(self.plan.workloads),
                    "ready_workloads": sum(readiness.values()),
                },
            )
            if evidence.status != "PASSED":
                self._rollback()
                rollback_completed = True
            else:
                self._journal(
                    "deployment_succeeded",
                    resources=[f"{item.kind}/{item.name}" for item in self.plan.workloads],
                    revisions=revisions,
                )
            return evidence
        except Exception:
            if mutation_attempted and not rollback_completed:
                try:
                    self._rollback()
                except Exception as rollback_error:
                    raise DomainError(
                        "PRODUCTION_DEPLOY_ROLLBACK_FAILED",
                        "deployment failed and the prior manifest could not be restored",
                        status=503,
                    ) from rollback_error
            raise
