from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import uuid
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import asdict, fields
from typing import Any
from urllib.parse import urlsplit

from shadow_sandbox.common.models import (
    DomainError,
    canonical_digest,
    canonical_json,
    utc_now,
)
from shadow_sandbox.common.object_storage import S3ObjectStorage, validate_object_key

from .evidence import GateCheck, GateEvidence, complete, target_digest
from .irsa_contract import (
    IRSA_MOUNT_PATH,
    IRSA_ROLE_ANNOTATION,
    IRSA_TOKEN_DEFAULT_MODE,
    IRSA_TOKEN_MOUNT,
    IRSA_TOKEN_PATH,
    IRSA_TOKEN_PROJECTION,
    IRSA_VOLUME_NAME,
)
from .production_deployment import (
    STORAGE_EGRESS_POD_LABEL_KEY,
    STORAGE_EGRESS_POD_LABEL_VALUE,
    cluster_identity,
    validate_exact_rbac,
)
from .storage_probe import S3SentinelBinding, S3WorkloadIdentityProbe

__all__ = (
    "IRSA_MOUNT_PATH",
    "IRSA_ROLE_ANNOTATION",
    "IRSA_TOKEN_DEFAULT_MODE",
    "IRSA_TOKEN_PATH",
    "IRSA_VOLUME_NAME",
)

KubectlRunner = Callable[[Sequence[str], int, str | None], str]

IDENTITIES = ("backup", "snapshot")
SERVICE_ACCOUNTS = {
    "backup": "shadow-backup-storage",
    "snapshot": "shadow-simulator-storage",
}
DIGEST = re.compile(r"[a-f0-9]{64}")
DIGEST_PINNED_IMAGE = re.compile(r"[^@\s]+@sha256:([a-f0-9]{64})")
DNS_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?")
IAM_ROLE_ARN = re.compile(r"arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/[A-Za-z0-9+=,.@_/-]+")
KMS_KEY_ARN = re.compile(r"arn:(aws|aws-us-gov|aws-cn):kms:([a-z0-9-]+):(\d{12}):key/[A-Za-z0-9-]+")
KUBERNETES_UID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}")
SYSTEM_NAMESPACES = frozenset({"default", "kube-system", "kube-public", "kube-node-lease"})
WORKLOAD_CHECKS = frozenset(
    {
        "exact_workload_role",
        "versioned_kms_roundtrip",
        "cross_prefix_exact_version_get_denied",
        "cross_prefix_exact_version_head_denied",
        "cross_prefix_list_denied",
        "cross_prefix_version_list_denied",
        "cross_prefix_denial_not_kms_only",
        "cross_prefix_denied",
        "probe_object_disposition",
    }
)
WORKLOAD_METRICS = frozenset(
    {
        "probe_bytes",
        "kms_denial_observed",
        "workload_retention_api_calls",
        "sentinel_binding_digest",
        "identity",
        "role_arn_digest",
        "cluster_uid_digest",
        "kubernetes_api_ca_digest",
        "prefix_contract_digest",
        "candidate_image_reference_digest",
        "inner_evidence_digest",
    }
)
STORAGE_PROBE_RBAC = frozenset(
    {
        ("", "namespaces", "get"),
        ("", "serviceaccounts", "get"),
        ("batch", "jobs", "create"),
        ("batch", "jobs", "delete"),
        ("batch", "jobs", "get"),
        ("batch", "jobs", "watch"),
        ("", "pods", "get"),
        ("", "pods", "list"),
        ("", "pods/log", "get"),
    }
)


def _run(command: Sequence[str], timeout: int, stdin: str | None = None) -> str:
    try:
        completed = subprocess.run(
            list(command),
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_COMMAND_TIMEOUT",
            "Kubernetes storage probe command timed out",
            status=503,
        ) from error
    if completed.returncode:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_COMMAND_FAILED",
            "Kubernetes storage probe command failed",
            {"exit_code": completed.returncode},
            status=503,
        )
    return completed.stdout


def _strict_json(value: str, *, code: str) -> Any:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 1024 * 1024:
        raise DomainError(code, "JSON input is empty or too large")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = child
        return result

    try:
        return json.loads(value, object_pairs_hook=object_pairs)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise DomainError(code, "JSON input is invalid") from error


def _validate_namespace(value: str) -> str:
    if not isinstance(value, str) or not DNS_LABEL.fullmatch(value) or value in SYSTEM_NAMESPACES:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_NAMESPACE_INVALID",
            "a non-system Kubernetes namespace is required",
        )
    return value


def _validate_context(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 253
        or any(character.isspace() or ord(character) < 0x20 for character in value)
    ):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_CONTEXT_INVALID",
            "an explicit Kubernetes context is required",
        )
    return value


def _normalize_prefixes(value: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"acceptance", "backup", "snapshot"}:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_PREFIX_INVALID",
            "exact acceptance, backup, and snapshot prefixes are required",
        )
    normalized: dict[str, str] = {}
    for name in ("acceptance", "backup", "snapshot"):
        prefix = value.get(name)
        if not isinstance(prefix, str) or not prefix or prefix != prefix.strip():
            raise DomainError(
                "KUBERNETES_STORAGE_PROBE_PREFIX_INVALID",
                "storage prefixes are invalid",
            )
        normalized[name] = validate_object_key(prefix.rstrip("/"))
    values = tuple(normalized.values())
    if len(set(values)) != len(values) or any(
        left.startswith(right + "/") or right.startswith(left + "/")
        for index, left in enumerate(values)
        for right in values[index + 1 :]
    ):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_PREFIX_INVALID",
            "storage prefixes must be pairwise non-overlapping",
        )
    return normalized


def _validate_roles(value: Mapping[str, Any], *, account_id: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != set(IDENTITIES):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_ROLE_INVALID",
            "exact backup and snapshot role ARNs are required",
        )
    roles: dict[str, str] = {}
    partitions: set[str] = set()
    for identity in IDENTITIES:
        role = value.get(identity)
        if not isinstance(role, str):
            raise DomainError(
                "KUBERNETES_STORAGE_PROBE_ROLE_INVALID",
                "workload role ARN is invalid or belongs to another account",
            )
        match = IAM_ROLE_ARN.fullmatch(role)
        if match is None or match.group(2) != account_id:
            raise DomainError(
                "KUBERNETES_STORAGE_PROBE_ROLE_INVALID",
                "workload role ARN is invalid or belongs to another account",
            )
        roles[identity] = role
        partitions.add(match.group(1))
    if len(set(roles.values())) != 2 or len(partitions) != 1:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_ROLE_INVALID",
            "backup and snapshot require distinct roles in one AWS partition",
        )
    return roles


def _validate_sentinels(
    value: Mapping[str, Any],
    *,
    bucket: str,
    kms_key_arn: str,
    prefixes: Mapping[str, str],
) -> dict[str, S3SentinelBinding]:
    if not isinstance(value, Mapping) or set(value) != set(IDENTITIES):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_SENTINEL_INVALID",
            "exact backup and snapshot sentinel bindings are required",
        )
    bindings: dict[str, S3SentinelBinding] = {}
    for identity in IDENTITIES:
        item = value.get(identity)
        if isinstance(item, S3SentinelBinding):
            binding = item
        elif isinstance(item, Mapping):
            binding = S3SentinelBinding.from_mapping(item)
        else:
            raise DomainError(
                "KUBERNETES_STORAGE_PROBE_SENTINEL_INVALID",
                "sentinel binding is invalid",
            )
        # The mapping key names the identity being denied, so its immutable
        # control-plane sentinel must live in the opposite workload's prefix.
        forbidden_prefix = "snapshot" if identity == "backup" else "backup"
        expected_prefix = prefixes[forbidden_prefix] + "/"
        if (
            binding.bucket != bucket
            or binding.kms_key_id != kms_key_arn
            or not binding.key.startswith(expected_prefix)
        ):
            raise DomainError(
                "KUBERNETES_STORAGE_PROBE_SENTINEL_INVALID",
                "sentinel binding does not match its immutable storage prefix",
            )
        bindings[identity] = binding
    if bindings["backup"].binding_digest == bindings["snapshot"].binding_digest:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_SENTINEL_INVALID",
            "backup and snapshot sentinel bindings must be distinct",
        )
    return bindings


def workload_target_coordinates(
    *,
    identity: str,
    bucket: str,
    region: str,
    prefixes: Mapping[str, str],
    kms_key_arn: str,
    account_id: str,
    expected_role_arn: str,
    forbidden_sentinel: S3SentinelBinding,
    cluster_uid_digest: str,
    kubernetes_api_ca_digest: str,
    candidate_image: str,
) -> Mapping[str, str]:
    """Return the deterministic, non-secret coordinates sealed by pod evidence."""
    return {
        "identity": identity,
        "bucket_digest": hashlib.sha256(bucket.encode("utf-8")).hexdigest(),
        "region": region,
        "prefix_contract_digest": canonical_digest(dict(prefixes)),
        "kms_key_digest": hashlib.sha256(kms_key_arn.encode("utf-8")).hexdigest(),
        "account_id_digest": hashlib.sha256(account_id.encode("utf-8")).hexdigest(),
        "role_arn_digest": hashlib.sha256(expected_role_arn.encode("utf-8")).hexdigest(),
        "forbidden_sentinel_binding_digest": forbidden_sentinel.binding_digest,
        "cluster_uid_digest": cluster_uid_digest,
        "kubernetes_api_ca_digest": kubernetes_api_ca_digest,
        "candidate_image_reference_digest": hashlib.sha256(
            candidate_image.encode("utf-8")
        ).hexdigest(),
    }


def _validate_aws_endpoint(
    client: Any,
    *,
    region: str,
    partition: str,
    service: str,
) -> bool:
    metadata = getattr(client, "meta", None)
    endpoint_url = str(getattr(metadata, "endpoint_url", ""))
    client_region = str(getattr(metadata, "region_name", ""))
    try:
        endpoint = urlsplit(endpoint_url)
        endpoint_port = endpoint.port
    except ValueError:
        return False
    suffix = "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com"
    allowed_hosts = {f"{service}.{region}.{suffix}"}
    return (
        endpoint.scheme == "https"
        and endpoint.hostname in allowed_hosts
        and endpoint_port in {None, 443}
        and endpoint.path in {"", "/"}
        and client_region == region
        and not endpoint.username
        and not endpoint.password
        and not endpoint.query
        and not endpoint.fragment
    )


def run_inside_pod(
    *,
    identity: str,
    bucket: str,
    region: str,
    prefixes: Mapping[str, Any],
    kms_key_arn: str,
    account_id: str,
    expected_role_arn: str,
    forbidden_sentinel: S3SentinelBinding | Mapping[str, Any],
    cluster_uid_digest: str,
    kubernetes_api_ca_digest: str,
    candidate_image: str,
    require_object_lock: bool,
    boto3_module: Any | None = None,
) -> GateEvidence:
    """Run the S3 least-privilege proof with the pod's ambient AWS identity."""
    started = utc_now()
    if identity not in IDENTITIES:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_IDENTITY_INVALID", "workload identity is invalid"
        )
    normalized_prefixes = _normalize_prefixes(prefixes)
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        raise DomainError("KUBERNETES_STORAGE_PROBE_BUCKET_INVALID", "S3 bucket is invalid")
    kms_match = KMS_KEY_ARN.fullmatch(kms_key_arn)
    role_match = IAM_ROLE_ARN.fullmatch(expected_role_arn)
    if (
        not re.fullmatch(r"\d{12}", account_id)
        or kms_match is None
        or role_match is None
        or kms_match.group(2) != region
        or kms_match.group(3) != account_id
        or role_match.group(1) != kms_match.group(1)
        or role_match.group(2) != account_id
        or not DIGEST.fullmatch(cluster_uid_digest)
        or not DIGEST.fullmatch(kubernetes_api_ca_digest)
        or DIGEST_PINNED_IMAGE.fullmatch(candidate_image) is None
        or require_object_lock is not True
    ):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_CONFIG_INVALID",
            "pod storage identity coordinates are invalid",
        )
    binding = (
        forbidden_sentinel
        if isinstance(forbidden_sentinel, S3SentinelBinding)
        else S3SentinelBinding.from_mapping(forbidden_sentinel)
    )
    forbidden_identity = "snapshot" if identity == "backup" else "backup"
    if (
        binding.bucket != bucket
        or binding.kms_key_id != kms_key_arn
        or not binding.key.startswith(normalized_prefixes[forbidden_identity] + "/")
    ):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_SENTINEL_INVALID",
            "the control-plane sentinel is not the exact forbidden-prefix binding",
        )
    if boto3_module is None:
        try:
            import boto3 as boto3_module  # type: ignore[no-redef]
        except ImportError as error:
            raise DomainError(
                "S3_DEPENDENCY_UNAVAILABLE", "boto3 is required inside the storage probe pod"
            ) from error
    session = boto3_module.Session(region_name=region)
    credentials = session.get_credentials()
    if credentials is None or getattr(credentials, "method", "") != "assume-role-with-web-identity":
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_CREDENTIAL_SOURCE_INVALID",
            "ambient credentials must come from the projected IRSA web identity token",
        )
    s3_client = session.client("s3", region_name=region)
    sts_client = session.client("sts", region_name=region)
    endpoints_bound = _validate_aws_endpoint(
        s3_client,
        region=region,
        partition=kms_match.group(1),
        service="s3",
    ) and _validate_aws_endpoint(
        sts_client,
        region=region,
        partition=kms_match.group(1),
        service="sts",
    )
    if not endpoints_bound:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_AWS_ENDPOINT_INVALID",
            "ambient AWS clients must use the signed region and official HTTPS endpoints",
        )
    storage = S3ObjectStorage(
        bucket,
        region=region,
        prefix=normalized_prefixes[identity],
        kms_key_id=kms_key_arn,
        kms_encryption_context={
            "application": "industrial-shadow",
            "purpose": identity,
        },
        client=s3_client,
        expected_bucket_owner=account_id,
        production=True,
    )
    inner = S3WorkloadIdentityProbe(
        storage,
        identity=identity,
        sts_client=sts_client,
        expected_role_arn=expected_role_arn,
        forbidden_sentinel=binding,
        require_object_lock=require_object_lock,
    ).run()
    inner.verify()
    if (
        inner.gate != f"s3_{identity}_identity"
        or inner.status != "PASSED"
        or {check.name for check in inner.checks} != WORKLOAD_CHECKS
        or not all(check.passed for check in inner.checks)
    ):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_INNER_EVIDENCE_INVALID",
            "S3 workload identity evidence is incomplete",
        )
    coordinates = workload_target_coordinates(
        identity=identity,
        bucket=bucket,
        region=region,
        prefixes=normalized_prefixes,
        kms_key_arn=kms_key_arn,
        account_id=account_id,
        expected_role_arn=expected_role_arn,
        forbidden_sentinel=binding,
        cluster_uid_digest=cluster_uid_digest,
        kubernetes_api_ca_digest=kubernetes_api_ca_digest,
        candidate_image=candidate_image,
    )
    return complete(
        f"kubernetes_s3_{identity}_identity",
        started_at=started,
        coordinates=coordinates,
        checks=inner.checks,
        metrics={
            **dict(inner.metrics),
            "identity": identity,
            "role_arn_digest": coordinates["role_arn_digest"],
            "cluster_uid_digest": cluster_uid_digest,
            "kubernetes_api_ca_digest": kubernetes_api_ca_digest,
            "prefix_contract_digest": coordinates["prefix_contract_digest"],
            "candidate_image_reference_digest": coordinates["candidate_image_reference_digest"],
            "inner_evidence_digest": inner.digest,
        },
    )


def _kubectl(
    runner: KubectlRunner,
    context: str,
    namespace: str,
    arguments: Sequence[str],
    timeout: int,
    stdin: str | None = None,
) -> str:
    return runner(
        ("kubectl", "--context", context, "-n", namespace, *arguments),
        timeout,
        stdin,
    )


def _service_account_role(
    *,
    runner: KubectlRunner,
    context: str,
    namespace: str,
    service_account: str,
) -> str:
    raw = _kubectl(
        runner,
        context,
        namespace,
        ("get", "serviceaccount", service_account, "-o", "json"),
        60,
    )
    payload = _strict_json(raw, code="KUBERNETES_STORAGE_PROBE_SERVICE_ACCOUNT_INVALID")
    metadata = payload.get("metadata", {}) if isinstance(payload, Mapping) else {}
    annotations = metadata.get("annotations", {}) if isinstance(metadata, Mapping) else {}
    role = annotations.get(IRSA_ROLE_ANNOTATION) if isinstance(annotations, Mapping) else None
    if (
        not isinstance(payload, Mapping)
        or payload.get("kind") not in {None, "ServiceAccount"}
        or metadata.get("name") != service_account
        or metadata.get("namespace") != namespace
        or not isinstance(role, str)
        or IAM_ROLE_ARN.fullmatch(role) is None
    ):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_SERVICE_ACCOUNT_INVALID",
            "live ServiceAccount identity is incomplete",
        )
    return role


def _validate_storage_probe_rbac(
    *,
    runner: KubectlRunner,
    context: str,
    namespace: str,
) -> None:
    raw = _kubectl(
        runner,
        context,
        namespace,
        ("auth", "can-i", "--list", "-o", "json"),
        30,
    )
    payload = _strict_json(raw, code="KUBERNETES_STORAGE_PROBE_RBAC_INVALID")
    if not isinstance(payload, Mapping) or not validate_exact_rbac(payload, STORAGE_PROBE_RBAC):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_RBAC_INVALID",
            "storage probe runner RBAC is not the exact least-privilege contract",
        )


def _job_manifest(
    *,
    name: str,
    probe_id: str,
    namespace: str,
    identity: str,
    service_account: str,
    candidate_image: str,
    bucket: str,
    region: str,
    prefixes: Mapping[str, str],
    kms_key_arn: str,
    account_id: str,
    expected_role_arn: str,
    forbidden_sentinel: S3SentinelBinding,
    cluster_uid_digest: str,
    kubernetes_api_ca_digest: str,
    timeout_seconds: int,
    require_object_lock: bool,
) -> Mapping[str, Any]:
    if require_object_lock is not True:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_CONFIG_INVALID",
            "production workload probes require Object Lock disposition",
        )
    labels = {
        "app.kubernetes.io/name": "industrial-shadow-storage-probe",
        STORAGE_EGRESS_POD_LABEL_KEY: STORAGE_EGRESS_POD_LABEL_VALUE,
        "shadow-sandbox.io/storage-probe-id": probe_id,
        "shadow-sandbox.io/storage-probe-identity": identity,
    }
    arguments = [
        "--inside-pod",
        "--identity",
        identity,
        "--bucket",
        bucket,
        "--region",
        region,
        "--acceptance-prefix",
        prefixes["acceptance"],
        "--backup-prefix",
        prefixes["backup"],
        "--snapshot-prefix",
        prefixes["snapshot"],
        "--kms-key-arn",
        kms_key_arn,
        "--account-id",
        account_id,
        "--expected-role-arn",
        expected_role_arn,
        "--forbidden-sentinel-json",
        canonical_json(forbidden_sentinel.to_mapping()),
        "--cluster-uid-digest",
        cluster_uid_digest,
        "--kubernetes-api-ca-digest",
        kubernetes_api_ca_digest,
        "--candidate-image",
        candidate_image,
        "--require-object-lock",
    ]
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": {
            "backoffLimit": 0,
            "completions": 1,
            "parallelism": 1,
            "activeDeadlineSeconds": timeout_seconds,
            "ttlSecondsAfterFinished": 300,
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "serviceAccountName": service_account,
                    # Use one deterministic IRSA projection; admission must not add
                    # a duplicate general Kubernetes API bearer token.
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "enableServiceLinks": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 65532,
                        "runAsGroup": 65532,
                        "fsGroup": 65532,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "volumes": [deepcopy(IRSA_TOKEN_PROJECTION)],
                    "containers": [
                        {
                            "name": "storage-identity-probe",
                            "image": candidate_image,
                            "imagePullPolicy": "IfNotPresent",
                            "command": [
                                "python",
                                "-B",
                                "-m",
                                "shadow_sandbox.operations.kubernetes_storage_probe",
                            ],
                            "args": arguments,
                            "env": [
                                {"name": "AWS_ROLE_ARN", "value": expected_role_arn},
                                {
                                    "name": "AWS_WEB_IDENTITY_TOKEN_FILE",
                                    "value": IRSA_TOKEN_PATH,
                                },
                                {"name": "AWS_REGION", "value": region},
                                {"name": "AWS_DEFAULT_REGION", "value": region},
                                {"name": "AWS_CONFIG_FILE", "value": "/dev/null"},
                                {
                                    "name": "AWS_SHARED_CREDENTIALS_FILE",
                                    "value": "/dev/null",
                                },
                                {
                                    "name": "AWS_STS_REGIONAL_ENDPOINTS",
                                    "value": "regional",
                                },
                                {
                                    "name": "AWS_EC2_METADATA_DISABLED",
                                    "value": "true",
                                },
                                {
                                    "name": "AWS_S3_US_EAST_1_REGIONAL_ENDPOINT",
                                    "value": "regional",
                                },
                            ],
                            "volumeMounts": [dict(IRSA_TOKEN_MOUNT)],
                            "resources": {
                                "requests": {"cpu": "25m", "memory": "64Mi"},
                                "limits": {"cpu": "500m", "memory": "256Mi"},
                            },
                            "securityContext": {
                                "runAsNonRoot": True,
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        }
                    ],
                },
            },
        },
    }


def _validate_live_pod(
    pod: Mapping[str, Any],
    *,
    namespace: str,
    job_name: str,
    job_uid: str,
    service_account: str,
    candidate_image: str,
    expected_role_arn: str,
    region: str,
    expected_labels: Mapping[str, str],
    expected_container: Mapping[str, Any],
) -> str:
    metadata = pod.get("metadata", {})
    spec = pod.get("spec", {})
    status = pod.get("status", {})
    if not all(isinstance(value, Mapping) for value in (metadata, spec, status)):
        raise DomainError("KUBERNETES_STORAGE_PROBE_POD_INVALID", "probe Pod payload is invalid")
    pod_uid = str(metadata.get("uid", ""))
    labels = metadata.get("labels", {})
    owners = metadata.get("ownerReferences", ())
    containers = spec.get("containers", ())
    init_containers = spec.get("initContainers", ()) or ()
    ephemeral = spec.get("ephemeralContainers", ()) or ()
    volume_value = spec.get("volumes")
    volumes = [] if volume_value is None else volume_value
    if (
        metadata.get("namespace") != namespace
        or not isinstance(labels, Mapping)
        or any(labels.get(key) != value for key, value in expected_labels.items())
        or not KUBERNETES_UID.fullmatch(pod_uid)
        or not isinstance(owners, list)
        or len(owners) != 1
        or not isinstance(owners[0], Mapping)
        or owners[0].get("apiVersion") != "batch/v1"
        or owners[0].get("kind") != "Job"
        or owners[0].get("name") != job_name
        or owners[0].get("uid") != job_uid
        or owners[0].get("controller") is not True
        or spec.get("serviceAccountName") != service_account
        or spec.get("automountServiceAccountToken") is not False
        or spec.get("restartPolicy") != "Never"
        or spec.get("hostNetwork") is True
        or spec.get("hostPID") is True
        or spec.get("hostIPC") is True
        or bool(spec.get("imagePullSecrets"))
        or not isinstance(containers, list)
        or len(containers) != 1
        or init_containers
        or ephemeral
        or not isinstance(volumes, list)
        or len(volumes) != 1
    ):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_POD_INVALID",
            "probe Pod is not uniquely owned or does not use the exact ServiceAccount",
        )
    volume = volumes[0]
    if volume != IRSA_TOKEN_PROJECTION:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_POD_INVALID",
            "probe Pod does not use the exact audience-bound IRSA token projection",
        )
    pod_security = spec.get("securityContext", {})
    container = containers[0]
    container_security = (
        container.get("securityContext", {}) if isinstance(container, Mapping) else {}
    )
    if (
        not isinstance(container, Mapping)
        or pod_security
        != {
            "runAsNonRoot": True,
            "runAsUser": 65532,
            "runAsGroup": 65532,
            "fsGroup": 65532,
            "seccompProfile": {"type": "RuntimeDefault"},
        }
        or container.get("name") != "storage-identity-probe"
        or container.get("image") != candidate_image
        or container.get("command") != expected_container.get("command")
        or container.get("args") != expected_container.get("args")
        or container.get("envFrom") not in (None, ())
        or container.get("imagePullPolicy") != "IfNotPresent"
        or container.get("resources") != expected_container.get("resources")
        or container_security.get("runAsNonRoot") is not True
        or container_security.get("allowPrivilegeEscalation") is not False
        or container_security.get("readOnlyRootFilesystem") is not True
        or container_security.get("capabilities") != {"drop": ["ALL"]}
        or container_security.get("privileged") is True
    ):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_POD_INVALID",
            "probe Pod container contract was mutated",
        )
    volume_mounts = container.get("volumeMounts", ()) or ()
    if volume_mounts != [IRSA_TOKEN_MOUNT]:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_POD_INVALID",
            "probe Pod does not mount only the exact IRSA token projection",
        )
    environment = container.get("env", ()) or ()
    allowed_environment = {
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_STS_REGIONAL_ENDPOINTS",
        "AWS_EC2_METADATA_DISABLED",
        "AWS_S3_US_EAST_1_REGIONAL_ENDPOINT",
    }
    environment_map: dict[str, str] = {}
    if isinstance(environment, list):
        for item in environment:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"name", "value"}
                or not isinstance(item.get("name"), str)
                or not isinstance(item.get("value"), str)
                or item["name"] not in allowed_environment
                or item["name"] in environment_map
            ):
                environment_map = {}
                break
            environment_map[item["name"]] = item["value"]
    if (
        set(environment_map) != allowed_environment
        or environment_map.get("AWS_ROLE_ARN") != expected_role_arn
        or environment_map.get("AWS_WEB_IDENTITY_TOKEN_FILE") != IRSA_TOKEN_PATH
        or environment_map.get("AWS_REGION") != region
        or environment_map.get("AWS_DEFAULT_REGION") != region
        or environment_map.get("AWS_CONFIG_FILE") != "/dev/null"
        or environment_map.get("AWS_SHARED_CREDENTIALS_FILE") != "/dev/null"
        or environment_map.get("AWS_STS_REGIONAL_ENDPOINTS") != "regional"
        or environment_map.get("AWS_EC2_METADATA_DISABLED") != "true"
        or environment_map.get("AWS_S3_US_EAST_1_REGIONAL_ENDPOINT") != "regional"
    ):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_POD_INVALID",
            "probe Pod must use only the exact ambient IRSA environment",
        )
    statuses = status.get("containerStatuses", ())
    image_match = DIGEST_PINNED_IMAGE.fullmatch(candidate_image)
    if image_match is None:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_IMAGE_INVALID", "candidate image is not digest pinned"
        )
    image_digest = image_match.group(1)
    if not isinstance(statuses, list) or len(statuses) != 1 or not isinstance(statuses[0], Mapping):
        raise DomainError("KUBERNETES_STORAGE_PROBE_IMAGE_INVALID", "probe image status is missing")
    image_id = str(statuses[0].get("imageID", ""))
    image_id_match = re.search(r"(?:@|//)sha256:([a-f0-9]{64})$", image_id)
    terminated = statuses[0].get("state", {}).get("terminated", {})
    if (
        image_id_match is None
        or image_id_match.group(1) != image_digest
        or not isinstance(terminated, Mapping)
        or terminated.get("exitCode") != 0
        or status.get("phase") != "Succeeded"
    ):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_IMAGE_INVALID",
            "probe Pod did not run the exact candidate image to success",
        )
    return pod_uid


def _parse_workload_evidence(
    raw: str,
    *,
    identity: str,
    expected_coordinates: Mapping[str, str],
) -> GateEvidence:
    lines = raw.splitlines()
    if len(lines) != 1 or not lines[0] or len(lines[0].encode("utf-8")) > 1024 * 1024:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_EVIDENCE_INVALID",
            "probe logs must contain exactly one bounded GateEvidence JSON record",
        )
    payload = _strict_json(lines[0], code="KUBERNETES_STORAGE_PROBE_EVIDENCE_INVALID")
    expected_fields = {item.name for item in fields(GateEvidence)}
    if not isinstance(payload, Mapping) or set(payload) != expected_fields:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_EVIDENCE_INVALID",
            "probe evidence fields are invalid",
        )
    try:
        normalized = dict(payload)
        checks = normalized.get("checks", ())
        if not isinstance(checks, list):
            raise TypeError("checks are invalid")
        normalized["checks"] = tuple(GateCheck(**item) for item in checks)
        evidence = GateEvidence(**normalized)
        evidence.verify()
    except (DomainError, TypeError, ValueError) as error:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_EVIDENCE_INVALID",
            "probe evidence cannot be verified",
        ) from error
    metrics = evidence.metrics
    if (
        evidence.schema_version != 1
        or evidence.gate != f"kubernetes_s3_{identity}_identity"
        or evidence.status != "PASSED"
        or evidence.target_digest != target_digest(expected_coordinates)
        or evidence.limitations
        or {check.name for check in evidence.checks} != WORKLOAD_CHECKS
        or not all(check.passed for check in evidence.checks)
        or not isinstance(metrics, Mapping)
        or set(metrics) != WORKLOAD_METRICS
        or metrics.get("identity") != identity
        or metrics.get("role_arn_digest") != expected_coordinates["role_arn_digest"]
        or metrics.get("cluster_uid_digest") != expected_coordinates["cluster_uid_digest"]
        or metrics.get("kubernetes_api_ca_digest")
        != expected_coordinates["kubernetes_api_ca_digest"]
        or metrics.get("prefix_contract_digest") != expected_coordinates["prefix_contract_digest"]
        or metrics.get("candidate_image_reference_digest")
        != expected_coordinates["candidate_image_reference_digest"]
        or metrics.get("sentinel_binding_digest")
        != expected_coordinates["forbidden_sentinel_binding_digest"]
        or metrics.get("probe_bytes") != 4096
        or metrics.get("kms_denial_observed") != 0
        or metrics.get("workload_retention_api_calls") != 0
        or not DIGEST.fullmatch(str(metrics.get("inner_evidence_digest", "")))
    ):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_EVIDENCE_INVALID",
            "probe evidence is not bound to the exact role, cluster, and storage contract",
        )
    return evidence


def _execute_job(
    *,
    runner: KubectlRunner,
    context: str,
    namespace: str,
    manifest: Mapping[str, Any],
    identity: str,
    service_account: str,
    expected_role_arn: str,
    region: str,
    expected_coordinates: Mapping[str, str],
    timeout_seconds: int,
) -> tuple[GateEvidence, str, str]:
    metadata = manifest["metadata"]
    name = str(metadata["name"])
    created = _strict_json(
        _kubectl(
            runner,
            context,
            namespace,
            ("create", "-f", "-", "-o", "json"),
            60,
            canonical_json(manifest),
        ),
        code="KUBERNETES_STORAGE_PROBE_JOB_INVALID",
    )
    created_metadata = created.get("metadata", {}) if isinstance(created, Mapping) else {}
    job_uid = str(created_metadata.get("uid", ""))
    if (
        not isinstance(created, Mapping)
        or created.get("kind") not in {None, "Job"}
        or created_metadata.get("name") != name
        or created_metadata.get("namespace") != namespace
        or not KUBERNETES_UID.fullmatch(job_uid)
    ):
        raise DomainError("KUBERNETES_STORAGE_PROBE_JOB_INVALID", "created probe Job is invalid")
    _kubectl(
        runner,
        context,
        namespace,
        (
            "wait",
            "--for=condition=complete",
            f"job/{name}",
            f"--timeout={timeout_seconds}s",
        ),
        timeout_seconds + 30,
    )
    labels = metadata["labels"]
    probe_id = str(labels["shadow-sandbox.io/storage-probe-id"])
    pods = _strict_json(
        _kubectl(
            runner,
            context,
            namespace,
            (
                "get",
                "pods",
                "-l",
                f"shadow-sandbox.io/storage-probe-id={probe_id}",
                "-o",
                "json",
            ),
            60,
        ),
        code="KUBERNETES_STORAGE_PROBE_POD_INVALID",
    )
    items = pods.get("items", ()) if isinstance(pods, Mapping) else ()
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], Mapping):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_POD_INVALID",
            "probe Job must own exactly one Pod",
        )
    expected_container = manifest["spec"]["template"]["spec"]["containers"][0]
    pod_uid = _validate_live_pod(
        items[0],
        namespace=namespace,
        job_name=name,
        job_uid=job_uid,
        service_account=service_account,
        candidate_image=str(expected_container["image"]),
        expected_role_arn=expected_role_arn,
        region=region,
        expected_labels=labels,
        expected_container=expected_container,
    )
    pod_name = str(items[0].get("metadata", {}).get("name", ""))
    if not DNS_LABEL.fullmatch(pod_name):
        raise DomainError("KUBERNETES_STORAGE_PROBE_POD_INVALID", "probe Pod name is invalid")
    raw_logs = _kubectl(
        runner,
        context,
        namespace,
        ("logs", f"pod/{pod_name}", "-c", "storage-identity-probe"),
        60,
    )
    evidence = _parse_workload_evidence(
        raw_logs, identity=identity, expected_coordinates=expected_coordinates
    )
    return evidence, job_uid, pod_uid


def run_kubernetes_storage_identity_probe(
    *,
    namespace: str,
    context: str,
    candidate_image: str,
    bucket: str,
    region: str,
    prefixes: Mapping[str, Any],
    kms_key_arn: str,
    account_id: str,
    expected_role_arns: Mapping[str, Any],
    immutable_sentinel_bindings: Mapping[str, Any],
    expected_cluster_uid_digest: str,
    expected_kubernetes_api_ca_digest: str,
    confirmation: str,
    require_object_lock: bool,
    runner: KubectlRunner = _run,
    timeout_seconds: int = 300,
) -> GateEvidence:
    """Run two owner-bound target-cluster Jobs that prove backup/snapshot IRSA isolation."""
    started = utc_now()
    namespace = _validate_namespace(namespace)
    context = _validate_context(context)
    if confirmation != f"{namespace}:s3-workload-identity-probe":
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_CONFIRMATION_REQUIRED",
            "exact storage identity probe confirmation is required",
        )
    if DIGEST_PINNED_IMAGE.fullmatch(candidate_image) is None:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_IMAGE_INVALID",
            "the candidate backend image must be digest pinned",
        )
    if (
        not re.fullmatch(r"\d{12}", account_id)
        or not re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-\d", region)
        or not DIGEST.fullmatch(expected_cluster_uid_digest)
        or not DIGEST.fullmatch(expected_kubernetes_api_ca_digest)
        or not 30 <= timeout_seconds <= 1800
        or require_object_lock is not True
    ):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_CONFIG_INVALID",
            "signed storage probe coordinates are invalid",
        )
    normalized_prefixes = _normalize_prefixes(prefixes)
    roles = _validate_roles(expected_role_arns, account_id=account_id)
    kms_match = KMS_KEY_ARN.fullmatch(kms_key_arn)
    if kms_match is None or kms_match.group(2) != region or kms_match.group(3) != account_id:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_CONFIG_INVALID",
            "KMS key ARN must match the exact region and account",
        )
    role_partition = IAM_ROLE_ARN.fullmatch(roles["backup"]).group(1)  # type: ignore[union-attr]
    if kms_match.group(1) != role_partition:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_CONFIG_INVALID",
            "AWS partitions do not match",
        )
    bindings = _validate_sentinels(
        immutable_sentinel_bindings,
        bucket=bucket,
        kms_key_arn=kms_key_arn,
        prefixes=normalized_prefixes,
    )
    observed_cluster_uid_digest, observed_api_ca_digest = cluster_identity(
        lambda command, timeout: runner(command, timeout, None), context
    )
    if (
        observed_cluster_uid_digest != expected_cluster_uid_digest
        or observed_api_ca_digest != expected_kubernetes_api_ca_digest
    ):
        raise DomainError(
            "KUBERNETES_CLUSTER_IDENTITY_MISMATCH",
            "storage probe cluster does not match the signed target profile",
        )
    _validate_storage_probe_rbac(
        runner=runner,
        context=context,
        namespace=namespace,
    )
    for identity in IDENTITIES:
        observed_role = _service_account_role(
            runner=runner,
            context=context,
            namespace=namespace,
            service_account=SERVICE_ACCOUNTS[identity],
        )
        if observed_role != roles[identity]:
            raise DomainError(
                "KUBERNETES_STORAGE_PROBE_SERVICE_ACCOUNT_MISMATCH",
                "live ServiceAccount role annotation does not match the signed raw ARN",
            )

    created_jobs: list[tuple[str, str]] = []
    executions: dict[str, tuple[GateEvidence, str, str]] = {}
    primary_error: Exception | None = None
    cleanup_failures: list[str] = []
    try:
        for identity in IDENTITIES:
            probe_id = uuid.uuid4().hex[:16]
            name = f"shadow-s3-{identity}-probe-{probe_id}"
            manifest = _job_manifest(
                name=name,
                probe_id=probe_id,
                namespace=namespace,
                identity=identity,
                service_account=SERVICE_ACCOUNTS[identity],
                candidate_image=candidate_image,
                bucket=bucket,
                region=region,
                prefixes=normalized_prefixes,
                kms_key_arn=kms_key_arn,
                account_id=account_id,
                expected_role_arn=roles[identity],
                forbidden_sentinel=bindings[identity],
                cluster_uid_digest=observed_cluster_uid_digest,
                kubernetes_api_ca_digest=observed_api_ca_digest,
                timeout_seconds=timeout_seconds,
                require_object_lock=require_object_lock,
            )
            created_jobs.append((name, probe_id))
            coordinates = workload_target_coordinates(
                identity=identity,
                bucket=bucket,
                region=region,
                prefixes=normalized_prefixes,
                kms_key_arn=kms_key_arn,
                account_id=account_id,
                expected_role_arn=roles[identity],
                forbidden_sentinel=bindings[identity],
                cluster_uid_digest=observed_cluster_uid_digest,
                kubernetes_api_ca_digest=observed_api_ca_digest,
                candidate_image=candidate_image,
            )
            executions[identity] = _execute_job(
                runner=runner,
                context=context,
                namespace=namespace,
                manifest=manifest,
                identity=identity,
                service_account=SERVICE_ACCOUNTS[identity],
                expected_role_arn=roles[identity],
                region=region,
                expected_coordinates=coordinates,
                timeout_seconds=timeout_seconds,
            )
    except Exception as error:  # noqa: BLE001 - cleanup must run for every partial mutation
        primary_error = error
    finally:
        for name, probe_id in reversed(created_jobs):
            try:
                _kubectl(
                    runner,
                    context,
                    namespace,
                    (
                        "delete",
                        "job",
                        name,
                        "--cascade=foreground",
                        "--wait=true",
                        "--ignore-not-found=true",
                        f"--timeout={timeout_seconds}s",
                    ),
                    timeout_seconds + 30,
                )
            except Exception:  # noqa: BLE001 - report only a redacted cleanup stage
                cleanup_failures.append(f"{name}:delete")
            try:
                remaining = _strict_json(
                    _kubectl(
                        runner,
                        context,
                        namespace,
                        (
                            "get",
                            "pods",
                            "-l",
                            f"shadow-sandbox.io/storage-probe-id={probe_id}",
                            "-o",
                            "json",
                        ),
                        60,
                    ),
                    code="KUBERNETES_STORAGE_PROBE_CLEANUP_FAILED",
                )
                items = remaining.get("items", ()) if isinstance(remaining, Mapping) else ()
                if not isinstance(items, list) or items:
                    cleanup_failures.append(f"{name}:pods")
            except Exception:  # noqa: BLE001 - report only a redacted cleanup stage
                cleanup_failures.append(f"{name}:verify")
    if cleanup_failures:
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_CLEANUP_FAILED",
            "foreground Job cleanup or owner-bound Pod cleanup failed",
            {"failure_count": len(cleanup_failures)},
            status=503,
        )
    if primary_error is not None:
        raise primary_error
    if set(executions) != set(IDENTITIES):
        raise DomainError(
            "KUBERNETES_STORAGE_PROBE_EVIDENCE_INVALID",
            "both workload identity Jobs must produce evidence",
        )

    checks: list[GateCheck] = []
    for identity in IDENTITIES:
        evidence, _job_uid, _pod_uid = executions[identity]
        checks.extend(
            GateCheck(f"{identity}_{check.name}", check.passed, check.details)
            for check in evidence.checks
        )
        checks.extend(
            (
                GateCheck(f"{identity}_service_account_role_exact", True),
                GateCheck(f"{identity}_job_owner_bound", True),
                GateCheck(f"{identity}_candidate_image_exact", True),
                GateCheck(f"{identity}_evidence_contract_exact", True),
            )
        )
    checks.extend(
        (
            GateCheck("storage_probe_rbac_exact", True),
            GateCheck("object_lock_disposition_required", require_object_lock),
            GateCheck("probe_jobs_foreground_deleted", True),
        )
    )
    return complete(
        "kubernetes_s3_workload_identity",
        started_at=started,
        coordinates={
            "namespace": namespace,
            "context_digest": hashlib.sha256(context.encode("utf-8")).hexdigest(),
            "candidate_image_reference_digest": hashlib.sha256(
                candidate_image.encode("utf-8")
            ).hexdigest(),
            "cluster_uid_digest": observed_cluster_uid_digest,
            "kubernetes_api_ca_digest": observed_api_ca_digest,
            "prefix_contract_digest": canonical_digest(normalized_prefixes),
            "role_contract_digest": canonical_digest(roles),
            "sentinel_contract_digest": canonical_digest(
                {name: binding.binding_digest for name, binding in bindings.items()}
            ),
            "workload_evidence_digest": canonical_digest(
                {
                    identity: executions[identity][0].digest
                    for identity in IDENTITIES
                }
            ),
        },
        checks=checks,
        metrics={
            "jobs": 2,
            "pods": 2,
            "cleanup_jobs": 2,
            "backup_job_uid_digest": hashlib.sha256(
                executions["backup"][1].encode("utf-8")
            ).hexdigest(),
            "backup_pod_uid_digest": hashlib.sha256(
                executions["backup"][2].encode("utf-8")
            ).hexdigest(),
            "snapshot_job_uid_digest": hashlib.sha256(
                executions["snapshot"][1].encode("utf-8")
            ).hexdigest(),
            "snapshot_pod_uid_digest": hashlib.sha256(
                executions["snapshot"][2].encode("utf-8")
            ).hexdigest(),
            "cluster_uid_digest": observed_cluster_uid_digest,
            "kubernetes_api_ca_digest": observed_api_ca_digest,
        },
    )


def _failure_evidence(identity: str, error_code: str) -> GateEvidence:
    safe_identity = identity if identity in IDENTITIES else "unknown"
    safe_code = error_code if re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", error_code) else "UNEXPECTED"
    started = utc_now()
    return complete(
        f"kubernetes_s3_{safe_identity}_identity",
        started_at=started,
        coordinates={"identity": safe_identity, "execution": "failed"},
        checks=(GateCheck("execution_completed", False, {"error_code": safe_code}),),
        limitations=("inside_pod_probe_failed",),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inside-pod", action="store_true")
    parser.add_argument("--identity", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--acceptance-prefix", required=True)
    parser.add_argument("--backup-prefix", required=True)
    parser.add_argument("--snapshot-prefix", required=True)
    parser.add_argument("--kms-key-arn", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--expected-role-arn", required=True)
    parser.add_argument("--forbidden-sentinel-json", required=True)
    parser.add_argument("--cluster-uid-digest", required=True)
    parser.add_argument("--kubernetes-api-ca-digest", required=True)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--require-object-lock", action="store_true")
    arguments = parser.parse_args(argv)
    if not arguments.inside_pod:
        parser.error("this module entrypoint is restricted to --inside-pod")
    try:
        sentinel = _strict_json(
            arguments.forbidden_sentinel_json,
            code="KUBERNETES_STORAGE_PROBE_SENTINEL_INVALID",
        )
        if not isinstance(sentinel, Mapping):
            raise DomainError(
                "KUBERNETES_STORAGE_PROBE_SENTINEL_INVALID",
                "sentinel binding JSON must be an object",
            )
        evidence = run_inside_pod(
            identity=arguments.identity,
            bucket=arguments.bucket,
            region=arguments.region,
            prefixes={
                "acceptance": arguments.acceptance_prefix,
                "backup": arguments.backup_prefix,
                "snapshot": arguments.snapshot_prefix,
            },
            kms_key_arn=arguments.kms_key_arn,
            account_id=arguments.account_id,
            expected_role_arn=arguments.expected_role_arn,
            forbidden_sentinel=sentinel,
            cluster_uid_digest=arguments.cluster_uid_digest,
            kubernetes_api_ca_digest=arguments.kubernetes_api_ca_digest,
            candidate_image=arguments.candidate_image,
            require_object_lock=arguments.require_object_lock,
        )
    except DomainError as error:
        evidence = _failure_evidence(arguments.identity, error.code)
    except Exception:  # noqa: BLE001 - stdout must remain a redacted GateEvidence record
        evidence = _failure_evidence(arguments.identity, "UNEXPECTED")
    print(canonical_json(asdict(evidence)), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
