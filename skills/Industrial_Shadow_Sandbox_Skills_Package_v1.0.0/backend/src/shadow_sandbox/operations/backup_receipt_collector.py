from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json
from shadow_sandbox.evaluation.formal_benchmark import FormalBenchmarkImporter

from .production_deployment import (
    ProductionDeploymentPlan,
    _manifest_objects,
    cluster_identity,
)
from .restore_drill import MAXIMUM_MANIFEST_BYTES, BackupRestoreReceipt
from .trust_store import SignerTrustStore

CommandRunner = Callable[[Sequence[str], int], str]

CONTEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,252}$")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
DNS_SUBDOMAIN = re.compile(
    r"^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$"
)
KUBERNETES_UID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")
KUBERNETES_RESOURCE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
DIGEST = re.compile(r"^[a-f0-9]{64}$")
DIGEST_IMAGE = re.compile(r"^[^@\s]+@sha256:([a-f0-9]{64})$")
IMAGE_ID = re.compile(
    r"^(?:[A-Za-z][A-Za-z0-9+.-]*://)?(?:[^@\s]+@)?sha256:([a-f0-9]{64})$"
)
MAXIMUM_KUBECTL_OUTPUT_BYTES = 8 * 1024 * 1024
MAXIMUM_KUBECTL_ERROR_BYTES = 64 * 1024
BACKUP_CONTAINER_NAME = "backup"
BACKUP_SERVICE_ACCOUNT = "shadow-backup-storage"
BACKUP_COMMAND = ("python", "-m", "shadow_sandbox.operations.backup_job")
BACKUP_CRONJOB_NAME = "shadow-postgres-backup"


@dataclass(frozen=True, slots=True)
class SignedBackupReceiptExpectations:
    candidate_image: str
    source_database_digest: str
    receipt_digest: str
    namespace: str
    cluster_uid_digest: str
    kubernetes_api_ca_digest: str
    backup_pod_template_digest: str


@dataclass(frozen=True, slots=True)
class ObservedBackupPod:
    name: str
    uid: str
    resource_version: str


_POD_DEFAULTS: Mapping[str, Any] = {
    "dnsPolicy": "ClusterFirst",
    "enableServiceLinks": True,
    "hostUsers": True,
    "preemptionPolicy": "PreemptLowerPriority",
    "schedulerName": "default-scheduler",
    "setHostnameAsFQDN": False,
    "shareProcessNamespace": False,
    "terminationGracePeriodSeconds": 30,
}
_CONTAINER_DEFAULTS: Mapping[str, Any] = {
    "imagePullPolicy": "IfNotPresent",
    "stdin": False,
    "stdinOnce": False,
    "terminationMessagePath": "/dev/termination-log",
    "terminationMessagePolicy": "File",
    "tty": False,
    "workingDir": "",
}
_DEFAULT_LIVE_TOLERATIONS: tuple[Mapping[str, Any], ...] = (
    {
        "effect": "NoExecute",
        "key": "node.kubernetes.io/not-ready",
        "operator": "Exists",
        "tolerationSeconds": 300,
    },
    {
        "effect": "NoExecute",
        "key": "node.kubernetes.io/unreachable",
        "operator": "Exists",
        "tolerationSeconds": 300,
    },
)


def _normalized_backup_pod_template(
    value: Mapping[str, Any],
    *,
    job_name: str | None = None,
    job_uid: str | None = None,
    live_pod: bool = False,
) -> Mapping[str, Any]:
    """Normalize only documented API defaults around a sealed backup Pod template."""

    metadata_value = value.get("metadata", {})
    spec_value = value.get("spec")
    if not isinstance(metadata_value, Mapping) or not isinstance(spec_value, Mapping):
        raise DomainError(
            "BACKUP_RECEIPT_POD_TEMPLATE_INVALID",
            "backup Pod template metadata or spec is invalid",
        )
    metadata = json.loads(canonical_json(metadata_value))
    spec = json.loads(canonical_json(spec_value))
    if not isinstance(metadata, dict) or not isinstance(spec, dict):
        raise DomainError(
            "BACKUP_RECEIPT_POD_TEMPLATE_INVALID",
            "backup Pod template cannot be normalized",
        )
    allowed_metadata = {"annotations", "creationTimestamp", "labels"}
    if live_pod:
        allowed_metadata.update(
            {"generateName", "name", "namespace", "ownerReferences", "resourceVersion", "uid"}
        )
    if not set(metadata).issubset(allowed_metadata):
        raise DomainError(
            "BACKUP_RECEIPT_POD_TEMPLATE_INVALID",
            "backup Pod template metadata contains an undeclared field",
        )
    creation_timestamp = metadata.pop("creationTimestamp", None)
    if live_pod:
        if not _valid_timestamp(creation_timestamp):
            raise DomainError(
                "BACKUP_RECEIPT_POD_TEMPLATE_INVALID",
                "live backup Pod creationTimestamp is invalid",
            )
        if metadata.get("generateName") != f"{job_name}-":
            raise DomainError(
                "BACKUP_RECEIPT_POD_TEMPLATE_INVALID",
                "live backup Pod generateName is not bound to the exact Job",
            )
    elif creation_timestamp is not None:
        raise DomainError(
            "BACKUP_RECEIPT_POD_TEMPLATE_INVALID",
            "backup Pod template creationTimestamp is not a Kubernetes default",
        )
    labels = metadata.get("labels", {})
    annotations = metadata.get("annotations", {})
    if not isinstance(labels, dict) or not isinstance(annotations, dict):
        raise DomainError(
            "BACKUP_RECEIPT_POD_TEMPLATE_INVALID",
            "backup Pod template labels or annotations are invalid",
        )
    if job_name is not None and job_uid is not None:
        controller_labels = {
            "batch.kubernetes.io/controller-uid": job_uid,
            "batch.kubernetes.io/job-name": job_name,
            "controller-uid": job_uid,
            "job-name": job_name,
        }
        for name, expected in controller_labels.items():
            if name in labels and labels.pop(name) != expected:
                raise DomainError(
                    "BACKUP_RECEIPT_POD_TEMPLATE_INVALID",
                    "backup Pod controller labels do not match the exact Job",
                )
    metadata = {
        **({"annotations": annotations} if annotations else {}),
        **({"labels": labels} if labels else {}),
    }
    for name, default in _POD_DEFAULTS.items():
        if spec.get(name) == default:
            spec.pop(name)
    if spec.get("serviceAccount") == spec.get("serviceAccountName"):
        spec.pop("serviceAccount")
    if live_pod:
        node_name = spec.pop("nodeName", None)
        if not isinstance(node_name, str) or DNS_SUBDOMAIN.fullmatch(node_name) is None:
            raise DomainError(
                "BACKUP_RECEIPT_POD_TEMPLATE_INVALID",
                "live backup Pod has no exact scheduled node name",
            )
        if spec.get("priority") == 0:
            spec.pop("priority")
        tolerations = spec.get("tolerations")
        if isinstance(tolerations, list) and tuple(tolerations) == _DEFAULT_LIVE_TOLERATIONS:
            spec.pop("tolerations")
    containers = spec.get("containers")
    if not isinstance(containers, list) or len(containers) != 1:
        raise DomainError(
            "BACKUP_RECEIPT_POD_TEMPLATE_INVALID",
            "backup Pod template must contain one container",
        )
    container = containers[0]
    if not isinstance(container, dict):
        raise DomainError(
            "BACKUP_RECEIPT_POD_TEMPLATE_INVALID",
            "backup Pod template container is invalid",
        )
    for name, default in _CONTAINER_DEFAULTS.items():
        if container.get(name) == default:
            container.pop(name)
    for name, default in (
        ("command", []),
        ("env", []),
        ("envFrom", []),
        ("ports", []),
        ("resources", {}),
        ("volumeDevices", []),
        ("volumeMounts", []),
    ):
        if container.get(name) == default:
            container.pop(name)
    for name, default in (
        ("hostIPC", False),
        ("hostNetwork", False),
        ("hostPID", False),
        ("hostAliases", []),
        ("imagePullSecrets", []),
        ("initContainers", []),
        ("ephemeralContainers", []),
        ("readinessGates", []),
        ("resourceClaims", []),
        ("schedulingGates", []),
        ("securityContext", {}),
        ("topologySpreadConstraints", []),
        ("volumes", []),
    ):
        if spec.get(name) == default:
            spec.pop(name)
    return {"metadata": metadata, "spec": spec}


def _backup_pod_template_digest(
    value: Mapping[str, Any],
    *,
    job_name: str | None = None,
    job_uid: str | None = None,
    live_pod: bool = False,
) -> str:
    return canonical_digest(
        _normalized_backup_pod_template(
            value,
            job_name=job_name,
            job_uid=job_uid,
            live_pod=live_pod,
        )
    )


def _sealed_backup_pod_template_digest(plan: ProductionDeploymentPlan) -> str:
    try:
        encoded = plan.bootstrap_manifest.path.read_bytes()
    except OSError as error:
        raise DomainError(
            "BACKUP_RECEIPT_SIGNED_TARGET_INVALID",
            "the sealed bootstrap manifest is unavailable",
        ) from error
    if hashlib.sha256(encoded).hexdigest() != plan.bootstrap_manifest.sha256:
        raise DomainError(
            "BACKUP_RECEIPT_SIGNED_TARGET_INVALID",
            "the sealed bootstrap manifest changed after plan verification",
        )
    try:
        objects = _manifest_objects(encoded.decode("utf-8"))
    except UnicodeError as error:
        raise DomainError(
            "BACKUP_RECEIPT_SIGNED_TARGET_INVALID",
            "the sealed bootstrap manifest is not UTF-8",
        ) from error
    candidates = [
        item
        for item in objects
        if item.get("kind") == "CronJob"
        and isinstance(item.get("metadata"), Mapping)
        and item["metadata"].get("name") == BACKUP_CRONJOB_NAME
    ]
    if len(candidates) != 1:
        raise DomainError(
            "BACKUP_RECEIPT_SIGNED_TARGET_INVALID",
            "the sealed plan must contain one exact backup CronJob",
        )
    spec = candidates[0].get("spec")
    job_template = spec.get("jobTemplate") if isinstance(spec, Mapping) else None
    job_spec = job_template.get("spec") if isinstance(job_template, Mapping) else None
    template = job_spec.get("template") if isinstance(job_spec, Mapping) else None
    if not isinstance(template, Mapping):
        raise DomainError(
            "BACKUP_RECEIPT_SIGNED_TARGET_INVALID",
            "the sealed backup CronJob Pod template is missing",
        )
    return _backup_pod_template_digest(template)


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


def _run(command: Sequence[str], timeout: int) -> str:
    if not 1 <= timeout <= 120:
        raise DomainError(
            "BACKUP_RECEIPT_KUBECTL_INVALID",
            "kubectl timeout is outside the bounded collector contract",
        )
    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise DomainError(
            "BACKUP_RECEIPT_KUBECTL_FAILED",
            "the read-only Kubernetes query could not complete",
            status=503,
        ) from error
    assert process.stdout is not None
    assert process.stderr is not None
    output = bytearray()
    error_output = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, output)
    selector.register(process.stderr, selectors.EVENT_READ, error_output)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_process(process)
                raise DomainError(
                    "BACKUP_RECEIPT_KUBECTL_FAILED",
                    "the read-only Kubernetes query timed out",
                    status=503,
                )
            for key, _events in selector.select(min(remaining, 1.0)):
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = key.data
                assert isinstance(target, bytearray)
                target.extend(chunk)
                limit = (
                    MAXIMUM_KUBECTL_OUTPUT_BYTES
                    if target is output
                    else MAXIMUM_KUBECTL_ERROR_BYTES
                )
                if len(target) > limit:
                    _stop_process(process)
                    raise DomainError(
                        "BACKUP_RECEIPT_KUBECTL_INVALID",
                        "kubectl output exceeds the collector size limit",
                        status=503,
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _stop_process(process)
            raise DomainError(
                "BACKUP_RECEIPT_KUBECTL_FAILED",
                "the read-only Kubernetes query timed out",
                status=503,
            )
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            _stop_process(process)
            raise DomainError(
                "BACKUP_RECEIPT_KUBECTL_FAILED",
                "the read-only Kubernetes query timed out",
                status=503,
            ) from error
    except DomainError:
        _stop_process(process)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    if return_code:
        raise DomainError(
            "BACKUP_RECEIPT_KUBECTL_FAILED",
            "the read-only Kubernetes query failed",
            {"exit_code": return_code},
            status=503,
        )
    try:
        return output.decode("utf-8")
    except UnicodeError as error:
        raise DomainError(
            "BACKUP_RECEIPT_KUBECTL_INVALID",
            "kubectl output is not valid UTF-8",
            status=503,
        ) from error


def _public_json(path_value: str | Path, *, root: Path) -> Mapping[str, Any]:
    path = Path(path_value)
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_CLOEXEC"):
        raise DomainError(
            "BACKUP_RECEIPT_SIGNED_TARGET_INVALID",
            "secure signed-report descriptors are unavailable",
        )
    descriptor = -1
    try:
        resolved = path.resolve(strict=True)
        if root.resolve() not in resolved.parents:
            raise DomainError(
                "BACKUP_RECEIPT_SIGNED_TARGET_INVALID",
                "the signed report is outside the repository",
            )
        descriptor = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= 16 * 1024 * 1024
        ):
            raise DomainError(
                "BACKUP_RECEIPT_SIGNED_TARGET_INVALID",
                "the signed report path is unsafe",
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_uid,
                after.st_gid,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            != (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_uid,
                before.st_gid,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
        ):
            raise DomainError(
                "BACKUP_RECEIPT_SIGNED_TARGET_INVALID",
                "the signed report changed while it was read",
            )
    except DomainError:
        raise
    except OSError as error:
        raise DomainError(
            "BACKUP_RECEIPT_SIGNED_TARGET_INVALID",
            "the signed report is unavailable",
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DomainError(
            "BACKUP_RECEIPT_SIGNED_TARGET_INVALID",
            "the signed report is not valid JSON",
        ) from error
    if not isinstance(value, Mapping):
        raise DomainError(
            "BACKUP_RECEIPT_SIGNED_TARGET_INVALID",
            "the signed report must be an object",
        )
    return value


def load_signed_backup_receipt_expectations(
    *,
    repository_root: str | Path,
    formal_report_path: str | Path,
    deployment_plan_path: str | Path,
    candidate_image: str,
    build_digest: str,
    simulator_build_digest: str,
    environment_digest: str,
    deployment_plan_digest: str,
    trust_store_path: str | Path,
    trust_root_attestation_path: str | Path,
    trust_root_public_key_path: str | Path,
    trust_root_key_sha256: str,
) -> SignedBackupReceiptExpectations:
    """Derive every receipt expectation from one verified signed target bundle."""

    root = Path(repository_root).resolve(strict=True)
    trust_store = SignerTrustStore.load_verified(
        trust_store_path,
        root_attestation_path=trust_root_attestation_path,
        root_public_key_path=trust_root_public_key_path,
        expected_root_key_sha256=trust_root_key_sha256,
    )
    report = _public_json(formal_report_path, root=root)
    evidence, target = FormalBenchmarkImporter(
        root,
        candidate_image=candidate_image,
        build_digest=build_digest,
        simulator_build_digest=simulator_build_digest,
        trust_store=trust_store,
        environment_digest=environment_digest,
        deployment_plan_digest=deployment_plan_digest,
    ).import_report_with_target_profile(report)
    if evidence.status != "PASSED" or evidence.limitations:
        raise DomainError(
            "BACKUP_RECEIPT_SIGNED_TARGET_INVALID",
            "the formal target report is not an unqualified PASS",
        )
    plan = ProductionDeploymentPlan.load(
        root,
        deployment_plan_path,
        candidate_image=candidate_image,
        expected_digest=deployment_plan_digest,
    )
    source_digest = str(target.get("managed_postgresql_source_coordinate_digest", ""))
    receipt_digest = str(target.get("backup_restore_receipt_digest", ""))
    cluster_uid_digest = str(target.get("cluster_uid_digest", ""))
    api_ca_digest = str(target.get("kubernetes_api_ca_digest", ""))
    if (
        target.get("candidate_image") != candidate_image
        or target.get("deployment_plan_digest") != plan.digest
        or not DNS_LABEL.fullmatch(plan.namespace)
        or any(
            DIGEST.fullmatch(value) is None
            for value in (
                source_digest,
                receipt_digest,
                cluster_uid_digest,
                api_ca_digest,
            )
        )
    ):
        raise DomainError(
            "BACKUP_RECEIPT_SIGNED_TARGET_INVALID",
            "the signed target does not contain exact backup receipt coordinates",
        )
    return SignedBackupReceiptExpectations(
        candidate_image,
        source_digest,
        receipt_digest,
        plan.namespace,
        cluster_uid_digest,
        api_ca_digest,
        _sealed_backup_pod_template_digest(plan),
    )


def _json_object(encoded: str, *, code: str) -> Mapping[str, Any]:
    if len(encoded.encode("utf-8")) > MAXIMUM_KUBECTL_OUTPUT_BYTES:
        raise DomainError(code, "Kubernetes JSON exceeds the collector size limit")
    try:
        value = json.loads(encoded)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DomainError(code, "Kubernetes returned invalid JSON") from error
    if not isinstance(value, Mapping):
        raise DomainError(code, "Kubernetes JSON must be an object")
    return value


def _conditions(value: Any, *, code: str) -> Mapping[str, Mapping[str, Any]]:
    if not isinstance(value, list):
        raise DomainError(code, "Kubernetes conditions are missing")
    result: dict[str, Mapping[str, Any]] = {}
    for item in value:
        if not isinstance(item, Mapping) or not isinstance(item.get("type"), str):
            raise DomainError(code, "Kubernetes conditions are malformed")
        condition_type = str(item["type"])
        if condition_type in result:
            raise DomainError(code, "Kubernetes conditions are duplicated")
        result[condition_type] = item
    return result


def _job_is_exact(
    job: Mapping[str, Any],
    *,
    namespace: str,
    job_name: str,
    job_uid: str,
    candidate_image: str,
    backup_pod_template_digest: str,
) -> None:
    metadata = job.get("metadata")
    spec = job.get("spec")
    status_value = job.get("status")
    if not all(isinstance(value, Mapping) for value in (metadata, spec, status_value)):
        raise DomainError("BACKUP_RECEIPT_JOB_INVALID", "backup Job is incomplete")
    assert isinstance(metadata, Mapping)
    assert isinstance(spec, Mapping)
    assert isinstance(status_value, Mapping)
    template = spec.get("template")
    pod_spec = template.get("spec") if isinstance(template, Mapping) else None
    containers = pod_spec.get("containers") if isinstance(pod_spec, Mapping) else None
    if (
        metadata.get("name") != job_name
        or metadata.get("namespace") != namespace
        or metadata.get("uid") != job_uid
        or spec.get("parallelism", 1) != 1
        or spec.get("completions", 1) != 1
        or not isinstance(pod_spec, Mapping)
        or pod_spec.get("serviceAccountName") != BACKUP_SERVICE_ACCOUNT
        or pod_spec.get("automountServiceAccountToken") is not False
        or pod_spec.get("restartPolicy") != "Never"
        or pod_spec.get("initContainers") not in (None, [])
        or pod_spec.get("ephemeralContainers") not in (None, [])
        or not isinstance(containers, list)
        or len(containers) != 1
    ):
        raise DomainError(
            "BACKUP_RECEIPT_JOB_INVALID",
            "backup Job identity or Pod contract is not exact",
        )
    assert isinstance(template, Mapping)
    container = containers[0]
    if (
        not isinstance(container, Mapping)
        or container.get("name") != BACKUP_CONTAINER_NAME
        or container.get("image") != candidate_image
        or container.get("command") not in (None, [])
        or tuple(container.get("args", ())) != BACKUP_COMMAND
    ):
        raise DomainError(
            "BACKUP_RECEIPT_JOB_INVALID",
            "backup Job does not use the exact candidate entrypoint",
        )
    if (
        _backup_pod_template_digest(
            template,
            job_name=job_name,
            job_uid=job_uid,
        )
        != backup_pod_template_digest
    ):
        raise DomainError(
            "BACKUP_RECEIPT_JOB_INVALID",
            "backup Job Pod template differs from the sealed deployment plan",
        )
    conditions = _conditions(
        status_value.get("conditions"), code="BACKUP_RECEIPT_JOB_INVALID"
    )
    complete = conditions.get("Complete")
    failed = conditions.get("Failed")
    uncounted = status_value.get("uncountedTerminatedPods", {})
    if (
        not isinstance(complete, Mapping)
        or complete.get("status") != "True"
        or (isinstance(failed, Mapping) and failed.get("status") == "True")
        or status_value.get("succeeded") != 1
        or status_value.get("failed", 0) not in (None, 0)
        or status_value.get("active", 0) not in (None, 0)
        or not status_value.get("completionTime")
        or (
            isinstance(uncounted, Mapping)
            and any(bool(uncounted.get(name)) for name in ("succeeded", "failed"))
        )
    ):
        raise DomainError(
            "BACKUP_RECEIPT_JOB_INVALID",
            "backup Job is not one clean successful completion",
        )


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _pod_name_if_exact(
    pod_list: Mapping[str, Any],
    *,
    namespace: str,
    job_name: str,
    job_uid: str,
    candidate_image: str,
    backup_pod_template_digest: str,
) -> ObservedBackupPod:
    items = pod_list.get("items")
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], Mapping):
        raise DomainError(
            "BACKUP_RECEIPT_POD_INVALID",
            "the completed backup Job must own exactly one Pod",
        )
    pod = items[0]
    metadata = pod.get("metadata")
    spec = pod.get("spec")
    status_value = pod.get("status")
    if not all(isinstance(value, Mapping) for value in (metadata, spec, status_value)):
        raise DomainError("BACKUP_RECEIPT_POD_INVALID", "backup Pod is incomplete")
    assert isinstance(metadata, Mapping)
    assert isinstance(spec, Mapping)
    assert isinstance(status_value, Mapping)
    pod_name = str(metadata.get("name", ""))
    pod_uid = str(metadata.get("uid", ""))
    resource_version = str(metadata.get("resourceVersion", ""))
    owners = metadata.get("ownerReferences")
    labels = metadata.get("labels")
    containers = spec.get("containers")
    if (
        not DNS_SUBDOMAIN.fullmatch(pod_name)
        or metadata.get("namespace") != namespace
        or KUBERNETES_UID.fullmatch(pod_uid) is None
        or KUBERNETES_RESOURCE_VERSION.fullmatch(resource_version) is None
        or not isinstance(labels, Mapping)
        or labels.get("job-name") != job_name
        or not isinstance(owners, list)
        or len(owners) != 1
        or not isinstance(owners[0], Mapping)
        or owners[0].get("apiVersion") != "batch/v1"
        or owners[0].get("kind") != "Job"
        or owners[0].get("name") != job_name
        or owners[0].get("uid") != job_uid
        or owners[0].get("controller") is not True
        or spec.get("serviceAccountName") != BACKUP_SERVICE_ACCOUNT
        or spec.get("automountServiceAccountToken") is not False
        or spec.get("restartPolicy") != "Never"
        or spec.get("initContainers") not in (None, [])
        or spec.get("ephemeralContainers") not in (None, [])
        or not isinstance(containers, list)
        or len(containers) != 1
        or not isinstance(containers[0], Mapping)
        or containers[0].get("name") != BACKUP_CONTAINER_NAME
        or containers[0].get("image") != candidate_image
        or containers[0].get("command") not in (None, [])
        or tuple(containers[0].get("args", ())) != BACKUP_COMMAND
        or status_value.get("phase") != "Succeeded"
    ):
        raise DomainError(
            "BACKUP_RECEIPT_POD_INVALID",
            "backup Pod identity, ownership, or candidate contract is not exact",
        )
    if (
        _backup_pod_template_digest(
            {"metadata": metadata, "spec": spec},
            job_name=job_name,
            job_uid=job_uid,
            live_pod=True,
        )
        != backup_pod_template_digest
    ):
        raise DomainError(
            "BACKUP_RECEIPT_POD_INVALID",
            "live backup Pod template differs from the sealed deployment plan",
        )
    conditions = _conditions(
        status_value.get("conditions"), code="BACKUP_RECEIPT_POD_INVALID"
    )
    initialized = conditions.get("Initialized")
    scheduled = conditions.get("PodScheduled")
    ready = conditions.get("Ready")
    containers_ready = conditions.get("ContainersReady")
    ready_to_start = conditions.get("PodReadyToStartContainers")
    if (
        not isinstance(initialized, Mapping)
        or initialized.get("status") != "True"
        or not isinstance(scheduled, Mapping)
        or scheduled.get("status") != "True"
        or not isinstance(ready, Mapping)
        or ready.get("status") != "False"
        or ready.get("reason") != "PodCompleted"
        or not isinstance(containers_ready, Mapping)
        or containers_ready.get("status") != "False"
        or containers_ready.get("reason") != "PodCompleted"
        or (
            isinstance(ready_to_start, Mapping)
            and ready_to_start.get("status") != "True"
        )
    ):
        raise DomainError(
            "BACKUP_RECEIPT_POD_INVALID",
            "backup Pod did not reach the exact successful terminal readiness state",
        )
    statuses = status_value.get("containerStatuses")
    if not isinstance(statuses, list) or len(statuses) != 1 or not isinstance(
        statuses[0], Mapping
    ):
        raise DomainError(
            "BACKUP_RECEIPT_POD_INVALID",
            "backup Pod container status is not unique",
        )
    container_status = statuses[0]
    state = container_status.get("state")
    terminated = state.get("terminated") if isinstance(state, Mapping) else None
    image_match = IMAGE_ID.fullmatch(str(container_status.get("imageID", "")))
    candidate_match = DIGEST_IMAGE.fullmatch(candidate_image)
    if (
        container_status.get("name") != BACKUP_CONTAINER_NAME
        or container_status.get("image") != candidate_image
        or candidate_match is None
        or image_match is None
        or image_match.group(1) != candidate_match.group(1)
        or container_status.get("ready") is not False
        or container_status.get("restartCount") != 0
        or container_status.get("lastState") not in (None, {})
        or not isinstance(terminated, Mapping)
        or terminated.get("exitCode") != 0
        or terminated.get("signal", 0) != 0
        or terminated.get("reason") != "Completed"
        or not _valid_timestamp(terminated.get("startedAt"))
        or not _valid_timestamp(terminated.get("finishedAt"))
    ):
        raise DomainError(
            "BACKUP_RECEIPT_POD_INVALID",
            "backup Pod image or successful termination evidence is invalid",
        )
    return ObservedBackupPod(pod_name, pod_uid, resource_version)


def _prepare_output(path_value: str | Path) -> Path:
    requested = Path(os.path.abspath(os.fspath(path_value)))
    if requested.name in {"", ".", ".."}:
        raise DomainError("BACKUP_RECEIPT_OUTPUT_INVALID", "receipt output name is invalid")
    try:
        resolved_parent = requested.parent.resolve(strict=True)
        parent_metadata = resolved_parent.lstat()
    except OSError as error:
        raise DomainError(
            "BACKUP_RECEIPT_OUTPUT_INVALID", "receipt output parent is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022
    ):
        raise DomainError(
            "BACKUP_RECEIPT_OUTPUT_INVALID",
            "receipt output parent must resolve to an owner-controlled directory",
        )
    path = resolved_parent / requested.name
    try:
        path.lstat()
    except FileNotFoundError:
        return path
    except OSError as error:
        raise DomainError(
            "BACKUP_RECEIPT_OUTPUT_INVALID", "receipt output cannot be inspected"
        ) from error
    raise DomainError(
        "BACKUP_RECEIPT_OUTPUT_EXISTS",
        "refusing to overwrite or follow an existing receipt output",
    )


def _install_private_receipt(
    path_value: str | Path,
    payload: bytes,
    *,
    expected_source_database_digest: str,
    expected_receipt_digest: str,
) -> BackupRestoreReceipt:
    path = _prepare_output(path_value)
    required_flags = ("O_NOFOLLOW", "O_CLOEXEC", "O_DIRECTORY")
    if any(not hasattr(os, name) for name in required_flags):
        raise DomainError(
            "BACKUP_RECEIPT_OUTPUT_INVALID",
            "secure receipt output descriptors are unavailable",
        )
    directory_descriptor = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    temporary_name = f".{path.name}.tmp-{secrets.token_hex(16)}"
    temporary_created = False
    published = False
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_descriptor,
        )
        temporary_created = True
        try:
            os.fchmod(descriptor, 0o600)
            written = 0
            while written < len(payload):
                chunk_size = os.write(descriptor, payload[written:])
                if chunk_size <= 0:
                    raise DomainError(
                        "BACKUP_RECEIPT_OUTPUT_INVALID",
                        "private receipt staging write made no progress",
                    )
                written += chunk_size
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size != len(payload)
            ):
                raise DomainError(
                    "BACKUP_RECEIPT_OUTPUT_INVALID",
                    "private receipt staging file is unsafe",
                )
        finally:
            os.close(descriptor)
        temporary_path = path.parent / temporary_name
        staged = BackupRestoreReceipt.load(
            temporary_path,
            expected_source_database_digest=expected_source_database_digest,
        )
        if staged.receipt_digest != expected_receipt_digest:
            raise DomainError(
                "BACKUP_RECEIPT_SIGNED_TARGET_MISMATCH",
                "collected receipt does not match the signed target digest",
            )
        try:
            os.link(
                temporary_name,
                path.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise DomainError(
                "BACKUP_RECEIPT_OUTPUT_EXISTS",
                "refusing to overwrite or follow an existing receipt output",
            ) from error
        published = True
        os.unlink(temporary_name, dir_fd=directory_descriptor)
        temporary_created = False
        os.fsync(directory_descriptor)
        final = BackupRestoreReceipt.load(
            path,
            expected_source_database_digest=expected_source_database_digest,
        )
        metadata = path.lstat()
        if (
            final.receipt_digest != expected_receipt_digest
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise DomainError(
                "BACKUP_RECEIPT_OUTPUT_INVALID",
                "published receipt failed its final private-file verification",
            )
        return final
    except Exception:
        if published:
            try:
                os.unlink(path.name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
        raise
    finally:
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
        os.close(directory_descriptor)


def collect_completed_backup_receipt(
    *,
    context: str,
    namespace: str,
    job_name: str,
    job_uid: str,
    expectations: SignedBackupReceiptExpectations,
    output_path: str | Path,
    runner: CommandRunner = _run,
) -> BackupRestoreReceipt:
    """Collect one receipt without mutating Kubernetes or replacing an existing file."""

    output = _prepare_output(output_path)
    if (
        CONTEXT.fullmatch(context) is None
        or "//" in context
        or any(part in {"", ".", ".."} for part in context.split("/"))
        or DNS_LABEL.fullmatch(namespace) is None
        or namespace != expectations.namespace
        or DNS_SUBDOMAIN.fullmatch(job_name) is None
        or KUBERNETES_UID.fullmatch(job_uid) is None
        or DIGEST_IMAGE.fullmatch(expectations.candidate_image) is None
    ):
        raise DomainError(
            "BACKUP_RECEIPT_COORDINATES_INVALID",
            "backup receipt Kubernetes or signed target coordinates are invalid",
        )
    observed_cluster_uid, observed_api_ca = cluster_identity(runner, context)
    if (
        observed_cluster_uid != expectations.cluster_uid_digest
        or observed_api_ca != expectations.kubernetes_api_ca_digest
    ):
        raise DomainError(
            "BACKUP_RECEIPT_CLUSTER_MISMATCH",
            "backup Job context is not the signed target cluster",
        )
    job = _json_object(
        runner(
            (
                "kubectl",
                "--context",
                context,
                "--namespace",
                namespace,
                "get",
                "job",
                job_name,
                "-o",
                "json",
            ),
            60,
        ),
        code="BACKUP_RECEIPT_JOB_INVALID",
    )
    _job_is_exact(
        job,
        namespace=namespace,
        job_name=job_name,
        job_uid=job_uid,
        candidate_image=expectations.candidate_image,
        backup_pod_template_digest=expectations.backup_pod_template_digest,
    )
    pod_list = _json_object(
        runner(
            (
                "kubectl",
                "--context",
                context,
                "--namespace",
                namespace,
                "get",
                "pods",
                f"--selector=job-name={job_name}",
                "-o",
                "json",
            ),
            60,
        ),
        code="BACKUP_RECEIPT_POD_INVALID",
    )
    observed_pod = _pod_name_if_exact(
        pod_list,
        namespace=namespace,
        job_name=job_name,
        job_uid=job_uid,
        candidate_image=expectations.candidate_image,
        backup_pod_template_digest=expectations.backup_pod_template_digest,
    )
    logs = runner(
        (
            "kubectl",
            "--context",
            context,
            "--namespace",
            namespace,
            "logs",
            observed_pod.name,
            "--container",
            BACKUP_CONTAINER_NAME,
            "--timestamps=false",
            f"--limit-bytes={MAXIMUM_MANIFEST_BYTES + 1}",
        ),
        60,
    )
    if (
        "\r" in logs
        or not logs.endswith("\n")
        or logs.count("\n") != 1
        or not 1 <= len(logs.encode("utf-8")) <= MAXIMUM_MANIFEST_BYTES
    ):
        raise DomainError(
            "BACKUP_RECEIPT_LOG_INVALID",
            "backup container stdout must be exactly one bounded canonical JSON line",
        )
    pod_after_logs = _json_object(
        runner(
            (
                "kubectl",
                "--context",
                context,
                "--namespace",
                namespace,
                "get",
                "pod",
                observed_pod.name,
                "-o",
                "json",
            ),
            60,
        ),
        code="BACKUP_RECEIPT_POD_INVALID",
    )
    verified_after_logs = _pod_name_if_exact(
        {"items": [pod_after_logs]},
        namespace=namespace,
        job_name=job_name,
        job_uid=job_uid,
        candidate_image=expectations.candidate_image,
        backup_pod_template_digest=expectations.backup_pod_template_digest,
    )
    if verified_after_logs != observed_pod:
        raise DomainError(
            "BACKUP_RECEIPT_POD_CHANGED",
            "backup Pod UID or resourceVersion changed while logs were collected",
        )
    try:
        value = json.loads(logs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DomainError(
            "BACKUP_RECEIPT_LOG_INVALID", "backup receipt log line is not valid JSON"
        ) from error
    if not isinstance(value, Mapping) or canonical_json(value) + "\n" != logs:
        raise DomainError(
            "BACKUP_RECEIPT_LOG_INVALID", "backup receipt log line is not canonical JSON"
        )
    return _install_private_receipt(
        output,
        logs.encode("utf-8"),
        expected_source_database_digest=expectations.source_database_digest,
        expected_receipt_digest=expectations.receipt_digest,
    )
