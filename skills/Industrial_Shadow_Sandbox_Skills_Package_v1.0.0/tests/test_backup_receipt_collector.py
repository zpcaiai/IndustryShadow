from __future__ import annotations

import base64
import copy
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest
import shadow_sandbox.operations.backup_receipt_collector as collector_module
from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json
from shadow_sandbox.operations.backup_receipt_collector import (
    SignedBackupReceiptExpectations,
    _backup_pod_template_digest,
    collect_completed_backup_receipt,
)
from shadow_sandbox.operations.restore_drill import MAXIMUM_MANIFEST_BYTES

CANDIDATE_DIGEST = "a" * 64
CANDIDATE_IMAGE = (
    f"registry.example.invalid/industrial-shadow/backend@sha256:{CANDIDATE_DIGEST}"
)
SOURCE_DIGEST = "b" * 64
JOB_UID = "11111111-2222-3333-4444-555555555555"
POD_UID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
NAMESPACE = "industrial-shadow"
JOB_NAME = "shadow-postgres-backup-29123456"
POD_NAME = JOB_NAME + "-abcde"


def _sealed_environment() -> list[dict[str, Any]]:
    return [
        {
            "name": "AWS_ROLE_ARN",
            "value": "arn:aws:iam::123456789012:role/shadow-backup",
        },
        {"name": "AWS_REGION", "value": "us-east-1"},
        {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"},
        {
            "name": "AWS_WEB_IDENTITY_TOKEN_FILE",
            "value": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
        },
        {"name": "AWS_STS_REGIONAL_ENDPOINTS", "value": "regional"},
        {"name": "AWS_S3_US_EAST_1_REGIONAL_ENDPOINT", "value": "regional"},
        {"name": "AWS_EC2_METADATA_DISABLED", "value": "true"},
        {"name": "AWS_CONFIG_FILE", "value": "/dev/null"},
        {"name": "AWS_SHARED_CREDENTIALS_FILE", "value": "/dev/null"},
        {"name": "SHADOW_ENVIRONMENT", "value": "production"},
        {"name": "SHADOW_AWS_ACCOUNT_ID", "value": "123456789012"},
        {"name": "SHADOW_OBJECT_STORAGE_BACKEND", "value": "s3"},
        {"name": "SHADOW_OBJECT_STORAGE_BUCKET", "value": "shadow-production-backups"},
        {"name": "SHADOW_OBJECT_STORAGE_REGION", "value": "us-east-1"},
        {
            "name": "SHADOW_OBJECT_STORAGE_KMS_KEY_ID",
            "value": "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555",
        },
        {
            "name": "SHADOW_BACKUP_OBJECT_STORAGE_PREFIX",
            "value": "industrial-shadow/production/backups",
        },
        {"name": "SHADOW_DATABASE_BACKUP_ROLE", "value": "shadow_backup"},
        {
            "name": "SHADOW_DATABASE_URL",
            "valueFrom": {
                "secretKeyRef": {
                    "name": "shadow-backup-secrets",
                    "key": "SHADOW_DATABASE_URL",
                }
            },
        },
    ]


def _receipt() -> dict[str, Any]:
    archive_digest = "c" * 64
    archive_key = f"postgres/2026-08-20/{archive_digest}.dump"
    payload: dict[str, Any] = {
        "schema_version": 2,
        "created_at": "2026-08-20T00:00:00+00:00",
        "source_database_digest": SOURCE_DIGEST,
        "archive": {
            "key": archive_key,
            "size": 4096,
            "sha256": archive_digest,
            "version_id": "archive-version",
            "encryption": "aws:kms",
        },
        "manifest": {
            "key": archive_key + ".manifest.json",
            "size": 2048,
            "sha256": "d" * 64,
            "version_id": "manifest-version",
            "encryption": "aws:kms",
        },
        "manifest_digest": "e" * 64,
        "backup_snapshot_digest": "f" * 64,
        "kms_key_partition": "aws",
        "sealed_receipt": {
            "key": archive_key + ".receipt.json",
            "size": 1024,
            "sha256": "1" * 64,
            "version_id": "receipt-version",
            "encryption": "aws:kms",
        },
        "sealed_receipt_digest": "2" * 64,
    }
    payload["receipt_digest"] = canonical_digest(payload)
    return payload


def _job() -> dict[str, Any]:
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": JOB_NAME, "namespace": NAMESPACE, "uid": JOB_UID},
        "spec": {
            "parallelism": 1,
            "completions": 1,
            "template": {
                "spec": {
                    "serviceAccountName": "shadow-backup-storage",
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "containers": [
                        {
                            "name": "backup",
                            "image": CANDIDATE_IMAGE,
                            "args": [
                                "python",
                                "-m",
                                "shadow_sandbox.operations.backup_job",
                            ],
                            "env": _sealed_environment(),
                        }
                    ],
                }
            },
        },
        "status": {
            "conditions": [{"type": "Complete", "status": "True"}],
            "succeeded": 1,
            "completionTime": "2026-08-20T00:05:00Z",
        },
    }


def _pod() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": POD_NAME,
            "generateName": JOB_NAME + "-",
            "namespace": NAMESPACE,
            "uid": POD_UID,
            "resourceVersion": "12345",
            "creationTimestamp": "2026-08-20T00:00:00Z",
            "labels": {"job-name": JOB_NAME},
            "ownerReferences": [
                {
                    "apiVersion": "batch/v1",
                    "kind": "Job",
                    "name": JOB_NAME,
                    "uid": JOB_UID,
                    "controller": True,
                }
            ],
        },
        "spec": {
            "nodeName": "worker-01",
            "serviceAccountName": "shadow-backup-storage",
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": "backup",
                    "image": CANDIDATE_IMAGE,
                    "args": ["python", "-m", "shadow_sandbox.operations.backup_job"],
                    "env": _sealed_environment(),
                }
            ],
        },
        "status": {
            "phase": "Succeeded",
            "conditions": [
                {"type": "PodReadyToStartContainers", "status": "True"},
                {"type": "Initialized", "status": "True"},
                {"type": "PodScheduled", "status": "True"},
                {"type": "Ready", "status": "False", "reason": "PodCompleted"},
                {
                    "type": "ContainersReady",
                    "status": "False",
                    "reason": "PodCompleted",
                },
            ],
            "containerStatuses": [
                {
                    "name": "backup",
                    "image": CANDIDATE_IMAGE,
                    "imageID": f"docker-pullable://{CANDIDATE_IMAGE}",
                    "ready": False,
                    "restartCount": 0,
                    "lastState": {},
                    "state": {
                        "terminated": {
                            "exitCode": 0,
                            "signal": 0,
                            "reason": "Completed",
                            "startedAt": "2026-08-20T00:00:00Z",
                            "finishedAt": "2026-08-20T00:05:00Z",
                        }
                    },
                }
            ],
        },
    }


class _Runner:
    def __init__(
        self,
        receipt: dict[str, Any],
        *,
        job: dict[str, Any] | None = None,
        pods: list[dict[str, Any]] | None = None,
        post_pod: dict[str, Any] | None = None,
        logs: str | None = None,
    ) -> None:
        self.receipt = receipt
        self.job = job or _job()
        self.pods = pods if pods is not None else [_pod()]
        self.post_pod = post_pod or copy.deepcopy(self.pods[0])
        self.logs = logs if logs is not None else canonical_json(receipt) + "\n"
        self.commands: list[tuple[str, ...]] = []
        self.ca = b"exact-target-ca"
        self.cluster_uid = canonical_digest(
            {
                "api_server_ca_sha256": canonical_digest_bytes(self.ca),
                "kube_system_namespace_uid": "kube-system-uid-12345678",
            }
        )

    def __call__(self, command: Any, _timeout: int) -> str:
        values = tuple(command)
        self.commands.append(values)
        if values[-5:] == ("get", "namespace", "kube-system", "-o", "json"):
            return json.dumps({"metadata": {"uid": "kube-system-uid-12345678"}})
        if "config" in values and "view" in values:
            return json.dumps(
                {
                    "clusters": [
                        {
                            "cluster": {
                                "server": "https://kubernetes.example.invalid",
                                "certificate-authority-data": base64.b64encode(
                                    self.ca
                                ).decode("ascii"),
                            }
                        }
                    ]
                }
            )
        if "job" in values and "get" in values:
            return json.dumps(self.job)
        if "pods" in values and "get" in values:
            return json.dumps({"items": self.pods})
        if "logs" in values:
            return self.logs
        if "pod" in values and "get" in values:
            return json.dumps(self.post_pod)
        raise AssertionError(values)


def canonical_digest_bytes(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()


def _expectations(
    runner: _Runner, receipt: dict[str, Any]
) -> SignedBackupReceiptExpectations:
    return SignedBackupReceiptExpectations(
        CANDIDATE_IMAGE,
        SOURCE_DIGEST,
        str(receipt["receipt_digest"]),
        NAMESPACE,
        runner.cluster_uid,
        canonical_digest_bytes(runner.ca),
        _backup_pod_template_digest(_job()["spec"]["template"]),
    )


def _collect(tmp_path: Path, runner: _Runner) -> Path:
    output = tmp_path / "backup-receipt.json"
    collect_completed_backup_receipt(
        context="production-storage",
        namespace=NAMESPACE,
        job_name=JOB_NAME,
        job_uid=JOB_UID,
        expectations=_expectations(runner, runner.receipt),
        output_path=output,
        runner=runner,
    )
    return output


def test_collects_one_canonical_receipt_to_private_exclusive_file(
    tmp_path: Path,
) -> None:
    receipt = _receipt()
    runner = _Runner(receipt)
    output = _collect(tmp_path, runner)

    metadata = output.lstat()
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_nlink == 1
    assert output.read_text(encoding="utf-8") == canonical_json(receipt) + "\n"
    assert sum("logs" in command for command in runner.commands) == 1
    logs_command = next(command for command in runner.commands if "logs" in command)
    assert logs_command[-5:] == (
        POD_NAME,
        "--container",
        "backup",
        "--timestamps=false",
        f"--limit-bytes={MAXIMUM_MANIFEST_BYTES + 1}",
    )
    assert runner.commands[-1][-5:] == ("get", "pod", POD_NAME, "-o", "json")


@pytest.mark.parametrize("target_kind", ["existing", "symlink", "hardlink"])
def test_refuses_existing_symlink_or_hardlink_output(
    tmp_path: Path, target_kind: str
) -> None:
    receipt = _receipt()
    runner = _Runner(receipt)
    output = tmp_path / "backup-receipt.json"
    source = tmp_path / "source"
    source.write_text("preserve", encoding="utf-8")
    if target_kind == "existing":
        output.write_text("preserve", encoding="utf-8")
    elif target_kind == "symlink":
        output.symlink_to(source)
    else:
        os.link(source, output)

    with pytest.raises(DomainError) as raised:
        _collect(tmp_path, runner)
    assert raised.value.code == "BACKUP_RECEIPT_OUTPUT_EXISTS"
    assert not runner.commands
    assert source.read_text(encoding="utf-8") == "preserve"


def test_rejects_failed_job_before_listing_pods_or_logs(tmp_path: Path) -> None:
    receipt = _receipt()
    job = _job()
    job["status"] = {
        "conditions": [
            {"type": "Complete", "status": "True"},
            {"type": "Failed", "status": "True"},
        ],
        "succeeded": 1,
        "failed": 1,
        "completionTime": "2026-08-20T00:05:00Z",
    }
    runner = _Runner(receipt, job=job)

    with pytest.raises(DomainError) as raised:
        _collect(tmp_path, runner)
    assert raised.value.code == "BACKUP_RECEIPT_JOB_INVALID"
    assert not any(
        "pods" in command or "logs" in command for command in runner.commands
    )


@pytest.mark.parametrize(
    "drift",
    [
        "env",
        "env_from",
        "working_dir",
        "volumes",
        "security_context",
        "pythonpath",
        "environment",
        "aws_endpoint_url",
        "config_map_key_ref",
    ],
)
def test_rejects_job_template_drift_from_sealed_plan_before_listing_pods(
    tmp_path: Path, drift: str
) -> None:
    receipt = _receipt()
    job = _job()
    pod_spec = job["spec"]["template"]["spec"]
    container = pod_spec["containers"][0]
    if drift == "env":
        container["env"] = [{"name": "EXTRA", "value": "unsafe"}]
    elif drift == "env_from":
        container["envFrom"] = [{"configMapRef": {"name": "unsealed"}}]
    elif drift == "working_dir":
        container["workingDir"] = "/tmp"
    elif drift == "volumes":
        pod_spec["volumes"] = [{"name": "extra", "emptyDir": {}}]
    elif drift == "security_context":
        pod_spec["securityContext"] = {"runAsUser": 0}
    elif drift == "pythonpath":
        container["env"] = [{"name": "PYTHONPATH", "value": "/tmp/override"}]
    elif drift == "environment":
        next(item for item in container["env"] if item["name"] == "SHADOW_ENVIRONMENT")[
            "value"
        ] = "staging"
    elif drift == "aws_endpoint_url":
        container["env"].append(
            {"name": "AWS_ENDPOINT_URL", "value": "https://attacker.example.invalid"}
        )
    else:
        environment = next(
            item for item in container["env"] if item["name"] == "SHADOW_ENVIRONMENT"
        )
        environment.pop("value")
        environment["valueFrom"] = {
            "configMapKeyRef": {"name": "shadow-runtime", "key": "SHADOW_ENVIRONMENT"}
        }
    runner = _Runner(receipt, job=job)

    with pytest.raises(DomainError) as raised:
        _collect(tmp_path, runner)
    assert raised.value.code == "BACKUP_RECEIPT_JOB_INVALID"
    assert not any(
        "pods" in command or "logs" in command for command in runner.commands
    )


def test_rejects_multiple_pods_before_reading_logs(tmp_path: Path) -> None:
    receipt = _receipt()
    second = copy.deepcopy(_pod())
    second["metadata"]["name"] = POD_NAME + "2"
    second["metadata"]["uid"] = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
    runner = _Runner(receipt, pods=[_pod(), second])

    with pytest.raises(DomainError) as raised:
        _collect(tmp_path, runner)
    assert raised.value.code == "BACKUP_RECEIPT_POD_INVALID"
    assert not any("logs" in command for command in runner.commands)


@pytest.mark.parametrize("drift", ["image", "restart", "exit"])
def test_rejects_live_container_drift_before_reading_logs(
    tmp_path: Path, drift: str
) -> None:
    receipt = _receipt()
    pod = _pod()
    status = pod["status"]["containerStatuses"][0]
    if drift == "image":
        status["imageID"] = "containerd://sha256:" + "9" * 64
    elif drift == "restart":
        status["restartCount"] = 1
    else:
        status["state"]["terminated"]["exitCode"] = 1
    runner = _Runner(receipt, pods=[pod])

    with pytest.raises(DomainError) as raised:
        _collect(tmp_path, runner)
    assert raised.value.code == "BACKUP_RECEIPT_POD_INVALID"
    assert not any("logs" in command for command in runner.commands)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("PYTHONPATH", "/tmp/admission-override"),
        ("AWS_ENDPOINT_URL", "https://attacker.example.invalid"),
    ],
)
def test_rejects_admission_time_pod_template_drift_before_reading_logs(
    tmp_path: Path, name: str, value: str
) -> None:
    receipt = _receipt()
    pod = _pod()
    pod["spec"]["containers"][0]["env"].append({"name": name, "value": value})
    runner = _Runner(receipt, pods=[pod])

    with pytest.raises(DomainError) as raised:
        _collect(tmp_path, runner)
    assert raised.value.code == "BACKUP_RECEIPT_POD_INVALID"
    assert not any("logs" in command for command in runner.commands)


@pytest.mark.parametrize(
    "drift", ["uid", "resource_version", "owner", "status", "image"]
)
def test_revalidates_exact_pod_after_logs_and_rejects_replacement_or_drift(
    tmp_path: Path, drift: str
) -> None:
    receipt = _receipt()
    post_pod = _pod()
    if drift == "uid":
        post_pod["metadata"]["uid"] = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
    elif drift == "resource_version":
        post_pod["metadata"]["resourceVersion"] = "12346"
    elif drift == "owner":
        post_pod["metadata"]["ownerReferences"][0]["uid"] = POD_UID
    elif drift == "status":
        post_pod["status"]["containerStatuses"][0]["state"]["terminated"][
            "exitCode"
        ] = 1
    else:
        post_pod["status"]["containerStatuses"][0]["imageID"] = (
            "containerd://sha256:" + "9" * 64
        )
    runner = _Runner(receipt, post_pod=post_pod)

    with pytest.raises(DomainError) as raised:
        _collect(tmp_path, runner)
    assert raised.value.code in {
        "BACKUP_RECEIPT_POD_CHANGED",
        "BACKUP_RECEIPT_POD_INVALID",
    }
    assert sum("logs" in command for command in runner.commands) == 1
    assert not (tmp_path / "backup-receipt.json").exists()


@pytest.mark.parametrize(
    "logs",
    [
        lambda receipt: json.dumps(receipt, indent=2) + "\n",
        lambda receipt: canonical_json(receipt) + "\nextra\n",
        lambda receipt: canonical_json(receipt),
    ],
)
def test_rejects_noncanonical_or_multiline_stdout(tmp_path: Path, logs: Any) -> None:
    receipt = _receipt()
    runner = _Runner(receipt, logs=logs(receipt))

    with pytest.raises(DomainError) as raised:
        _collect(tmp_path, runner)
    assert raised.value.code == "BACKUP_RECEIPT_LOG_INVALID"
    assert not (tmp_path / "backup-receipt.json").exists()


def test_rejects_oversized_stdout_and_passes_server_side_log_limit(
    tmp_path: Path,
) -> None:
    receipt = _receipt()
    runner = _Runner(receipt, logs="x" * (MAXIMUM_MANIFEST_BYTES + 2))

    with pytest.raises(DomainError) as raised:
        _collect(tmp_path, runner)
    assert raised.value.code == "BACKUP_RECEIPT_LOG_INVALID"
    logs_command = next(command for command in runner.commands if "logs" in command)
    assert f"--limit-bytes={MAXIMUM_MANIFEST_BYTES + 1}" in logs_command
    assert not (tmp_path / "backup-receipt.json").exists()


def test_default_runner_terminates_while_streaming_oversized_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(collector_module, "MAXIMUM_KUBECTL_OUTPUT_BYTES", 1024)
    with pytest.raises(DomainError) as raised:
        collector_module._run(
            (sys.executable, "-c", 'import sys; sys.stdout.write("x" * 4096)'),
            5,
        )
    assert raised.value.code == "BACKUP_RECEIPT_KUBECTL_INVALID"


def test_rejects_receipt_not_bound_to_signed_digest(tmp_path: Path) -> None:
    receipt = _receipt()
    runner = _Runner(receipt)
    expectations = SignedBackupReceiptExpectations(
        CANDIDATE_IMAGE,
        SOURCE_DIGEST,
        "0" * 64,
        NAMESPACE,
        runner.cluster_uid,
        canonical_digest_bytes(runner.ca),
        _backup_pod_template_digest(_job()["spec"]["template"]),
    )

    with pytest.raises(DomainError) as raised:
        collect_completed_backup_receipt(
            context="production-storage",
            namespace=NAMESPACE,
            job_name=JOB_NAME,
            job_uid=JOB_UID,
            expectations=expectations,
            output_path=tmp_path / "backup-receipt.json",
            runner=runner,
        )
    assert raised.value.code == "BACKUP_RECEIPT_SIGNED_TARGET_MISMATCH"
    assert not (tmp_path / "backup-receipt.json").exists()
