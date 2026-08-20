from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import (
    DomainError,
    canonical_digest,
    canonical_json,
    utc_now,
)
from shadow_sandbox.evaluation.formal_benchmark import (
    validate_production_storage_target,
)
from shadow_sandbox.operations.evidence import (
    GateCheck,
    GateEvidence,
    bind_to_acceptance_run,
    complete,
    failed_execution,
    write_evidence,
)
from shadow_sandbox.operations.production_deployment import (
    PUBLISH_RBAC,
    KubernetesProductionPublisher,
    ProductionDeploymentPlan,
)

if __package__:
    from .check_release_evidence import INPUT as CLOSURE_INPUT
    from .check_release_evidence import main as check_release_evidence
else:
    from check_release_evidence import INPUT as CLOSURE_INPUT
    from check_release_evidence import main as check_release_evidence

ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"^[a-f0-9]{64}$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
SOURCE_REVISION = re.compile(r"^[a-f0-9]{40}$")
OUTPUT_ROOT = ROOT / "docs/evidence/batch-24/production-deployment"


JOURNAL_PHASE_KEYS = {
    "cluster_identity_verified": frozenset({"kubernetes_api_ca_digest"}),
    "rbac_verified": frozenset({"permission_count"}),
    "server_dry_run_completed": frozenset(),
    "candidate_mutation_started": frozenset(),
    "manifest_applied": frozenset({"artifact_sha256"}),
    "migration_stop_attempted": frozenset({"resource"}),
    "migration_stopped": frozenset({"resource"}),
    "candidate_inventory_pruned": frozenset({"resources"}),
    "rollback_attempted": frozenset({"attempted", "succeeded"}),
    "rollback_succeeded": frozenset(
        {"attempted", "succeeded", "revisions", "resources"}
    ),
    "deployment_succeeded": frozenset({"revisions", "resources"}),
}
JOURNAL_COMMON_KEYS = frozenset(
    {"at", "phase", "plan_id", "plan_digest", "namespace", "cluster_uid_digest"}
)
DEPLOYMENT_BINDING_KEYS = frozenset(
    {
        "schema_version",
        "operation",
        "repository",
        "github_run_id",
        "github_run_attempt",
        "closure_run_id",
        "closure_run_attempt",
        "closure_artifact_id",
        "closure_artifact_sha256",
        "source_revision",
        "acceptance_run_id",
        "release_digest",
        "closure_input_sha256",
        "closure_approval_digest",
        "plan_id",
        "plan_digest",
        "namespace",
        "cluster_uid_digest",
        "kubernetes_api_ca_digest",
        "backend_image",
        "web_image",
        "rollback_images_digest",
        "prior_binding_digest",
        "prior_artifact_id",
        "prior_artifact_sha256",
        "created_at",
        "digest",
    }
)


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise DomainError("PRODUCTION_DEPLOY_CONFIG_MISSING", f"{name} is required")
    return value


def _positive_integer(value: str, *, code: str, label: str) -> str:
    if not POSITIVE_INTEGER.fullmatch(value):
        raise DomainError(code, f"{label} must be a positive integer")
    return value


def _closure_artifact_coordinates() -> dict[str, str]:
    coordinates = {
        "closure_run_id": _positive_integer(
            _required("SHADOW_PRODUCTION_CLOSURE_RUN_ID"),
            code="PRODUCTION_CLOSURE_ARTIFACT_INVALID",
            label="production closure run ID",
        ),
        "closure_run_attempt": _positive_integer(
            _required("SHADOW_PRODUCTION_CLOSURE_RUN_ATTEMPT"),
            code="PRODUCTION_CLOSURE_ARTIFACT_INVALID",
            label="production closure run attempt",
        ),
        "closure_artifact_id": _positive_integer(
            _required("SHADOW_PRODUCTION_CLOSURE_ARTIFACT_ID"),
            code="PRODUCTION_CLOSURE_ARTIFACT_INVALID",
            label="production closure artifact ID",
        ),
        "closure_artifact_sha256": _required(
            "SHADOW_PRODUCTION_CLOSURE_ARTIFACT_SHA256"
        ),
        "source_revision": _required("SHADOW_PRODUCTION_SOURCE_REVISION"),
    }
    if not DIGEST.fullmatch(coordinates["closure_artifact_sha256"]):
        raise DomainError(
            "PRODUCTION_CLOSURE_ARTIFACT_INVALID",
            "production closure artifact digest is invalid",
        )
    if not SOURCE_REVISION.fullmatch(coordinates["source_revision"]):
        raise DomainError(
            "PRODUCTION_DEPLOY_SOURCE_INVALID",
            "signed source revision is invalid",
        )
    git_environment = os.environ.copy()
    for name in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    ):
        git_environment.pop(name, None)
    try:
        observed = subprocess.run(
            ("git", "rev-parse", "--verify", "HEAD^{commit}"),
            cwd=ROOT,
            check=False,
            capture_output=True,
            env=git_environment,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise DomainError(
            "PRODUCTION_DEPLOY_SOURCE_INVALID",
            "checked-out source revision could not be verified",
        ) from error
    if (
        observed.returncode != 0
        or observed.stdout.strip() != coordinates["source_revision"]
    ):
        raise DomainError(
            "PRODUCTION_DEPLOY_SOURCE_INVALID",
            "checked-out source does not match the signed closure revision",
        )
    return coordinates


def _check_release_for_source(source_revision: str) -> int:
    previous = os.environ.get("GITHUB_SHA")
    os.environ["GITHUB_SHA"] = source_revision
    try:
        return check_release_evidence()
    finally:
        if previous is None:
            os.environ.pop("GITHUB_SHA", None)
        else:
            os.environ["GITHUB_SHA"] = previous


def _validate_output_contract(args: argparse.Namespace, *, operation: str) -> None:
    try:
        root = OUTPUT_ROOT.resolve(strict=True)
        root_metadata = root.stat()
    except OSError as error:
        raise DomainError(
            "PRODUCTION_DEPLOY_OUTPUT_INVALID",
            "production deployment evidence directory is missing",
        ) from error
    cursor = ROOT
    for component in OUTPUT_ROOT.relative_to(ROOT).parts:
        cursor /= component
        if cursor.is_symlink():
            raise DomainError(
                "PRODUCTION_DEPLOY_OUTPUT_INVALID",
                "production deployment evidence directory cannot contain symlinks",
            )
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.geteuid()
        or root_metadata.st_mode & 0o022
    ):
        raise DomainError(
            "PRODUCTION_DEPLOY_OUTPUT_INVALID",
            "production deployment evidence directory permissions are unsafe",
        )
    prefix = {
        "deploy": "deployment",
        "restore-prior-bundle": "prior-bundle-restore",
        "same-run-rollback": "same-run-rollback",
    }.get(operation)
    if prefix is None:
        raise DomainError(
            "PRODUCTION_DEPLOY_CONFIG_INVALID", "deployment operation is invalid"
        )
    expected = {
        "binding": f"{prefix}-binding.json",
        "recovery_envelope": f"{prefix}-recovery-envelope.json",
        "execution_envelope": f"{prefix}-execution-envelope.json",
        "journal": f"{prefix}-journal.json",
        "output": f"{prefix}-evidence.json",
    }
    for attribute, filename in expected.items():
        candidate = Path(getattr(args, attribute))
        try:
            parent = candidate.parent.resolve(strict=True)
        except OSError as error:
            raise DomainError(
                "PRODUCTION_DEPLOY_OUTPUT_INVALID",
                "production deployment output parent is missing",
            ) from error
        if parent != root or candidate.name != filename:
            raise DomainError(
                "PRODUCTION_DEPLOY_OUTPUT_INVALID",
                "production deployment output paths must use the sealed evidence directory",
            )
        if candidate.exists() or candidate.is_symlink():
            raise DomainError(
                "PRODUCTION_DEPLOY_OUTPUT_EXISTS",
                "refusing to overwrite an existing production deployment output",
            )
    plan = Path(args.plan)
    try:
        plan_parent = plan.parent.resolve(strict=True)
    except OSError as error:
        raise DomainError(
            "PRODUCTION_DEPLOY_PLAN_INVALID", "deployment plan parent is missing"
        ) from error
    if plan_parent != root or plan.name != "deployment-plan.json":
        raise DomainError(
            "PRODUCTION_DEPLOY_PLAN_INVALID",
            "deployment must use the closure-bound plan path",
        )
    _safe_bytes(
        plan,
        maximum_bytes=8 * 1024 * 1024,
        code="PRODUCTION_DEPLOY_PLAN_INVALID",
    )
    if operation == "deploy":
        return
    require_final = (
        operation == "restore-prior-bundle" and args.prior_conclusion == "failure"
    )
    raw_prior = (
        args.prior_binding,
        args.prior_recovery_envelope,
        args.prior_journal,
        *((args.prior_envelope, args.prior_evidence) if require_final else ()),
    )
    if any(value is None for value in raw_prior):
        raise DomainError(
            "PRIOR_DEPLOYMENT_EVIDENCE_REQUIRED",
            "prior binding, recovery envelope, and journal are required for recovery",
        )
    prior = {
        Path(args.prior_binding): "deployment-binding.json",
        Path(args.prior_recovery_envelope): "deployment-recovery-envelope.json",
        Path(args.prior_journal): "deployment-journal.json",
    }
    if require_final:
        prior.update(
            {
                Path(args.prior_envelope): "deployment-execution-envelope.json",
                Path(args.prior_evidence): "deployment-evidence.json",
            }
        )
    parents: set[Path] = set()
    for candidate, filename in prior.items():
        if candidate.name != filename or candidate.is_symlink():
            raise DomainError(
                "PRIOR_DEPLOYMENT_EVIDENCE_INVALID",
                "prior deployment artifact paths are invalid",
            )
        try:
            parents.add(candidate.parent.resolve(strict=True))
        except OSError as error:
            raise DomainError(
                "PRIOR_DEPLOYMENT_EVIDENCE_INVALID",
                "prior deployment artifact directory is missing",
            ) from error
    expected_count = 5 if require_final else 3
    if (
        len(prior) != expected_count
        or len(parents) != 1
        or operation == "restore-prior-bundle"
        and root in parents
        or operation == "same-run-rollback"
        and parents != {root}
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_EVIDENCE_INVALID",
            "prior deployment evidence must be one distinct downloaded artifact",
        )


def _safe_bytes(path: Path, *, maximum_bytes: int, code: str) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise DomainError(code, "no-follow file reads are unavailable on this runner")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DomainError(code, "input file is missing or unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022
            or not 1 <= metadata.st_size <= maximum_bytes
        ):
            raise DomainError(
                code,
                "input file is not an owned, bounded regular file protected from other writers",
            )
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) != metadata.st_size
            or after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
            or after.st_nlink != metadata.st_nlink
            or after.st_mode != metadata.st_mode
            or after.st_uid != metadata.st_uid
            or after.st_gid != metadata.st_gid
            or after.st_mtime_ns != metadata.st_mtime_ns
            or after.st_ctime_ns != metadata.st_ctime_ns
        ):
            raise DomainError(code, "input file changed while it was read")
        return payload
    finally:
        os.close(descriptor)


def _safe_json(path: Path, *, maximum_bytes: int, code: str) -> Any:
    try:
        return json.loads(
            _safe_bytes(path, maximum_bytes=maximum_bytes, code=code).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DomainError(code, "input file is not valid JSON") from error


def _safe_json_and_sha256(
    path: Path, *, maximum_bytes: int, code: str
) -> tuple[Any, str]:
    payload = _safe_bytes(path, maximum_bytes=maximum_bytes, code=code)
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DomainError(code, "input file is not valid JSON") from error
    return decoded, hashlib.sha256(payload).hexdigest()


def _execution_envelope(
    *,
    operation: str,
    binding_path: Path,
    journal_path: Path,
    evidence: GateEvidence,
) -> dict[str, Any]:
    binding, binding_sha256 = _safe_json_and_sha256(
        binding_path,
        maximum_bytes=1024 * 1024,
        code="PRODUCTION_DEPLOY_BINDING_INVALID",
    )
    if (
        not isinstance(binding, Mapping)
        or not DIGEST.fullmatch(str(binding.get("digest", "")))
        or binding.get("digest") != canonical_digest({**binding, "digest": ""})
    ):
        raise DomainError(
            "PRODUCTION_DEPLOY_BINDING_INVALID", "deployment binding digest is invalid"
        )
    journal, journal_sha256 = _safe_json_and_sha256(
        journal_path,
        maximum_bytes=8 * 1024 * 1024,
        code="PRODUCTION_DEPLOY_JOURNAL_INVALID",
    )
    if not isinstance(journal, list) or not journal:
        raise DomainError(
            "PRODUCTION_DEPLOY_JOURNAL_INVALID",
            "a non-empty journal is required for an execution envelope",
        )
    evidence_bytes = (canonical_json(asdict(evidence)) + "\n").encode("utf-8")
    payload: dict[str, Any] = {
        "schema_version": 1,
        "operation": operation,
        "binding_digest": str(binding["digest"]),
        "binding_sha256": binding_sha256,
        "journal_sha256": journal_sha256,
        "journal_entries": len(journal),
        "evidence_digest": evidence.digest,
        "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
        "status": evidence.status,
        "completed_at": utc_now(),
        "digest": "",
    }
    payload["digest"] = canonical_digest(payload)
    return payload


def _recovery_envelope(*, operation: str, binding_path: Path) -> dict[str, Any]:
    """Seal the recovery authority before the first Kubernetes mutation."""
    binding, binding_sha256 = _safe_json_and_sha256(
        binding_path,
        maximum_bytes=1024 * 1024,
        code="PRODUCTION_DEPLOY_BINDING_INVALID",
    )
    if (
        not isinstance(binding, Mapping)
        or not DIGEST.fullmatch(str(binding.get("digest", "")))
        or binding.get("digest") != canonical_digest({**binding, "digest": ""})
        or binding.get("operation") != operation
    ):
        raise DomainError(
            "PRODUCTION_DEPLOY_BINDING_INVALID",
            "deployment binding is invalid before recovery activation",
        )
    payload: dict[str, Any] = {
        "schema_version": 1,
        "operation": operation,
        "binding_digest": str(binding["digest"]),
        "binding_sha256": binding_sha256,
        "repository": str(binding.get("repository", "")),
        "github_run_id": str(binding.get("github_run_id", "")),
        "github_run_attempt": str(binding.get("github_run_attempt", "")),
        "plan_digest": str(binding.get("plan_digest", "")),
        "namespace": str(binding.get("namespace", "")),
        "cluster_uid_digest": str(binding.get("cluster_uid_digest", "")),
        "kubernetes_api_ca_digest": str(binding.get("kubernetes_api_ca_digest", "")),
        "activated_at": utc_now(),
        "digest": "",
    }
    payload["digest"] = canonical_digest(payload)
    return payload


def _validate_recovery_envelope(
    path: Path,
    *,
    binding: Mapping[str, Any],
    binding_sha256: str,
) -> dt.datetime:
    envelope = _safe_json(
        path,
        maximum_bytes=1024 * 1024,
        code="PRIOR_DEPLOYMENT_RECOVERY_ENVELOPE_INVALID",
    )
    expected_keys = {
        "schema_version",
        "operation",
        "binding_digest",
        "binding_sha256",
        "repository",
        "github_run_id",
        "github_run_attempt",
        "plan_digest",
        "namespace",
        "cluster_uid_digest",
        "kubernetes_api_ca_digest",
        "activated_at",
        "digest",
    }
    claimed_digest = (
        str(envelope.get("digest", "")) if isinstance(envelope, Mapping) else ""
    )
    if (
        not isinstance(envelope, Mapping)
        or set(envelope) != expected_keys
        or type(envelope.get("schema_version")) is not int
        or envelope.get("schema_version") != 1
        or envelope.get("operation") != binding.get("operation")
        or envelope.get("binding_digest") != binding.get("digest")
        or envelope.get("binding_sha256") != binding_sha256
        or any(
            envelope.get(key) != binding.get(key)
            for key in (
                "repository",
                "github_run_id",
                "github_run_attempt",
                "plan_digest",
                "namespace",
                "cluster_uid_digest",
                "kubernetes_api_ca_digest",
            )
        )
        or not DIGEST.fullmatch(claimed_digest)
        or claimed_digest != canonical_digest({**envelope, "digest": ""})
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_RECOVERY_ENVELOPE_INVALID",
            "recovery envelope does not bind the interrupted deployment",
        )
    try:
        activated = dt.datetime.fromisoformat(
            str(envelope["activated_at"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise DomainError(
            "PRIOR_DEPLOYMENT_RECOVERY_ENVELOPE_INVALID",
            "recovery envelope timestamp is invalid",
        ) from error
    if activated.tzinfo is None:
        raise DomainError(
            "PRIOR_DEPLOYMENT_RECOVERY_ENVELOPE_INVALID",
            "recovery envelope timestamp lacks a timezone",
        )
    return activated


def _atomic_binding(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise DomainError(
            "PRODUCTION_DEPLOY_BINDING_EXISTS",
            "refusing to overwrite an existing deployment binding",
        )
    descriptor, temporary = tempfile.mkstemp(
        prefix=".deployment-binding-", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(canonical_json(payload) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o444)
        os.link(temporary, path)
        os.unlink(temporary)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _verified_approval(
    closure: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    approval = closure.get("approval")
    if not isinstance(approval, Mapping):
        raise DomainError("PRODUCTION_CLOSURE_INVALID", "closure approval is missing")
    coordinates = approval.get("release_coordinates")
    if not isinstance(coordinates, Mapping):
        raise DomainError(
            "PRODUCTION_CLOSURE_INVALID", "closure release coordinates are missing"
        )
    approval_digest = str(approval.get("approval_digest", ""))
    release_digest = str(approval.get("release_digest", ""))
    if (
        not DIGEST.fullmatch(approval_digest)
        or approval_digest
        != canonical_digest(
            {key: value for key, value in approval.items() if key != "approval_digest"}
        )
        or not DIGEST.fullmatch(release_digest)
        or release_digest != canonical_digest(dict(coordinates))
    ):
        raise DomainError(
            "PRODUCTION_CLOSURE_INVALID", "closure approval digest is invalid"
        )
    return approval, coordinates


def _invocation_coordinates() -> tuple[str, str, str]:
    repository = _required("GITHUB_REPOSITORY")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise DomainError(
            "PRODUCTION_DEPLOY_INVOCATION_INVALID", "GitHub repository is invalid"
        )
    run_id = _positive_integer(
        _required("GITHUB_RUN_ID"),
        code="PRODUCTION_DEPLOY_INVOCATION_INVALID",
        label="GitHub run ID",
    )
    run_attempt = _positive_integer(
        _required("GITHUB_RUN_ATTEMPT"),
        code="PRODUCTION_DEPLOY_INVOCATION_INVALID",
        label="GitHub run attempt",
    )
    return repository, run_id, run_attempt


def _binding_payload(
    *,
    operation: str,
    closure_sha256: str,
    approval: Mapping[str, Any],
    plan: ProductionDeploymentPlan,
    cluster_uid_digest: str,
    api_ca_digest: str,
    repository: str,
    github_run_id: str,
    github_run_attempt: str,
    closure_artifact: Mapping[str, str],
    prior_binding_digest: str = "",
    prior_artifact_id: str = "",
    prior_artifact_sha256: str = "",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "operation": operation,
        "repository": repository,
        "github_run_id": github_run_id,
        "github_run_attempt": github_run_attempt,
        "closure_run_id": closure_artifact["closure_run_id"],
        "closure_run_attempt": closure_artifact["closure_run_attempt"],
        "closure_artifact_id": closure_artifact["closure_artifact_id"],
        "closure_artifact_sha256": closure_artifact["closure_artifact_sha256"],
        "source_revision": closure_artifact["source_revision"],
        "acceptance_run_id": str(approval["acceptance_run_id"]),
        "release_digest": str(approval["release_digest"]),
        "closure_input_sha256": closure_sha256,
        "closure_approval_digest": str(approval["approval_digest"]),
        "plan_id": plan.plan_id,
        "plan_digest": plan.digest,
        "namespace": plan.namespace,
        "cluster_uid_digest": cluster_uid_digest,
        "kubernetes_api_ca_digest": api_ca_digest,
        "backend_image": plan.backend_image,
        "web_image": plan.web_image,
        "rollback_images_digest": canonical_digest(list(plan.rollback_images)),
        "prior_binding_digest": prior_binding_digest,
        "prior_artifact_id": prior_artifact_id,
        "prior_artifact_sha256": prior_artifact_sha256,
        "created_at": utc_now(),
        "digest": "",
    }
    payload["digest"] = canonical_digest(payload)
    return payload


def _read_gate_evidence(path: Path) -> GateEvidence:
    payload = _safe_json(
        path, maximum_bytes=4 * 1024 * 1024, code="PRIOR_DEPLOYMENT_EVIDENCE_INVALID"
    )
    if not isinstance(payload, dict):
        raise DomainError(
            "PRIOR_DEPLOYMENT_EVIDENCE_INVALID", "prior evidence must be an object"
        )
    try:
        payload["checks"] = tuple(
            GateCheck(**item) for item in payload.get("checks", ())
        )
        evidence = GateEvidence(**payload)
        evidence.verify()
    except Exception as error:
        raise DomainError(
            "PRIOR_DEPLOYMENT_EVIDENCE_INVALID", "prior evidence digest is invalid"
        ) from error
    return evidence


def _reject_completed_same_run_recovery(
    directory: Path,
    *,
    prior_binding: Mapping[str, Any],
    prior_binding_digest: str,
) -> None:
    """Reject a later mutation when the same run already sealed successful recovery."""
    paths = {
        "binding": directory / "same-run-rollback-binding.json",
        "recovery": directory / "same-run-rollback-recovery-envelope.json",
        "journal": directory / "same-run-rollback-journal.json",
        "evidence": directory / "same-run-rollback-evidence.json",
        "execution": directory / "same-run-rollback-execution-envelope.json",
    }
    present = {name: path.exists() or path.is_symlink() for name, path in paths.items()}
    if not any(present.values()):
        return
    if not all(present.values()):
        # A second interrupted recovery remains recoverable from the original durable
        # mutation marker; only a complete, digest-valid recovery blocks another apply.
        return
    binding, binding_sha256 = _safe_json_and_sha256(
        paths["binding"],
        maximum_bytes=1024 * 1024,
        code="PRIOR_DEPLOYMENT_RECOVERY_COMPLETION_INVALID",
    )
    if (
        not isinstance(binding, Mapping)
        or set(binding) != DEPLOYMENT_BINDING_KEYS
        or type(binding.get("schema_version")) is not int
        or binding.get("schema_version") != 1
        or binding.get("operation") != "same-run-rollback"
        or binding.get("prior_binding_digest") != prior_binding_digest
        or binding.get("prior_artifact_id") != ""
        or binding.get("prior_artifact_sha256") != ""
        or any(
            binding.get(key) != prior_binding.get(key)
            for key in (
                "repository",
                "github_run_id",
                "github_run_attempt",
                "closure_run_id",
                "closure_run_attempt",
                "closure_artifact_id",
                "closure_artifact_sha256",
                "source_revision",
                "acceptance_run_id",
                "release_digest",
                "closure_input_sha256",
                "closure_approval_digest",
                "plan_id",
                "plan_digest",
                "namespace",
                "cluster_uid_digest",
                "kubernetes_api_ca_digest",
                "backend_image",
                "web_image",
                "rollback_images_digest",
            )
        )
        or not DIGEST.fullmatch(str(binding.get("digest", "")))
        or binding.get("digest") != canonical_digest({**binding, "digest": ""})
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_RECOVERY_COMPLETION_INVALID",
            "same-run recovery binding is invalid",
        )
    recovery_activated = _validate_recovery_envelope(
        paths["recovery"], binding=binding, binding_sha256=binding_sha256
    )
    try:
        binding_created = dt.datetime.fromisoformat(
            str(binding["created_at"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise DomainError(
            "PRIOR_DEPLOYMENT_RECOVERY_COMPLETION_INVALID",
            "same-run recovery binding timestamp is invalid",
        ) from error
    if binding_created.tzinfo is None or binding_created > recovery_activated:
        raise DomainError(
            "PRIOR_DEPLOYMENT_RECOVERY_COMPLETION_INVALID",
            "same-run recovery activation ordering is invalid",
        )
    journal, journal_sha256 = _safe_json_and_sha256(
        paths["journal"],
        maximum_bytes=8 * 1024 * 1024,
        code="PRIOR_DEPLOYMENT_RECOVERY_COMPLETION_INVALID",
    )
    if not isinstance(journal, list) or not journal:
        raise DomainError(
            "PRIOR_DEPLOYMENT_RECOVERY_COMPLETION_INVALID",
            "same-run recovery journal is invalid",
        )
    evidence = _read_gate_evidence(paths["evidence"])
    expected_target_digests = {
        canonical_digest(
            {
                "prior_binding_digest": prior_binding_digest,
                "prior_artifact_id": "",
                "prior_artifact_sha256": "",
                "interrupted_state": state,
                "plan_digest": prior_binding.get("plan_digest"),
                "namespace": prior_binding.get("namespace"),
                "cluster_uid_digest": prior_binding.get("cluster_uid_digest"),
                "kubernetes_api_ca_digest": prior_binding.get(
                    "kubernetes_api_ca_digest"
                ),
            }
        )
        for state in ("no_mutation", "unfinished", "restored")
    }
    if (
        evidence.gate != "production_same_run_rollback"
        or evidence.status != "PASSED"
        or evidence.acceptance_run_id != prior_binding.get("acceptance_run_id")
        or evidence.release_digest != prior_binding.get("release_digest")
        or evidence.target_digest not in expected_target_digests
        or [check.name for check in evidence.checks]
        != [
            "rollback_specific_confirmation",
            "prior_recovery_envelope_verified",
            "interruption_activation_verified",
            "interrupted_journal_verified",
            "sealed_prior_bundle_safe",
        ]
        or not all(check.passed and not check.details for check in evidence.checks)
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_RECOVERY_COMPLETION_INVALID",
            "same-run recovery evidence is invalid",
        )
    envelope = _safe_json(
        paths["execution"],
        maximum_bytes=1024 * 1024,
        code="PRIOR_DEPLOYMENT_RECOVERY_COMPLETION_INVALID",
    )
    evidence_bytes = (canonical_json(asdict(evidence)) + "\n").encode("utf-8")
    envelope_keys = {
        "schema_version",
        "operation",
        "binding_digest",
        "binding_sha256",
        "journal_sha256",
        "journal_entries",
        "evidence_digest",
        "evidence_sha256",
        "status",
        "completed_at",
        "digest",
    }
    if (
        not isinstance(envelope, Mapping)
        or set(envelope) != envelope_keys
        or type(envelope.get("schema_version")) is not int
        or envelope.get("schema_version") != 1
        or envelope.get("operation") != "same-run-rollback"
        or envelope.get("binding_digest") != binding.get("digest")
        or envelope.get("binding_sha256") != binding_sha256
        or envelope.get("journal_sha256") != journal_sha256
        or type(envelope.get("journal_entries")) is not int
        or envelope.get("journal_entries") != len(journal)
        or envelope.get("evidence_digest") != evidence.digest
        or envelope.get("evidence_sha256") != hashlib.sha256(evidence_bytes).hexdigest()
        or envelope.get("status") != "PASSED"
        or not DIGEST.fullmatch(str(envelope.get("digest", "")))
        or envelope.get("digest") != canonical_digest({**envelope, "digest": ""})
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_RECOVERY_COMPLETION_INVALID",
            "same-run recovery execution envelope is invalid",
        )
    try:
        completed = dt.datetime.fromisoformat(
            str(envelope["completed_at"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise DomainError(
            "PRIOR_DEPLOYMENT_RECOVERY_COMPLETION_INVALID",
            "same-run recovery completion timestamp is invalid",
        ) from error
    if (
        completed.tzinfo is None
        or completed < recovery_activated
        or completed > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_RECOVERY_COMPLETION_INVALID",
            "same-run recovery completion ordering is invalid",
        )
    raise DomainError(
        "PRIOR_DEPLOYMENT_ALREADY_RECOVERED",
        "same-run recovery already restored and sealed the prior bundle",
    )


@dataclass(frozen=True)
class _JournalState:
    started_at: dt.datetime
    completed_at: dt.datetime
    state: str
    rollback_attempts: int


def _validate_journal(
    payload: Any,
    *,
    plan: ProductionDeploymentPlan,
    cluster_uid_digest: str,
    api_ca_digest: str,
) -> _JournalState:
    if not isinstance(payload, list) or not payload:
        raise DomainError(
            "PRIOR_DEPLOYMENT_JOURNAL_INVALID", "prior deployment journal is empty"
        )
    phases: list[str] = []
    cluster_verified = False
    first_timestamp: dt.datetime | None = None
    previous_timestamp: dt.datetime | None = None
    for entry in payload:
        if not isinstance(entry, Mapping):
            raise DomainError(
                "PRIOR_DEPLOYMENT_JOURNAL_INVALID", "journal entries must be objects"
            )
        phase = str(entry.get("phase", ""))
        extra_keys = JOURNAL_PHASE_KEYS.get(phase)
        if extra_keys is None or set(entry) != JOURNAL_COMMON_KEYS | extra_keys:
            raise DomainError(
                "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
                "journal fields or phase are invalid",
            )
        try:
            timestamp = dt.datetime.fromisoformat(
                str(entry["at"]).replace("Z", "+00:00")
            )
        except ValueError as error:
            raise DomainError(
                "PRIOR_DEPLOYMENT_JOURNAL_INVALID", "journal timestamp is invalid"
            ) from error
        if timestamp.tzinfo is None:
            raise DomainError(
                "PRIOR_DEPLOYMENT_JOURNAL_INVALID", "journal timestamp lacks a timezone"
            )
        if previous_timestamp is not None and timestamp < previous_timestamp:
            raise DomainError(
                "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
                "journal timestamps are not monotonic",
            )
        if first_timestamp is None:
            first_timestamp = timestamp
        previous_timestamp = timestamp
        if (
            entry.get("plan_id") != plan.plan_id
            or entry.get("plan_digest") != plan.digest
            or entry.get("namespace") != plan.namespace
        ):
            raise DomainError(
                "PRIOR_DEPLOYMENT_JOURNAL_INVALID", "journal plan binding is invalid"
            )
        entry_cluster = str(entry.get("cluster_uid_digest", ""))
        if phase == "cluster_identity_verified":
            if (
                entry_cluster != cluster_uid_digest
                or entry.get("kubernetes_api_ca_digest") != api_ca_digest
            ):
                raise DomainError(
                    "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
                    "journal target cluster binding is invalid",
                )
            cluster_verified = True
        elif not cluster_verified or entry_cluster != cluster_uid_digest:
            raise DomainError(
                "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
                "journal entry predates verified cluster identity",
            )
        if phase == "rbac_verified" and (
            type(entry.get("permission_count")) is not int
            or entry.get("permission_count") != len(PUBLISH_RBAC)
        ):
            raise DomainError(
                "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
                "journal RBAC verification count is invalid",
            )
        if phase == "manifest_applied" and not DIGEST.fullmatch(
            str(entry.get("artifact_sha256", ""))
        ):
            raise DomainError(
                "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
                "journal manifest digest is invalid",
            )
        if (
            phase in {"migration_stop_attempted", "migration_stopped"}
            and entry.get("resource") != f"job/{plan.migration_job}"
        ):
            raise DomainError(
                "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
                "journal migration resource is invalid",
            )
        if phase == "candidate_inventory_pruned":
            resources = entry.get("resources")
            if (
                not isinstance(resources, list)
                or len(resources) > 256
                or any(not isinstance(resource, str) for resource in resources)
                or len(resources) != len(set(resources))
                or any(
                    not re.fullmatch(
                        r"[a-z][a-z0-9.-]*/[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?",
                        resource,
                    )
                    for resource in resources
                )
            ):
                raise DomainError(
                    "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
                    "journal pruned resource inventory is invalid",
                )
        phases.append(phase)
    if first_timestamp is None or previous_timestamp is None:
        raise DomainError(
            "PRIOR_DEPLOYMENT_JOURNAL_INVALID", "journal timestamps are missing"
        )
    preflight = [
        "cluster_identity_verified",
        "rbac_verified",
        "server_dry_run_completed",
    ]
    if (
        not cluster_verified
        or (phases != preflight[: len(phases)] and phases[:3] != preflight)
        or phases.count("cluster_identity_verified") != 1
        or phases.count("rbac_verified") > 1
        or phases.count("server_dry_run_completed") > 1
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
            "journal preflight phases are not an authentic execution prefix",
        )
    mutation_markers = [
        index
        for index, phase in enumerate(phases)
        if phase == "candidate_mutation_started"
    ]
    if not mutation_markers:
        if phases != preflight[: len(phases)]:
            raise DomainError(
                "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
                "journal contains mutation phases without the durable mutation marker",
            )
        return _JournalState(first_timestamp, previous_timestamp, "no_mutation", 0)
    if mutation_markers != [3] or phases[:3] != preflight:
        raise DomainError(
            "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
            "candidate mutation marker is missing, duplicated, or out of order",
        )
    rollback_attempts = [
        index for index, phase in enumerate(phases) if phase == "rollback_attempted"
    ]
    rollback_successes = [
        index for index, phase in enumerate(phases) if phase == "rollback_succeeded"
    ]
    deployment_successes = [
        index for index, phase in enumerate(phases) if phase == "deployment_succeeded"
    ]
    if (
        len(rollback_attempts) > 2
        or len(rollback_successes) > 1
        or len(deployment_successes) > 1
        or rollback_successes
        and deployment_successes
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
            "journal terminal or rollback phases are ambiguous",
        )
    attempts = [payload[index] for index in rollback_attempts]
    if any(
        attempt.get("attempted") is not True or attempt.get("succeeded") is not False
        for attempt in attempts
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_JOURNAL_INVALID", "rollback attempt marker is invalid"
        )
    terminal_positions = rollback_attempts + rollback_successes + deployment_successes
    candidate_end = min(terminal_positions) if terminal_positions else len(payload)
    candidate_entries = payload[4:candidate_end]
    candidate_hashes = [
        plan.bootstrap_manifest.sha256,
        plan.migration_manifest.sha256,
        plan.runtime_manifest.sha256,
    ]
    if (
        len(candidate_entries) > len(candidate_hashes)
        or any(entry.get("phase") != "manifest_applied" for entry in candidate_entries)
        or [entry.get("artifact_sha256") for entry in candidate_entries]
        != candidate_hashes[: len(candidate_entries)]
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
            "candidate journal phases are not an authentic deployment prefix",
        )
    expected_resources = [f"{item.kind}/{item.name}" for item in plan.workloads]

    def _valid_terminal(entry: Mapping[str, Any], *, rollback: bool) -> bool:
        revisions = entry.get("revisions")
        resources = entry.get("resources")
        if (
            not isinstance(revisions, Mapping)
            or set(revisions) != {item.name for item in plan.workloads}
            or any(
                not isinstance(value, str)
                or not re.fullmatch(r"[A-Za-z0-9._:/-]{1,256}", value)
                for value in revisions.values()
            )
            or resources != expected_resources
        ):
            return False
        return (
            entry.get("attempted") is True and entry.get("succeeded") is True
            if rollback
            else True
        )

    if deployment_successes:
        success_index = deployment_successes[0]
        if (
            success_index != len(payload) - 1
            or rollback_attempts
            or len(candidate_entries) != len(candidate_hashes)
            or not _valid_terminal(payload[success_index], rollback=False)
        ):
            raise DomainError(
                "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
                "deployment success marker is not an authentic terminal phase",
            )
        return _JournalState(first_timestamp, previous_timestamp, "deployed", 0)
    rollback_prefix = [
        "migration_stop_attempted",
        "migration_stopped",
        "manifest_applied",
        "candidate_inventory_pruned",
    ]
    for position, attempt_index in enumerate(rollback_attempts):
        candidates = rollback_attempts[position + 1 :]
        if rollback_successes:
            candidates.append(rollback_successes[0])
        end = min(candidates) if candidates else len(payload)
        segment = payload[attempt_index + 1 : end]
        segment_phases = [str(entry["phase"]) for entry in segment]
        if segment_phases != rollback_prefix[: len(segment_phases)]:
            raise DomainError(
                "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
                "rollback journal phases are not an authentic execution prefix",
            )
        if (
            len(segment) >= 3
            and segment[2].get("artifact_sha256") != plan.rollback_manifest.sha256
        ):
            raise DomainError(
                "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
                "rollback journal does not use the sealed prior manifest",
            )
    if rollback_successes:
        success_index = rollback_successes[0]
        if (
            not rollback_attempts
            or success_index != len(payload) - 1
            or [
                str(entry["phase"])
                for entry in payload[rollback_attempts[-1] + 1 : success_index]
            ]
            != rollback_prefix
            or not _valid_terminal(payload[success_index], rollback=True)
        ):
            raise DomainError(
                "PRIOR_DEPLOYMENT_JOURNAL_INVALID",
                "rollback success marker is not an authentic terminal phase",
            )
        return _JournalState(
            first_timestamp,
            previous_timestamp,
            "restored",
            len(rollback_attempts),
        )
    return _JournalState(
        first_timestamp,
        previous_timestamp,
        "unfinished",
        len(rollback_attempts),
    )


def _validate_prior_deployment(
    *,
    binding_path: Path,
    recovery_envelope_path: Path,
    envelope_path: Path | None,
    evidence_path: Path | None,
    journal_path: Path,
    expected_run_id: str,
    expected_run_attempt: str,
    expected_conclusion: str,
    closure_sha256: str,
    approval: Mapping[str, Any],
    plan: ProductionDeploymentPlan,
    cluster_uid_digest: str,
    api_ca_digest: str,
    repository: str,
    closure_artifact: Mapping[str, str],
) -> tuple[str, str]:
    binding, binding_sha256 = _safe_json_and_sha256(
        binding_path,
        maximum_bytes=1024 * 1024,
        code="PRIOR_DEPLOYMENT_BINDING_INVALID",
    )
    if not isinstance(binding, Mapping) or set(binding) != DEPLOYMENT_BINDING_KEYS:
        raise DomainError(
            "PRIOR_DEPLOYMENT_BINDING_INVALID",
            "prior deployment binding fields are invalid",
        )
    claimed_digest = str(binding.get("digest", ""))
    if (
        type(binding.get("schema_version")) is not int
        or binding.get("schema_version") != 1
        or binding.get("operation") != "deploy"
        or binding.get("repository") != repository
        or binding.get("github_run_id") != expected_run_id
        or binding.get("github_run_attempt") != expected_run_attempt
        or binding.get("closure_run_id") != closure_artifact["closure_run_id"]
        or binding.get("closure_run_attempt") != closure_artifact["closure_run_attempt"]
        or binding.get("closure_artifact_id") != closure_artifact["closure_artifact_id"]
        or binding.get("closure_artifact_sha256")
        != closure_artifact["closure_artifact_sha256"]
        or binding.get("source_revision") != closure_artifact["source_revision"]
        or binding.get("acceptance_run_id") != approval.get("acceptance_run_id")
        or binding.get("release_digest") != approval.get("release_digest")
        or binding.get("closure_input_sha256") != closure_sha256
        or binding.get("closure_approval_digest") != approval.get("approval_digest")
        or binding.get("plan_id") != plan.plan_id
        or binding.get("plan_digest") != plan.digest
        or binding.get("namespace") != plan.namespace
        or binding.get("cluster_uid_digest") != cluster_uid_digest
        or binding.get("kubernetes_api_ca_digest") != api_ca_digest
        or binding.get("backend_image") != plan.backend_image
        or binding.get("web_image") != plan.web_image
        or binding.get("rollback_images_digest")
        != canonical_digest(list(plan.rollback_images))
        or binding.get("prior_binding_digest") != ""
        or binding.get("prior_artifact_id") != ""
        or binding.get("prior_artifact_sha256") != ""
        or not DIGEST.fullmatch(claimed_digest)
        or claimed_digest != canonical_digest({**binding, "digest": ""})
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_BINDING_INVALID",
            "prior deployment does not match this closure, plan, target, or candidate",
        )
    try:
        created = dt.datetime.fromisoformat(
            str(binding["created_at"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise DomainError(
            "PRIOR_DEPLOYMENT_BINDING_INVALID", "prior binding timestamp is invalid"
        ) from error
    if created.tzinfo is None:
        raise DomainError(
            "PRIOR_DEPLOYMENT_BINDING_INVALID",
            "prior binding timestamp lacks a timezone",
        )
    now = dt.datetime.now(dt.timezone.utc)
    if created > now + dt.timedelta(minutes=5):
        raise DomainError(
            "PRIOR_DEPLOYMENT_BINDING_INVALID",
            "prior binding timestamp is in the future",
        )
    recovery_activated = _validate_recovery_envelope(
        recovery_envelope_path,
        binding=binding,
        binding_sha256=binding_sha256,
    )
    journal, journal_sha256 = _safe_json_and_sha256(
        journal_path,
        maximum_bytes=8 * 1024 * 1024,
        code="PRIOR_DEPLOYMENT_JOURNAL_INVALID",
    )
    journal_state = _validate_journal(
        journal,
        plan=plan,
        cluster_uid_digest=cluster_uid_digest,
        api_ca_digest=api_ca_digest,
    )
    if (
        recovery_activated < created
        or recovery_activated > journal_state.started_at
        or journal_state.completed_at > now + dt.timedelta(minutes=5)
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_RECOVERY_ENVELOPE_INVALID",
            "binding, recovery envelope, and journal ordering is invalid",
        )
    if expected_conclusion != "same-run" and journal_state.state == "unfinished":
        _reject_completed_same_run_recovery(
            journal_path.parent,
            prior_binding=binding,
            prior_binding_digest=claimed_digest,
        )
    if expected_conclusion in {"cancelled", "same-run"}:
        if expected_conclusion == "cancelled" and journal_state.state != "unfinished":
            raise DomainError(
                "PRIOR_DEPLOYMENT_NOT_RESTORABLE",
                "cancelled deployment journal does not prove unfinished mutation",
            )
        return claimed_digest, journal_state.state
    if expected_conclusion != "failure":
        raise DomainError(
            "PRIOR_DEPLOYMENT_EVIDENCE_INVALID",
            "prior deployment conclusion is invalid",
        )
    if (
        journal_state.state != "unfinished"
        or journal_state.rollback_attempts < 1
        or evidence_path is None
        or envelope_path is None
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_NOT_RESTORABLE",
            "failed deployment does not prove an attempted unfinished rollback",
        )
    evidence = _read_gate_evidence(evidence_path)
    if (
        evidence.gate != "production_deployment"
        or evidence.status != "FAILED"
        or evidence.schema_version != 2
        or evidence.acceptance_run_id != approval.get("acceptance_run_id")
        or evidence.release_digest != approval.get("release_digest")
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_EVIDENCE_INVALID",
            "prior evidence is not a closure-bound failed deployment",
        )
    envelope = _safe_json(
        envelope_path,
        maximum_bytes=1024 * 1024,
        code="PRIOR_DEPLOYMENT_ENVELOPE_INVALID",
    )
    envelope_keys = {
        "schema_version",
        "operation",
        "binding_digest",
        "binding_sha256",
        "journal_sha256",
        "journal_entries",
        "evidence_digest",
        "evidence_sha256",
        "status",
        "completed_at",
        "digest",
    }
    if not isinstance(envelope, Mapping) or set(envelope) != envelope_keys:
        raise DomainError(
            "PRIOR_DEPLOYMENT_ENVELOPE_INVALID",
            "prior execution envelope fields are invalid",
        )
    envelope_digest = str(envelope.get("digest", ""))
    evidence_bytes = (canonical_json(asdict(evidence)) + "\n").encode("utf-8")
    if (
        type(envelope.get("schema_version")) is not int
        or envelope.get("schema_version") != 1
        or envelope.get("operation") != "deploy"
        or envelope.get("binding_digest") != claimed_digest
        or envelope.get("binding_sha256") != binding_sha256
        or envelope.get("journal_sha256") != journal_sha256
        or type(envelope.get("journal_entries")) is not int
        or envelope.get("journal_entries") != len(journal)
        or envelope.get("evidence_digest") != evidence.digest
        or envelope.get("evidence_sha256") != hashlib.sha256(evidence_bytes).hexdigest()
        or envelope.get("status") != "FAILED"
        or not DIGEST.fullmatch(envelope_digest)
        or envelope_digest != canonical_digest({**envelope, "digest": ""})
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_ENVELOPE_INVALID",
            "prior execution envelope does not bind its evidence and journal",
        )
    try:
        envelope_completed = dt.datetime.fromisoformat(
            str(envelope["completed_at"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise DomainError(
            "PRIOR_DEPLOYMENT_ENVELOPE_INVALID",
            "prior execution envelope timestamp is invalid",
        ) from error
    if (
        envelope_completed.tzinfo is None
        or envelope_completed < created
        or envelope_completed > now + dt.timedelta(minutes=5)
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_ENVELOPE_INVALID",
            "prior execution envelope timestamp is inconsistent",
        )
    evidence_completed = dt.datetime.fromisoformat(
        evidence.completed_at.replace("Z", "+00:00")
    )
    if (
        journal_state.started_at < created
        or journal_state.completed_at > evidence_completed
        or evidence_completed > envelope_completed
        or journal_state.started_at > now + dt.timedelta(minutes=5)
        or evidence_completed > now + dt.timedelta(minutes=5)
    ):
        raise DomainError(
            "PRIOR_DEPLOYMENT_ENVELOPE_INVALID",
            "prior binding, journal, evidence, and envelope ordering is invalid",
        )
    return claimed_digest, journal_state.state


def _signed_target_cluster_digest(
    *,
    environment_digest: str,
    coordinates: Mapping[str, object],
    plan: ProductionDeploymentPlan,
) -> tuple[str, str]:
    report_path = (
        ROOT / "docs/evidence/batch-24/production/formal-benchmark/report.json"
    )
    report = _safe_json(
        report_path,
        maximum_bytes=16 * 1024 * 1024,
        code="PRODUCTION_TARGET_PROFILE_INVALID",
    )
    if not isinstance(report, Mapping):
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID", "formal benchmark report is invalid"
        )
    artifacts = report.get("artifacts", ())
    if not isinstance(artifacts, list) or any(
        not isinstance(item, Mapping) for item in artifacts
    ):
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID",
            "formal benchmark artifact inventory is invalid",
        )
    targets = [item for item in artifacts if item.get("kind") == "target_profile"]
    if (
        len(targets) != 1
        or report.get("target_profile_digest") != environment_digest
        or targets[0].get("sha256") != environment_digest
    ):
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID",
            "closure-bound target profile artifact is missing",
        )
    target_source = ROOT / str(targets[0].get("path", ""))
    try:
        target_path = target_source.resolve(strict=True)
    except OSError as error:
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID", "target profile path is missing"
        ) from error
    if ROOT.resolve() not in target_path.parents or target_source.is_symlink():
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID", "target profile path is unsafe"
        )
    target, target_sha256 = _safe_json_and_sha256(
        target_source,
        maximum_bytes=16 * 1024 * 1024,
        code="PRODUCTION_TARGET_PROFILE_INVALID",
    )
    if target_sha256 != environment_digest:
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID", "target profile digest mismatch"
        )
    if not isinstance(target, Mapping):
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID", "target profile is invalid"
        )
    validate_production_storage_target(target)
    if (
        target.get("candidate_image") != coordinates.get("candidate_image")
        or target.get("build_digest") != coordinates.get("build_digest")
        or target.get("simulator_build_digest")
        != coordinates.get("simulator_build_digest")
        or target.get("deployment_plan_digest")
        != coordinates.get("deployment_plan_digest")
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
        or target.get("aws_account_id") != plan.object_storage_account_id
        or plan.object_storage_region != plan.storage_egress_contract.region
        or target.get("aws_partition") != plan.storage_egress_contract.partition
        or target.get("storage_egress_contract_digest")
        != plan.storage_egress_contract.digest
        or not DIGEST.fullmatch(str(target.get("cluster_uid_digest", "")))
        or not DIGEST.fullmatch(str(target.get("kubernetes_api_ca_digest", "")))
    ):
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID",
            "target profile release coordinates mismatch",
        )
    return str(target["cluster_uid_digest"]), str(target["kubernetes_api_ca_digest"])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deploy one closure-bound release to the approved Kubernetes target"
    )
    parser.add_argument(
        "--plan",
        type=Path,
        default=ROOT
        / "docs/evidence/batch-24/production-deployment/deployment-plan.json",
    )
    parser.add_argument(
        "--journal",
        type=Path,
        default=ROOT
        / "docs/evidence/batch-24/production-deployment/deployment-journal.json",
    )
    parser.add_argument(
        "--break-glass-restore",
        action="store_true",
        help=(
            "restore the sealed prior bundle only after independently verifying a "
            "closure-bound failed deployment and its unfinished rollback journal"
        ),
    )
    parser.add_argument(
        "--same-run-rollback",
        action="store_true",
        help=(
            "verify this workflow attempt's immutable activation record and "
            "finish an interrupted rollback with independent authorization"
        ),
    )
    parser.add_argument(
        "--binding",
        type=Path,
        default=ROOT
        / "docs/evidence/batch-24/production-deployment/deployment-binding.json",
    )
    parser.add_argument(
        "--recovery-envelope",
        type=Path,
        default=ROOT
        / "docs/evidence/batch-24/production-deployment/deployment-recovery-envelope.json",
    )
    parser.add_argument(
        "--execution-envelope",
        type=Path,
        default=ROOT
        / "docs/evidence/batch-24/production-deployment/deployment-execution-envelope.json",
    )
    parser.add_argument("--prior-binding", type=Path)
    parser.add_argument("--prior-recovery-envelope", type=Path)
    parser.add_argument("--prior-envelope", type=Path)
    parser.add_argument("--prior-evidence", type=Path)
    parser.add_argument("--prior-journal", type=Path)
    parser.add_argument("--prior-conclusion", choices=("failure", "cancelled"))
    parser.add_argument("--prior-deployment-run-id")
    parser.add_argument("--prior-deployment-run-attempt")
    parser.add_argument("--prior-deployment-artifact-id")
    parser.add_argument("--prior-deployment-artifact-sha256")
    parser.add_argument(
        "--rollback-only",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT
        / "docs/evidence/batch-24/production-deployment/deployment-evidence.json",
    )
    args = parser.parse_args()
    restore = bool(args.break_glass_restore)
    same_run = bool(args.same_run_rollback)
    operation = (
        "same-run-rollback"
        if same_run
        else "restore-prior-bundle"
        if restore
        else "deploy"
    )
    try:
        if restore and same_run:
            raise DomainError(
                "PRODUCTION_DEPLOY_CONFIG_INVALID",
                "break-glass restore and same-run rollback are mutually exclusive",
            )
        _validate_output_contract(args, operation=operation)
    except DomainError as error:
        print(
            canonical_json(
                {
                    "gate": (
                        "production_prior_bundle_restore"
                        if restore
                        else "production_same_run_rollback"
                        if same_run
                        else "production_deployment"
                    ),
                    "status": "FAILED",
                    "error_code": error.code,
                }
            )
        )
        return 1
    started = utc_now()
    run_id = "unbound-" + canonical_digest({"started_at": started})[:20]
    release_digest = canonical_digest({"configuration": "incomplete"})
    gate_name = (
        "production_prior_bundle_restore"
        if restore
        else "production_same_run_rollback"
        if same_run
        else "production_deployment"
    )
    evidence: GateEvidence
    try:
        if args.rollback_only:
            raise DomainError(
                "UNBOUND_ROLLBACK_FORBIDDEN",
                "--rollback-only is unsafe; use the closure-bound break-glass restore contract",
            )
        closure_artifact = _closure_artifact_coordinates()
        if _check_release_for_source(closure_artifact["source_revision"]) != 0:
            raise DomainError(
                "PRODUCTION_CLOSURE_REQUIRED",
                "verified production closure is required before deployment",
            )
        closure, closure_sha256 = _safe_json_and_sha256(
            CLOSURE_INPUT,
            maximum_bytes=16 * 1024 * 1024,
            code="PRODUCTION_CLOSURE_INVALID",
        )
        if not isinstance(closure, Mapping):
            raise DomainError(
                "PRODUCTION_CLOSURE_INVALID", "closure input must be an object"
            )
        approval, coordinates = _verified_approval(closure)
        run_id = str(approval["acceptance_run_id"])
        release_digest = str(approval["release_digest"])
        plan = ProductionDeploymentPlan.load(
            ROOT,
            args.plan,
            candidate_image=str(coordinates["candidate_image"]),
            expected_digest=str(coordinates["deployment_plan_digest"]),
        )
        cluster_uid_digest, api_ca_digest = _signed_target_cluster_digest(
            environment_digest=str(coordinates["environment_digest"]),
            coordinates=coordinates,
            plan=plan,
        )
        repository, github_run_id, github_run_attempt = _invocation_coordinates()
        prior_binding_digest = ""
        prior_artifact_id = ""
        prior_artifact_sha256 = ""
        recovery_state = ""
        if restore:
            if (
                args.prior_binding is None
                or args.prior_recovery_envelope is None
                or args.prior_journal is None
                or args.prior_conclusion not in {"failure", "cancelled"}
                or args.prior_conclusion == "failure"
                and (args.prior_envelope is None or args.prior_evidence is None)
                or args.prior_conclusion == "cancelled"
                and (args.prior_envelope is not None or args.prior_evidence is not None)
            ):
                raise DomainError(
                    "PRIOR_DEPLOYMENT_EVIDENCE_REQUIRED",
                    "prior recovery inputs do not match the selected run conclusion",
                )
            prior_run_id = _positive_integer(
                str(args.prior_deployment_run_id or ""),
                code="PRIOR_DEPLOYMENT_EVIDENCE_REQUIRED",
                label="prior deployment run ID",
            )
            prior_run_attempt = _positive_integer(
                str(args.prior_deployment_run_attempt or ""),
                code="PRIOR_DEPLOYMENT_EVIDENCE_REQUIRED",
                label="prior deployment run attempt",
            )
            prior_artifact_id = _positive_integer(
                str(args.prior_deployment_artifact_id or ""),
                code="PRIOR_DEPLOYMENT_EVIDENCE_REQUIRED",
                label="prior deployment artifact ID",
            )
            prior_artifact_sha256 = str(args.prior_deployment_artifact_sha256 or "")
            if not DIGEST.fullmatch(prior_artifact_sha256):
                raise DomainError(
                    "PRIOR_DEPLOYMENT_EVIDENCE_REQUIRED",
                    "prior deployment artifact digest is required",
                )
            if prior_run_id == github_run_id:
                raise DomainError(
                    "PRIOR_DEPLOYMENT_EVIDENCE_INVALID",
                    "restore must reference a distinct prior deployment run",
                )
            prior_binding_digest, recovery_state = _validate_prior_deployment(
                binding_path=args.prior_binding,
                recovery_envelope_path=args.prior_recovery_envelope,
                envelope_path=args.prior_envelope,
                evidence_path=args.prior_evidence,
                journal_path=args.prior_journal,
                expected_run_id=prior_run_id,
                expected_run_attempt=prior_run_attempt,
                expected_conclusion=args.prior_conclusion,
                closure_sha256=closure_sha256,
                approval=approval,
                plan=plan,
                cluster_uid_digest=cluster_uid_digest,
                api_ca_digest=api_ca_digest,
                repository=repository,
                closure_artifact=closure_artifact,
            )
            publisher_confirmation = _required(
                "SHADOW_PRODUCTION_ROLLBACK_CONFIRMATION"
            )
        elif same_run:
            if (
                args.prior_binding is None
                or args.prior_recovery_envelope is None
                or args.prior_journal is None
                or any(
                    value is not None
                    for value in (
                        args.prior_envelope,
                        args.prior_evidence,
                        args.prior_conclusion,
                        args.prior_deployment_run_id,
                        args.prior_deployment_run_attempt,
                        args.prior_deployment_artifact_id,
                        args.prior_deployment_artifact_sha256,
                    )
                )
            ):
                raise DomainError(
                    "PRIOR_DEPLOYMENT_EVIDENCE_REQUIRED",
                    "same-run recovery requires only this run's binding, recovery envelope, and journal",
                )
            prior_binding_digest, recovery_state = _validate_prior_deployment(
                binding_path=args.prior_binding,
                recovery_envelope_path=args.prior_recovery_envelope,
                envelope_path=None,
                evidence_path=None,
                journal_path=args.prior_journal,
                expected_run_id=github_run_id,
                expected_run_attempt=github_run_attempt,
                expected_conclusion="same-run",
                closure_sha256=closure_sha256,
                approval=approval,
                plan=plan,
                cluster_uid_digest=cluster_uid_digest,
                api_ca_digest=api_ca_digest,
                repository=repository,
                closure_artifact=closure_artifact,
            )
            if recovery_state == "deployed":
                raise DomainError(
                    "PRIOR_DEPLOYMENT_NOT_RESTORABLE",
                    "a successfully deployed candidate cannot enter rollback recovery",
                )
            publisher_confirmation = _required(
                "SHADOW_PRODUCTION_ROLLBACK_CONFIRMATION"
            )
        else:
            if any(
                value is not None
                for value in (
                    args.prior_binding,
                    args.prior_recovery_envelope,
                    args.prior_envelope,
                    args.prior_evidence,
                    args.prior_journal,
                    args.prior_conclusion,
                    args.prior_deployment_run_id,
                    args.prior_deployment_run_attempt,
                    args.prior_deployment_artifact_id,
                    args.prior_deployment_artifact_sha256,
                )
            ):
                raise DomainError(
                    "PRODUCTION_DEPLOY_CONFIG_INVALID",
                    "prior deployment inputs are only valid for break-glass restore",
                )
            publisher_confirmation = _required(
                "SHADOW_PRODUCTION_DEPLOYMENT_CONFIRMATION"
            )
        binding = _binding_payload(
            operation=operation,
            closure_sha256=closure_sha256,
            approval=approval,
            plan=plan,
            cluster_uid_digest=cluster_uid_digest,
            api_ca_digest=api_ca_digest,
            repository=repository,
            github_run_id=github_run_id,
            github_run_attempt=github_run_attempt,
            closure_artifact=closure_artifact,
            prior_binding_digest=prior_binding_digest,
            prior_artifact_id=prior_artifact_id,
            prior_artifact_sha256=prior_artifact_sha256,
        )
        _atomic_binding(args.binding, binding)
        _atomic_binding(
            args.recovery_envelope,
            _recovery_envelope(operation=operation, binding_path=args.binding),
        )
        publisher = KubernetesProductionPublisher(
            plan,
            confirmation=publisher_confirmation,
            operation="restore-prior-bundle" if restore or same_run else "deploy",
            context=_required("SHADOW_KUBERNETES_CONTEXT"),
            expected_cluster_uid_digest=cluster_uid_digest,
            expected_kubernetes_api_ca_digest=api_ca_digest,
            journal_path=args.journal,
        )
        if restore or same_run:
            restored = (
                publisher.verify_no_mutation()
                if recovery_state == "no_mutation"
                else publisher.verify_restored_bundle()
                if recovery_state == "restored"
                else publisher.resume_rollback()
            )
            restored.verify()
            if restored.status != "PASSED":
                raise DomainError(
                    "PRODUCTION_PRIOR_BUNDLE_RESTORE_FAILED",
                    "prior bundle restore did not pass every runtime check",
                )
            evidence = complete(
                gate_name,
                started_at=restored.started_at,
                completed_at=restored.completed_at,
                coordinates={
                    "prior_binding_digest": prior_binding_digest,
                    "prior_artifact_id": prior_artifact_id,
                    "prior_artifact_sha256": prior_artifact_sha256,
                    "interrupted_state": recovery_state,
                    "plan_digest": plan.digest,
                    "namespace": plan.namespace,
                    "cluster_uid_digest": publisher.cluster_uid_digest,
                    "kubernetes_api_ca_digest": publisher.kubernetes_api_ca_digest,
                },
                checks=(
                    GateCheck("rollback_specific_confirmation", True),
                    GateCheck("prior_recovery_envelope_verified", True),
                    GateCheck(
                        (
                            "prior_execution_envelope_verified"
                            if restore and args.prior_conclusion == "failure"
                            else "interruption_activation_verified"
                        ),
                        True,
                    ),
                    GateCheck(
                        "interrupted_journal_verified",
                        recovery_state in {"no_mutation", "unfinished", "restored"},
                    ),
                    GateCheck(
                        "sealed_prior_bundle_safe",
                        restored.status == "PASSED",
                    ),
                ),
                metrics={"workloads": len(plan.workloads)},
            )
        else:
            evidence = publisher.run()
        evidence = bind_to_acceptance_run(
            evidence, run_id=run_id, release_digest=release_digest
        )
    except DomainError as error:
        evidence = failed_execution(
            gate_name,
            started_at=started,
            error_code=error.code,
            run_id=run_id,
            release_digest=release_digest,
        )
    except Exception:  # noqa: BLE001 - unexpected deployment faults must fail closed
        evidence = failed_execution(
            gate_name,
            started_at=started,
            error_code="UNEXPECTED",
            run_id=run_id,
            release_digest=release_digest,
        )
    finalization_ready = all(
        path.is_file() and not path.is_symlink()
        for path in (args.binding, args.recovery_envelope, args.journal)
    )
    if finalization_ready:
        try:
            binding_value, binding_sha256 = _safe_json_and_sha256(
                args.binding,
                maximum_bytes=1024 * 1024,
                code="PRODUCTION_DEPLOY_FINALIZATION_FAILED",
            )
            if not isinstance(binding_value, Mapping):
                raise DomainError(
                    "PRODUCTION_DEPLOY_FINALIZATION_FAILED",
                    "deployment binding is invalid during finalization",
                )
            _validate_recovery_envelope(
                args.recovery_envelope,
                binding=binding_value,
                binding_sha256=binding_sha256,
            )
            envelope = _execution_envelope(
                operation=operation,
                binding_path=args.binding,
                journal_path=args.journal,
                evidence=evidence,
            )
            _atomic_binding(args.execution_envelope, envelope)
        except Exception:  # noqa: BLE001 - finalization faults must fail closed
            if evidence.status == "PASSED":
                evidence = failed_execution(
                    gate_name,
                    started_at=started,
                    error_code="PRODUCTION_DEPLOY_FINALIZATION_FAILED",
                    run_id=run_id,
                    release_digest=release_digest,
                )
    elif evidence.status == "PASSED":
        evidence = failed_execution(
            gate_name,
            started_at=started,
            error_code="PRODUCTION_DEPLOY_FINALIZATION_FAILED",
            run_id=run_id,
            release_digest=release_digest,
        )
    write_evidence(args.output, evidence)
    os.chmod(args.output, 0o444)
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
