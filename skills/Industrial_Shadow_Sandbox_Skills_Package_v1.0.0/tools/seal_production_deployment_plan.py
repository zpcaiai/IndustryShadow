from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json
from shadow_sandbox.operations.production_deployment import ProductionDeploymentPlan

ROOT = Path(__file__).resolve().parents[1]


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise DomainError(
            "DEPLOYMENT_PLAN_OUTPUT_EXISTS",
            "refusing to overwrite an existing sealed deployment plan",
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".deployment-plan-", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(canonical_json(payload) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o444)
        os.link(temporary, path)
        os.unlink(temporary)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate and digest-seal a phased production deployment plan"
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (
        args.input.is_symlink()
        or not args.input.is_file()
        or not stat.S_ISREG(args.input.stat().st_mode)
        or args.input.stat().st_nlink != 1
        or not 1 <= args.input.stat().st_size <= 4 * 1024 * 1024
    ):
        raise DomainError(
            "DEPLOYMENT_PLAN_INVALID", "deployment plan input must be a safe file"
        )
    value = json.loads(args.input.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise DomainError(
            "DEPLOYMENT_PLAN_INVALID", "deployment plan input must be an object"
        )
    if value.get("digest") not in {None, ""}:
        raise DomainError(
            "DEPLOYMENT_PLAN_ALREADY_SEALED",
            "input digest must be empty to prevent stale resealing",
        )
    payload = {**value, "digest": ""}
    for name in (
        "bootstrap_manifest",
        "migration_manifest",
        "runtime_manifest",
        "rollback_manifest",
    ):
        item = payload.get(name)
        if not isinstance(item, Mapping) or set(item) != {"path", "sha256"}:
            raise DomainError(
                "DEPLOYMENT_PLAN_INVALID", "deployment artifact fields are invalid"
            )
        source = ROOT / str(item.get("path", ""))
        if source.is_symlink():
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_INVALID",
                "deployment artifact must not be a symlink",
            )
        path = source.resolve(strict=True)
        if (
            ROOT.resolve() not in path.parents
            or not path.is_file()
            or not stat.S_ISREG(path.stat().st_mode)
            or path.stat().st_nlink != 1
            or not 1 <= path.stat().st_size <= 64 * 1024 * 1024
        ):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_INVALID",
                "deployment artifact must be a regular repository file",
            )
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        declared = str(item.get("sha256", ""))
        if declared not in {"", actual}:
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_INVALID",
                "refusing to seal a stale deployment artifact digest",
            )
        payload[name] = {"path": str(item["path"]), "sha256": actual}
    payload["digest"] = canonical_digest(payload)
    _atomic_write(args.output, payload)
    try:
        plan = ProductionDeploymentPlan.load(
            ROOT,
            args.output,
            candidate_image=str(payload.get("backend_image", "")),
            expected_digest=str(payload["digest"]),
        )
    except Exception:
        args.output.unlink(missing_ok=True)
        raise
    print(
        canonical_json(
            {
                "plan_id": plan.plan_id,
                "namespace": plan.namespace,
                "workloads": len(plan.workloads),
                "digest": plan.digest,
                "output": str(args.output),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
