from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json
from shadow_sandbox.operations.external_assurance import ExternalAssuranceImporter
from shadow_sandbox.operations.trust_store import SignerTrustStore

ROOT = Path(__file__).resolve().parents[1]


def _inside_root(path: Path) -> Path:
    if path.is_symlink():
        raise DomainError(
            "ASSURANCE_ARTIFACT_INVALID",
            "assurance artifact must not be a symlink",
        )
    resolved = path.resolve(strict=True)
    if (
        ROOT.resolve() not in resolved.parents
        or not resolved.is_file()
        or resolved.stat().st_nlink != 1
        or not 1 <= resolved.stat().st_size <= 10 * 1024 * 1024
    ):
        raise DomainError(
            "ASSURANCE_ARTIFACT_INVALID",
            "assurance artifact must be a regular repository file",
        )
    return resolved


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise DomainError(
            "ASSURANCE_REPORT_EXISTS",
            "refusing to overwrite an existing signed assurance report",
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".assurance-report-", dir=path.parent
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
        description="Build and Ed25519-sign a release-bound external assurance report"
    )
    parser.add_argument(
        "--gate", choices=("security", "privacy", "accessibility"), required=True
    )
    parser.add_argument("--assessment-id", required=True)
    parser.add_argument("--assessor", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--completed-at", required=True)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--build-digest", required=True)
    parser.add_argument("--environment-digest", required=True)
    parser.add_argument("--deployment-plan-digest", required=True)
    parser.add_argument("--checks", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, action="append", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--trust-store", type=Path, required=True)
    parser.add_argument("--trust-root-attestation", type=Path, required=True)
    parser.add_argument("--trust-root-public-key", type=Path, required=True)
    parser.add_argument("--trust-root-key-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    checks_path = _inside_root(args.checks)
    checks_value = json.loads(checks_path.read_text(encoding="utf-8"))
    checks = checks_value.get("checks", ()) if isinstance(checks_value, Mapping) else ()
    if not isinstance(checks, list):
        raise DomainError(
            "ASSURANCE_CHECKS_INVALID", "checks file must contain a checks list"
        )
    required = ExternalAssuranceImporter.REQUIRED_CHECKS[args.gate]
    by_name = {
        str(item.get("name", "")): item
        for item in checks
        if isinstance(item, Mapping)
    }
    if set(by_name) != set(required) or any(
        item.get("passed") is not True
        or item.get("details") != {"artifact_kind": name}
        for name, item in by_name.items()
    ):
        raise DomainError(
            "ASSURANCE_CHECKS_INVALID",
            "checks must bind every exact required control to one artifact kind",
        )
    artifacts = []
    observed: set[Path] = set()
    for candidate in args.artifact:
        path = _inside_root(candidate)
        if path in observed:
            raise DomainError(
                "ASSURANCE_ARTIFACT_INVALID", "assurance artifacts are duplicated"
            )
        observed.add(path)
        try:
            artifact_value = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DomainError(
                "ASSURANCE_ARTIFACT_INVALID", "assurance artifacts must be structured JSON"
            ) from error
        if not isinstance(artifact_value, Mapping):
            raise DomainError(
                "ASSURANCE_ARTIFACT_INVALID", "assurance artifact must be an object"
            )
        kind = str(artifact_value.get("artifact_kind", ""))
        artifacts.append(
            {
                "kind": kind,
                "path": str(path.relative_to(ROOT)),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "media_type": "application/json",
            }
        )
    if {str(item["kind"]) for item in artifacts} != set(required) or len(artifacts) != len(
        required
    ):
        raise DomainError(
            "ASSURANCE_ARTIFACT_INVALID",
            "one exact structured artifact is required for each assurance control",
        )

    key_path = args.private_key.resolve(strict=True)
    if (
        args.private_key.is_symlink()
        or not key_path.is_file()
        or key_path.stat().st_nlink != 1
        or not 1 <= key_path.stat().st_size <= 1024 * 1024
        or stat.S_IMODE(key_path.stat().st_mode) & 0o077
    ):
        raise DomainError(
            "ASSURANCE_KEY_PERMISSIONS_INVALID",
            "assurance signing key must not be accessible to group or other users",
        )
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None
        )
    except Exception as error:
        raise DomainError(
            "ASSURANCE_KEY_INVALID", "could not load assurance signing key"
        ) from error
    if not isinstance(private, Ed25519PrivateKey):
        raise DomainError("ASSURANCE_KEY_INVALID", "assurance key must be Ed25519")
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    trust_store = SignerTrustStore.load_verified(
        args.trust_store,
        root_attestation_path=args.trust_root_attestation,
        root_public_key_path=args.trust_root_public_key,
        expected_root_key_sha256=args.trust_root_key_sha256,
    )
    report: dict[str, Any] = {
        "schema_version": 3,
        "gate": args.gate,
        "assessment_id": args.assessment_id,
        "assessor": args.assessor,
        "started_at": args.started_at,
        "completed_at": args.completed_at,
        "candidate_image": args.candidate_image,
        "build_digest": args.build_digest,
        "environment_digest": args.environment_digest,
        "deployment_plan_digest": args.deployment_plan_digest,
        "checks": checks,
        "artifacts": artifacts,
        "limitations": [],
        "public_key_b64": base64.b64encode(public).decode("ascii"),
        "report_digest": "",
    }
    report["report_digest"] = canonical_digest(report)
    report["signature_b64"] = base64.b64encode(
        private.sign(str(report["report_digest"]).encode("ascii"))
    ).decode("ascii")
    evidence = ExternalAssuranceImporter(
        ROOT,
        trust_store=trust_store,
        candidate_image=args.candidate_image,
        build_digest=args.build_digest,
        environment_digest=args.environment_digest,
        deployment_plan_digest=args.deployment_plan_digest,
    ).import_report(report)
    _atomic_write(args.output, report)
    print(
        canonical_json(
            {
                "gate": args.gate,
                "status": evidence.status,
                "report": str(args.output),
                "report_digest": report["report_digest"],
            }
        )
    )
    return 0 if evidence.status == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
