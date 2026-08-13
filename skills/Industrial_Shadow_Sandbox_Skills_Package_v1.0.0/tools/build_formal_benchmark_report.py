from __future__ import annotations

import argparse
import base64
import hashlib
import os
import stat
import tempfile
from pathlib import Path

from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json
from shadow_sandbox.evaluation.formal_benchmark import FormalBenchmarkImporter
from shadow_sandbox.evaluation.metrics.gate import ReleaseGate
from shadow_sandbox.operations.trust_store import SignerTrustStore

ROOT = Path(__file__).resolve().parents[1]


def _inside_root(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if ROOT.resolve() not in resolved.parents or resolved.is_symlink():
        raise DomainError(
            "FORMAL_BENCHMARK_ARTIFACT_INVALID",
            "measurement artifact is outside repository",
        )
    return resolved


def _atomic_write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".formal-report-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(canonical_json(payload) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build and Ed25519-sign a formal exact-bundle benchmark report"
    )
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--build-digest", required=True)
    parser.add_argument("--simulator-build-digest", required=True)
    parser.add_argument("--episode-results", type=Path, required=True)
    parser.add_argument("--measurement-log", type=Path, required=True)
    parser.add_argument("--target-profile", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--trust-store", type=Path, required=True)
    parser.add_argument("--benchmark-id", required=True)
    parser.add_argument("--assessor", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--completed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    result_path = _inside_root(args.episode_results)
    log_path = _inside_root(args.measurement_log)
    profile_path = _inside_root(args.target_profile)
    key_path = args.private_key.resolve(strict=True)
    if stat.S_IMODE(key_path.stat().st_mode) & 0o077:
        raise DomainError(
            "FORMAL_BENCHMARK_KEY_PERMISSIONS_INVALID",
            "signing key must not be accessible to group or other users",
        )
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None
        )
    except Exception as error:
        raise DomainError(
            "FORMAL_BENCHMARK_KEY_INVALID", "could not load benchmark signing key"
        ) from error
    if not isinstance(private, Ed25519PrivateKey):
        raise DomainError(
            "FORMAL_BENCHMARK_KEY_INVALID", "benchmark signing key must be Ed25519"
        )

    importer = FormalBenchmarkImporter(
        ROOT,
        candidate_image=args.candidate_image,
        build_digest=args.build_digest,
        simulator_build_digest=args.simulator_build_digest,
        trust_store=SignerTrustStore.load(args.trust_store),
        environment_digest=hashlib.sha256(profile_path.read_bytes()).hexdigest(),
    )
    evaluation, result_digest = importer.evaluate_results(result_path)
    gate = ReleaseGate().evaluate(
        "formal-target-benchmark-gate-v1", importer.bundle_digest, evaluation
    )
    artifacts = [
        {
            "kind": kind,
            "path": str(path.relative_to(ROOT)),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for kind, path in (
            ("episode_results", result_path),
            ("measurement_log", log_path),
            ("target_profile", profile_path),
        )
    ]
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    report: dict[str, object] = {
        "schema_version": 1,
        "benchmark_id": args.benchmark_id,
        "assessor": args.assessor,
        "started_at": args.started_at,
        "completed_at": args.completed_at,
        "candidate_image": args.candidate_image,
        "build_digest": args.build_digest,
        "simulator_build_digest": args.simulator_build_digest,
        "suite_digest": importer.suite_digest,
        "bundle_digest": importer.bundle_digest,
        "result_digest": result_digest,
        "evaluation_digest": evaluation.digest,
        "certification_digest": gate.certification_digest,
        "target_profile_digest": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
        "artifacts": artifacts,
        "limitations": [],
        "public_key_b64": base64.b64encode(public).decode("ascii"),
        "report_digest": "",
    }
    report["report_digest"] = canonical_digest(report)
    report["signature_b64"] = base64.b64encode(
        private.sign(str(report["report_digest"]).encode("ascii"))
    ).decode("ascii")
    evidence = importer.import_report(report)
    _atomic_write(args.output, report)
    print(
        canonical_json(
            {
                "benchmark_id": args.benchmark_id,
                "gate_status": evidence.status,
                "report": str(args.output),
                "report_digest": report["report_digest"],
            }
        )
    )
    return 0 if evidence.status == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
