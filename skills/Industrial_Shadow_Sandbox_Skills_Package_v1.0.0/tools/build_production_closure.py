from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json
from shadow_sandbox.evaluation.formal_benchmark import FormalBenchmarkImporter
from shadow_sandbox.operations.container_scan import DockerScoutImageProbe
from shadow_sandbox.operations.evidence import GateEvidence, read_evidence
from shadow_sandbox.operations.external_assurance import ExternalAssuranceImporter
from shadow_sandbox.operations.production_deployment import ProductionDeploymentPlan
from shadow_sandbox.operations.trust_store import SignerTrustStore

ROOT = Path(__file__).resolve().parents[1]
SOURCE_GATES = (
    "preflight",
    "oidc",
    "backup_restore",
    "s3",
    "external_ca",
    "real_ot",
    "network_policy",
    "container_scan",
    "security",
    "resilience",
    "performance",
    "privacy",
    "accessibility",
    "upgrade_rollback",
    "benchmark_150",
)
REQUIRED_SIGNATORY_ROLES = frozenset({"release_owner", "security_owner"})


def _inside_root(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if ROOT.resolve() not in resolved.parents or resolved.is_symlink():
        raise DomainError(
            "CLOSURE_ARTIFACT_INVALID", "closure artifact is outside the repository"
        )
    return resolved


def load_gate_evidence(directory: Path) -> dict[str, tuple[Path, GateEvidence]]:
    evidence: dict[str, tuple[Path, GateEvidence]] = {}
    for gate in SOURCE_GATES:
        path = _inside_root(directory / f"{gate}.json")
        value = read_evidence(path)
        if value.gate != gate:
            raise DomainError(
                "CLOSURE_GATE_MISMATCH",
                "gate evidence filename and payload do not match",
            )
        if value.status != "PASSED":
            raise DomainError("CLOSURE_GATE_FAILED", f"{gate} is not PASSED")
        if value.limitations:
            raise DomainError(
                "CLOSURE_GATE_LIMITED", f"{gate} still has unresolved limitations"
            )
        if value.schema_version != 2:
            raise DomainError(
                "CLOSURE_GATE_UNBOUND", f"{gate} is not acceptance-run-bound evidence"
            )
        if gate == "container_scan":
            for report_name, metric_name in (
                ("container-scan.sarif.json", "backend_report_sha256"),
                ("web-container-scan.sarif.json", "web_report_sha256"),
            ):
                report_path = _inside_root(directory / report_name)
                report_bytes = report_path.read_bytes()
                report = json.loads(report_bytes)
                if value.metrics.get(metric_name) != hashlib.sha256(
                    report_bytes
                ).hexdigest() or DockerScoutImageProbe._sarif_results(report):
                    raise DomainError(
                        "CLOSURE_CONTAINER_SCAN_INVALID",
                        "container scan reports are missing, modified, or have findings",
                    )
        evidence[gate] = (path, value)
    run_ids = {value.acceptance_run_id for _path, value in evidence.values()}
    release_digests = {value.release_digest for _path, value in evidence.values()}
    if len(run_ids) != 1 or len(release_digests) != 1:
        raise DomainError(
            "CLOSURE_RUN_BINDING_MISMATCH",
            "all source gates must belong to one acceptance run and release",
        )
    try:
        starts = [
            dt.datetime.fromisoformat(value.started_at.replace("Z", "+00:00"))
            for _path, value in evidence.values()
        ]
        completions = [
            dt.datetime.fromisoformat(value.completed_at.replace("Z", "+00:00"))
            for _path, value in evidence.values()
        ]
    except ValueError as error:
        raise DomainError(
            "CLOSURE_EVIDENCE_TIME_INVALID", "gate timestamps are invalid"
        ) from error
    now = dt.datetime.now(dt.UTC)
    if (
        any(value.tzinfo is None for value in (*starts, *completions))
        or any(
            completed - started > dt.timedelta(days=30)
            for started, completed in zip(starts, completions, strict=True)
        )
        or any(now - completed > dt.timedelta(days=90) for completed in completions)
        or max(completions) > now + dt.timedelta(minutes=5)
    ):
        raise DomainError(
            "CLOSURE_EVIDENCE_STALE", "gate evidence time window is invalid or stale"
        )
    return evidence


def load_source_attestations(
    directory: Path,
    evidence: Mapping[str, tuple[Path, GateEvidence]],
    trust_store: SignerTrustStore,
    release_coordinates: Mapping[str, str],
) -> list[dict[str, Any]]:
    reports = {
        "security": directory / "security-assurance/report.json",
        "privacy": directory / "privacy-assurance/report.json",
        "accessibility": directory / "accessibility-assurance/report.json",
        "benchmark_150": directory / "formal-benchmark/report.json",
    }
    records: list[dict[str, Any]] = []
    observed_paths: set[Path] = set()
    for gate, report_candidate in reports.items():
        report_path = _inside_root(report_candidate)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(report, Mapping):
            raise DomainError(
                "CLOSURE_ATTESTATION_INVALID", "attestation report is invalid"
            )
        if gate in {"security", "privacy", "accessibility"}:
            imported = ExternalAssuranceImporter(
                ROOT,
                trust_store=trust_store,
                candidate_image=release_coordinates["candidate_image"],
                build_digest=release_coordinates["build_digest"],
                environment_digest=release_coordinates["environment_digest"],
                deployment_plan_digest=release_coordinates["deployment_plan_digest"],
            ).import_report(report)
        else:
            imported = FormalBenchmarkImporter(
                ROOT,
                candidate_image=str(report.get("candidate_image", "")),
                build_digest=str(report.get("build_digest", "")),
                simulator_build_digest=str(report.get("simulator_build_digest", "")),
                trust_store=trust_store,
                environment_digest=release_coordinates["environment_digest"],
            ).import_report(report)
        if imported.digest != evidence[gate][1].digest:
            raise DomainError(
                "CLOSURE_ATTESTATION_MISMATCH",
                f"{gate} attestation does not reproduce its gate evidence",
            )
        artifacts = []
        for item in report.get("artifacts", ()):
            artifact_path = _inside_root(ROOT / str(item.get("path", "")))
            actual = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
            if actual != item.get("sha256") or artifact_path in observed_paths:
                raise DomainError(
                    "CLOSURE_ATTESTATION_ARTIFACT_INVALID",
                    "attestation artifact is missing, duplicated, or digest-mismatched",
                )
            observed_paths.add(artifact_path)
            artifacts.append(
                {
                    "path": str(artifact_path.relative_to(ROOT)),
                    "sha256": actual,
                }
            )
        if report_path in observed_paths:
            raise DomainError(
                "CLOSURE_ATTESTATION_ARTIFACT_INVALID",
                "attestation report is duplicated",
            )
        observed_paths.add(report_path)
        records.append(
            {
                "gate": gate,
                "report_path": str(report_path.relative_to(ROOT)),
                "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
                "report_digest": str(report.get("report_digest", "")),
                "trust_store_digest": trust_store.digest,
                "artifacts": artifacts,
            }
        )
    return records


def approval_payload(
    evidence: Mapping[str, tuple[Path, GateEvidence]],
    attestations: Sequence[Mapping[str, Any]] = (),
    release_coordinates: Mapping[str, str] | None = None,
    trust_store: SignerTrustStore | None = None,
) -> dict[str, Any]:
    if trust_store is None or not release_coordinates:
        raise DomainError(
            "CLOSURE_TRUST_REQUIRED", "trust store and release coordinates are required"
        )
    gate_digests = {
        gate: value.digest for gate, (_path, value) in sorted(evidence.items())
    }
    run_ids = {value.acceptance_run_id for _path, value in evidence.values()}
    release_digests = {value.release_digest for _path, value in evidence.values()}
    expected_release_digest = canonical_digest(dict(release_coordinates))
    if len(run_ids) != 1 or release_digests != {expected_release_digest}:
        raise DomainError(
            "CLOSURE_RUN_BINDING_MISMATCH",
            "evidence does not match one acceptance run and the requested release",
        )
    payload = {
        "schema_version": 2,
        "acceptance_run_id": next(iter(run_ids)),
        "release_digest": expected_release_digest,
        "trust_store_digest": trust_store.digest,
        "gate_digests": gate_digests,
        "attestation_digests": {
            str(item["gate"]): canonical_digest(item) for item in attestations
        },
        "release_coordinates": dict(release_coordinates or {}),
        "scope": ["S0 simulation", "S1 historical replay", "S2 real read-only Shadow"],
        "exclusions": ["real write", "real control", "regulatory certification"],
    }
    return {**payload, "approval_digest": canonical_digest(payload)}


def verify_signatories(
    signatories: Sequence[Mapping[str, Any]],
    approval_digest: str,
    trust_store: SignerTrustStore,
) -> list[dict[str, Any]]:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as error:
        raise DomainError(
            "CRYPTOGRAPHY_DEPENDENCY_UNAVAILABLE",
            "cryptography is required",
            status=503,
        ) from error
    identities: set[str] = set()
    roles: set[str] = set()
    verified: list[dict[str, Any]] = []
    for item in signatories:
        identity = str(item.get("identity", ""))
        role = str(item.get("role", ""))
        if (
            not identity
            or identity in identities
            or role not in REQUIRED_SIGNATORY_ROLES
            or role in roles
            or not item.get("approved")
        ):
            raise DomainError(
                "CLOSURE_SIGNATORY_INVALID", "signatories must be distinct approvals"
            )
        if item.get("approval_digest") != approval_digest:
            raise DomainError(
                "CLOSURE_SIGNATORY_INVALID", "signatory approval digest mismatch"
            )
        trust_store.verify_signer(
            identity=identity,
            purpose=f"closure_{role}",
            public_key_b64=str(item.get("public_key_b64", "")),
            signed_at=str(item.get("signed_at", "")),
        )
        try:
            public_key = base64.b64decode(str(item["public_key_b64"]), validate=True)
            signature = base64.b64decode(str(item["signature_b64"]), validate=True)
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature, approval_digest.encode("ascii")
            )
        except Exception as error:
            raise DomainError(
                "CLOSURE_SIGNATURE_INVALID", "closure signatory signature is invalid"
            ) from error
        identities.add(identity)
        roles.add(role)
        verified.append(dict(item))
    if len(identities) < 2 or not REQUIRED_SIGNATORY_ROLES.issubset(roles):
        raise DomainError(
            "CLOSURE_SIGNATORIES_REQUIRED",
            "release_owner and security_owner signatures are required",
        )
    return verified


def build_closure(
    evidence: Mapping[str, tuple[Path, GateEvidence]],
    signatories: Sequence[Mapping[str, Any]],
    *,
    attestations: Sequence[Mapping[str, Any]] = (),
    release_coordinates: Mapping[str, str] | None = None,
    trust_store: SignerTrustStore | None = None,
) -> dict[str, Any]:
    approval = approval_payload(
        evidence, attestations, release_coordinates, trust_store
    )
    if trust_store is None:
        raise DomainError("CLOSURE_TRUST_REQUIRED", "trust store is required")
    verified_signatories = verify_signatories(
        signatories, approval["approval_digest"], trust_store
    )
    artifacts = []
    for gate, (path, value) in sorted(evidence.items()):
        artifacts.append(
            {
                "gate": gate,
                "path": str(path.relative_to(ROOT)),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "evidence_digest": value.digest,
            }
        )
    benchmark = evidence["benchmark_150"][1]
    red_lines = {
        "real_write_attempts": int(benchmark.metrics.get("real_write_attempts", -1)),
        "unauthorized_actions": int(benchmark.metrics.get("unapproved_actions", -1)),
        "gold_exposures": int(benchmark.metrics.get("gold_leaks", -1)),
    }
    gates = {
        "production_preflight": "PASSED",
        "postgresql_migration": "PASSED",
        "backup_restore": "PASSED",
        "oidc": "PASSED",
        "s3": "PASSED",
        "opcua_interoperability": "PASSED",
        "network_policy": "PASSED",
        "container_scan": "PASSED",
        "security": "PASSED",
        "resilience": "PASSED",
        "performance": "PASSED",
        "privacy": "PASSED",
        "accessibility": "PASSED",
        "upgrade_rollback": "PASSED",
        "benchmark_150": "PASSED",
    }
    return {
        "schema_version": 2,
        "status": "verified",
        "approval": approval,
        "gates": gates,
        "red_lines": red_lines,
        "artifacts": artifacts,
        "attestations": list(attestations),
        "signatories": verified_signatories,
    }


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".closure-", dir=path.parent)
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
        description="Build a two-person signed closure input"
    )
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--signatories", type=Path)
    parser.add_argument("--approval-request", type=Path)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--build-digest", required=True)
    parser.add_argument("--simulator-build-digest", required=True)
    parser.add_argument("--environment-digest", required=True)
    parser.add_argument("--deployment-plan-digest", required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "docs/evidence/batch-24/production-closure-input.json",
    )
    args = parser.parse_args()
    trust_store_path = _inside_root(args.evidence_dir / "assessor-trust-store.json")
    trust_store = SignerTrustStore.load(trust_store_path)
    evidence = load_gate_evidence(args.evidence_dir)
    release_coordinates = {
        "candidate_image": args.candidate_image,
        "build_digest": args.build_digest,
        "simulator_build_digest": args.simulator_build_digest,
        "environment_digest": args.environment_digest,
        "deployment_plan_digest": args.deployment_plan_digest,
    }
    ProductionDeploymentPlan.load(
        ROOT,
        args.evidence_dir.parent / "production-deployment/deployment-plan.json",
        candidate_image=args.candidate_image,
        expected_digest=args.deployment_plan_digest,
    )
    attestations = load_source_attestations(
        args.evidence_dir, evidence, trust_store, release_coordinates
    )
    formal = json.loads(
        (args.evidence_dir / "formal-benchmark/report.json").read_text(encoding="utf-8")
    )
    if (
        any(
            formal.get(key) != value
            for key, value in release_coordinates.items()
            if key in {"candidate_image", "build_digest", "simulator_build_digest"}
        )
        or formal.get("target_profile_digest")
        != release_coordinates["environment_digest"]
    ):
        raise DomainError(
            "CLOSURE_RELEASE_COORDINATES_MISMATCH",
            "formal benchmark and requested release coordinates differ",
        )
    approval = approval_payload(
        evidence, attestations, release_coordinates, trust_store
    )
    if args.approval_request:
        _atomic_write(args.approval_request, approval)
    if not args.signatories:
        print(canonical_json(approval))
        return 2
    payload = json.loads(args.signatories.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, Mapping)
        or set(payload) != {"schema_version", "approval_digest", "signatories"}
        or payload.get("schema_version") != 1
        or payload.get("approval_digest") != approval["approval_digest"]
        or not isinstance(payload.get("signatories"), list)
    ):
        raise DomainError(
            "CLOSURE_SIGNATURE_FILE_INVALID", "closure signature file is invalid"
        )
    values = payload["signatories"]
    closure = build_closure(
        evidence,
        values,
        attestations=attestations,
        release_coordinates=release_coordinates,
        trust_store=trust_store,
    )
    _atomic_write(args.output, closure)
    print(canonical_json({"status": "verified", "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
