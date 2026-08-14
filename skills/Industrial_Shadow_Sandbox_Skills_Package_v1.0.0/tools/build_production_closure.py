from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json
from shadow_sandbox.evaluation.formal_benchmark import (
    FormalBenchmarkImporter,
    validate_s3_closure_evidence,
)
from shadow_sandbox.operations.container_scan import DockerScoutImageProbe
from shadow_sandbox.operations.evidence import GateEvidence, read_evidence
from shadow_sandbox.operations.external_assurance import ExternalAssuranceImporter
from shadow_sandbox.operations.production_deployment import ProductionDeploymentPlan
from shadow_sandbox.operations.trust_store import SignerTrustStore

ROOT = Path(__file__).resolve().parents[1]
SOURCE_GATES = (
    "preflight",
    "supply_chain",
    "postgresql_migration",
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
SIGNATORY_KEYS = frozenset(
    {
        "identity",
        "role",
        "approved",
        "signed_at",
        "approval_digest",
        "public_key_b64",
        "signature_b64",
    }
)


def _inside_root(path: Path) -> Path:
    try:
        relative = path.absolute().relative_to(ROOT.resolve())
    except ValueError as error:
        raise DomainError(
            "CLOSURE_ARTIFACT_INVALID", "closure artifact is outside the repository"
        ) from error
    cursor = ROOT.resolve()
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise DomainError(
            "CLOSURE_ARTIFACT_INVALID", "closure artifact path is invalid"
        )
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise DomainError(
                "CLOSURE_ARTIFACT_INVALID",
                "closure artifact paths must not contain symlinks",
            )
    resolved = path.resolve(strict=True)
    if (
        ROOT.resolve() not in resolved.parents
        or not resolved.is_file()
        or resolved.stat().st_nlink != 1
        or not 1 <= resolved.stat().st_size <= 64 * 1024 * 1024
    ):
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
    ca_metrics = evidence["external_ca"][1].metrics
    ot_metrics = evidence["real_ot"][1].metrics
    shared_ot_coordinates = (
        "server_certificate_fingerprint",
        "client_certificate_fingerprint",
        "next_client_certificate_fingerprint",
        "client_application_uri",
        "security_policy",
    )
    if any(
        not ca_metrics.get(name) or ca_metrics.get(name) != ot_metrics.get(name)
        for name in shared_ot_coordinates
    ):
        raise DomainError(
            "CLOSURE_OT_BINDING_MISMATCH",
            "external CA and real OT gates do not describe the same certificate-bound session",
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
                deployment_plan_digest=release_coordinates[
                    "deployment_plan_digest"
                ],
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
    key_fingerprints: set[str] = set()
    verified: list[dict[str, Any]] = []
    for item in signatories:
        if set(item) != SIGNATORY_KEYS:
            raise DomainError(
                "CLOSURE_SIGNATORY_INVALID",
                "signatory records contain missing or unknown fields",
            )
        identity = str(item.get("identity", ""))
        role = str(item.get("role", ""))
        if (
            not identity
            or identity in identities
            or role not in REQUIRED_SIGNATORY_ROLES
            or role in roles
            or item.get("approved") is not True
        ):
            raise DomainError(
                "CLOSURE_SIGNATORY_INVALID", "signatories must be distinct approvals"
            )
        if item.get("approval_digest") != approval_digest:
            raise DomainError(
                "CLOSURE_SIGNATORY_INVALID", "signatory approval digest mismatch"
            )
        fingerprint = trust_store.verify_signer(
            identity=identity,
            purpose=f"closure_{role}",
            public_key_b64=str(item.get("public_key_b64", "")),
            signed_at=str(item.get("signed_at", "")),
        )
        if fingerprint in key_fingerprints:
            raise DomainError(
                "CLOSURE_SIGNATORY_INVALID",
                "two-person approval requires two distinct signing keys",
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
        key_fingerprints.add(fingerprint)
        verified.append({key: item[key] for key in SIGNATORY_KEYS})
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
    def status(source: str) -> str:
        return evidence[source][1].status

    gates = {
        "production_preflight": status("preflight"),
        "supply_chain": status("supply_chain"),
        "postgresql_migration": status("postgresql_migration"),
        "backup_restore": status("backup_restore"),
        "oidc": status("oidc"),
        "s3": status("s3"),
        "opcua_interoperability": (
            "PASSED"
            if status("external_ca") == status("real_ot") == "PASSED"
            else "FAILED"
        ),
        "network_policy": status("network_policy"),
        "container_scan": status("container_scan"),
        "security": status("security"),
        "resilience": status("resilience"),
        "performance": status("performance"),
        "privacy": status("privacy"),
        "accessibility": status("accessibility"),
        "upgrade_rollback": status("upgrade_rollback"),
        "benchmark_150": status("benchmark_150"),
    }
    closure = {
        "schema_version": 2,
        "status": "verified",
        "approval": approval,
        "gates": gates,
        "red_lines": red_lines,
        "artifacts": artifacts,
        "attestations": list(attestations),
        "signatories": verified_signatories,
    }
    schema = json.loads(
        (ROOT / "schemas/production/production-closure-input-v2.json").read_text(
            encoding="utf-8"
        )
    )
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(closure)
    except Exception as error:
        raise DomainError(
            "CLOSURE_SCHEMA_INVALID", "generated closure does not satisfy its schema"
        ) from error
    return closure


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise DomainError(
            "CLOSURE_OUTPUT_EXISTS", "refusing to overwrite signed closure material"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".closure-", dir=path.parent)
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
    parser.add_argument("--trust-root-attestation", type=Path, required=True)
    parser.add_argument("--trust-root-public-key", type=Path, required=True)
    parser.add_argument("--trust-root-key-sha256", required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "docs/evidence/batch-24/production-closure-input.json",
    )
    args = parser.parse_args()
    trust_store_path = _inside_root(args.evidence_dir / "assessor-trust-store.json")
    trust_store = SignerTrustStore.load_verified(
        trust_store_path,
        root_attestation_path=args.trust_root_attestation,
        root_public_key_path=args.trust_root_public_key,
        expected_root_key_sha256=args.trust_root_key_sha256,
    )
    evidence = load_gate_evidence(args.evidence_dir)
    release_coordinates = {
        "candidate_image": args.candidate_image,
        "build_digest": args.build_digest,
        "simulator_build_digest": args.simulator_build_digest,
        "environment_digest": args.environment_digest,
        "deployment_plan_digest": args.deployment_plan_digest,
    }
    deployment_plan = ProductionDeploymentPlan.load(
        ROOT,
        args.evidence_dir.parent / "production-deployment/deployment-plan.json",
        candidate_image=args.candidate_image,
        expected_digest=args.deployment_plan_digest,
    )
    if (
        deployment_plan.real_ot_node_allowlist_digest
        != evidence["real_ot"][1].metrics.get("node_allowlist_digest")
        or deployment_plan.real_ot_runtime_binding_digest
        != evidence["real_ot"][1].metrics.get("runtime_binding_digest")
    ):
        raise DomainError(
            "CLOSURE_OT_BINDING_MISMATCH",
            "sealed deployment NodeId allowlist does not match real OT evidence",
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
    formal_evidence, signed_target_profile = FormalBenchmarkImporter(
        ROOT,
        candidate_image=args.candidate_image,
        build_digest=args.build_digest,
        simulator_build_digest=args.simulator_build_digest,
        trust_store=trust_store,
        environment_digest=args.environment_digest,
        deployment_plan_digest=args.deployment_plan_digest,
    ).import_report_with_target_profile(formal)
    if formal_evidence.digest != evidence["benchmark_150"][1].digest:
        raise DomainError(
            "CLOSURE_ATTESTATION_MISMATCH",
            "formal benchmark does not reproduce its source gate evidence",
        )
    validate_s3_closure_evidence(
        evidence["s3"][1], signed_target_profile, deployment_plan
    )
    approval = approval_payload(
        evidence, attestations, release_coordinates, trust_store
    )
    if args.approval_request:
        _atomic_write(args.approval_request, approval)
    if not args.signatories:
        print(canonical_json(approval))
        return 2
    signatories_path = args.signatories
    if (
        signatories_path.is_symlink()
        or not signatories_path.is_file()
        or signatories_path.stat().st_nlink != 1
        or not 1 <= signatories_path.stat().st_size <= 4 * 1024 * 1024
        or stat.S_IMODE(signatories_path.stat().st_mode) & 0o077
    ):
        raise DomainError(
            "CLOSURE_SIGNATURE_FILE_INVALID",
            "closure signature file must be a protected regular file",
        )
    payload = json.loads(signatories_path.read_text(encoding="utf-8"))
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
