from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import canonical_digest
from shadow_sandbox.evaluation.formal_benchmark import FormalBenchmarkImporter
from shadow_sandbox.operations.container_scan import DockerScoutImageProbe
from shadow_sandbox.operations.evidence import read_evidence
from shadow_sandbox.operations.external_assurance import ExternalAssuranceImporter
from shadow_sandbox.operations.production_deployment import ProductionDeploymentPlan
from shadow_sandbox.operations.trust_store import SignerTrustStore

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "docs/evidence/batch-24/production-closure-input.json"
REQUIRED_GATES = {
    "production_preflight",
    "postgresql_migration",
    "backup_restore",
    "oidc",
    "s3",
    "opcua_interoperability",
    "network_policy",
    "container_scan",
    "security",
    "resilience",
    "performance",
    "privacy",
    "accessibility",
    "upgrade_rollback",
    "benchmark_150",
}
SOURCE_GATES = {
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
}


def main() -> int:
    if not INPUT.is_file():
        print(f"RELEASE_BLOCKED: missing {INPUT.relative_to(ROOT)}")
        return 1
    data: dict[str, Any] = json.loads(INPUT.read_text(encoding="utf-8"))
    errors: list[str] = []
    trust_store: SignerTrustStore | None = None
    try:
        trust_store = SignerTrustStore.load(
            ROOT / "docs/evidence/batch-24/production/assessor-trust-store.json"
        )
    except Exception:  # noqa: BLE001 - invalid trust material must block release
        errors.append("assessor and approver trust store is missing or invalid")
    if data.get("schema_version") != 2:
        errors.append("closure input schema_version is not 2")
    if data.get("status") != "verified":
        errors.append("closure input status is not verified")
    gates = data.get("gates", {})
    approval = data.get("approval", {})
    for gate in sorted(REQUIRED_GATES):
        if gates.get(gate) != "PASSED":
            errors.append(f"{gate} is not PASSED")
    red_lines = data.get("red_lines", {})
    for name in ("real_write_attempts", "unauthorized_actions", "gold_exposures"):
        if red_lines.get(name) != 0:
            errors.append(f"red line {name} is not zero")
    artifacts = data.get("artifacts", [])
    if not artifacts:
        errors.append("no closure artifacts supplied")
    observed_gate_digests: dict[str, str] = {}
    observed_run_ids: set[str] = set()
    observed_release_digests: set[str] = set()
    observed_times: list[tuple[dt.datetime, dt.datetime]] = []
    for artifact in artifacts:
        path = ROOT / str(artifact.get("path", ""))
        try:
            resolved = path.resolve(strict=True)
        except FileNotFoundError:
            errors.append(f"missing artifact {artifact.get('path')}")
            continue
        if ROOT.resolve() not in resolved.parents or resolved.is_symlink():
            errors.append(f"artifact outside repository {artifact.get('path')}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != artifact.get("sha256"):
            errors.append(f"artifact digest mismatch {artifact.get('path')}")
        gate = str(artifact.get("gate", ""))
        if gate not in SOURCE_GATES or gate in observed_gate_digests:
            errors.append(f"invalid or duplicate source gate {gate}")
            continue
        try:
            evidence = read_evidence(path)
        except Exception:  # noqa: BLE001 - any evidence decoding failure is invalid
            errors.append(f"invalid gate evidence {artifact.get('path')}")
            continue
        if evidence.gate != gate or evidence.status != "PASSED":
            errors.append(f"source gate {gate} is not digest-valid PASSED evidence")
        if evidence.limitations:
            errors.append(f"source gate {gate} has unresolved limitations")
        if evidence.schema_version != 2:
            errors.append(f"source gate {gate} is not acceptance-run-bound")
        observed_run_ids.add(evidence.acceptance_run_id)
        observed_release_digests.add(evidence.release_digest)
        try:
            observed_times.append(
                (
                    dt.datetime.fromisoformat(
                        evidence.started_at.replace("Z", "+00:00")
                    ),
                    dt.datetime.fromisoformat(
                        evidence.completed_at.replace("Z", "+00:00")
                    ),
                )
            )
        except ValueError:
            errors.append(f"source gate {gate} has invalid timestamps")
        if evidence.digest != artifact.get("evidence_digest"):
            errors.append(f"source gate evidence digest mismatch {gate}")
        if gate == "container_scan":
            try:
                for report_name, metric_name in (
                    ("container-scan.sarif.json", "backend_report_sha256"),
                    ("web-container-scan.sarif.json", "web_report_sha256"),
                ):
                    scan_path = path.parent / report_name
                    scan_resolved = scan_path.resolve(strict=True)
                    if (
                        ROOT.resolve() not in scan_resolved.parents
                        or scan_resolved.is_symlink()
                    ):
                        raise ValueError("scan report outside repository")
                    scan_bytes = scan_path.read_bytes()
                    if evidence.metrics.get(metric_name) != hashlib.sha256(
                        scan_bytes
                    ).hexdigest() or DockerScoutImageProbe._sarif_results(
                        json.loads(scan_bytes)
                    ):
                        raise ValueError("scan report is modified or has findings")
            except Exception:  # noqa: BLE001 - malformed scan evidence blocks release
                errors.append("invalid or mismatched Docker Scout SARIF reports")
        observed_gate_digests[gate] = evidence.digest
    if set(observed_gate_digests) != SOURCE_GATES:
        errors.append("source gate evidence set is incomplete")
    if len(observed_run_ids) != 1 or len(observed_release_digests) != 1:
        errors.append("source gates do not belong to one acceptance run and release")
    now = dt.datetime.now(dt.UTC)
    if len(observed_times) != len(SOURCE_GATES) or any(
        started.tzinfo is None
        or completed.tzinfo is None
        or completed < started
        or completed - started > dt.timedelta(days=30)
        or now - completed > dt.timedelta(days=90)
        or completed > now + dt.timedelta(minutes=5)
        for started, completed in observed_times
    ):
        errors.append("source gate evidence time window is invalid or stale")

    release_coordinates = approval.get("release_coordinates", {})
    coordinate_keys = {
        "candidate_image",
        "build_digest",
        "simulator_build_digest",
        "environment_digest",
        "deployment_plan_digest",
    }
    if (
        not isinstance(release_coordinates, dict)
        or set(release_coordinates) != coordinate_keys
    ):
        errors.append("release coordinates are incomplete")
        release_coordinates = {}
    expected_release_digest = canonical_digest(release_coordinates)
    try:
        ProductionDeploymentPlan.load(
            ROOT,
            ROOT / "docs/evidence/batch-24/production-deployment/deployment-plan.json",
            candidate_image=str(release_coordinates.get("candidate_image", "")),
            expected_digest=str(release_coordinates.get("deployment_plan_digest", "")),
        )
    except Exception:  # noqa: BLE001 - invalid deployment plan blocks release
        errors.append("deployment plan is missing, invalid, or not closure-bound")
    if approval.get("schema_version") != 2:
        errors.append("approval schema version is not 2")
    if approval.get("acceptance_run_id") not in observed_run_ids:
        errors.append("approval acceptance run does not match source gates")
    if approval.get(
        "release_digest"
    ) != expected_release_digest or observed_release_digests != {
        expected_release_digest
    }:
        errors.append("approval release digest does not match source gates")
    if trust_store is None or approval.get("trust_store_digest") != trust_store.digest:
        errors.append("approval trust store digest mismatch")
    attestation_digests: dict[str, str] = {}
    attestation_gates: set[str] = set()
    for attestation in data.get("attestations", []):
        gate = str(attestation.get("gate", ""))
        if (
            gate not in {"security", "privacy", "accessibility", "benchmark_150"}
            or gate in attestation_gates
        ):
            errors.append(f"invalid or duplicate source attestation {gate}")
            continue
        attestation_gates.add(gate)
        report_path = ROOT / str(attestation.get("report_path", ""))
        try:
            report_resolved = report_path.resolve(strict=True)
            if (
                ROOT.resolve() not in report_resolved.parents
                or report_resolved.is_symlink()
            ):
                raise ValueError("outside repository")
            report_sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
            if report_sha != attestation.get("report_sha256"):
                raise ValueError("report digest mismatch")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if trust_store is None:
                raise ValueError("trust store unavailable")
            if attestation.get("trust_store_digest") != trust_store.digest:
                raise ValueError("attestation trust store mismatch")
            if report.get("report_digest") != attestation.get("report_digest"):
                raise ValueError("signed report digest mismatch")
            declared_artifacts = {
                (str(item.get("path", "")), str(item.get("sha256", "")))
                for item in report.get("artifacts", ())
            }
            closure_artifacts = {
                (str(item.get("path", "")), str(item.get("sha256", "")))
                for item in attestation.get("artifacts", ())
            }
            if declared_artifacts != closure_artifacts:
                raise ValueError("attestation artifact set mismatch")
            for relative, expected_sha in declared_artifacts:
                artifact_path = ROOT / relative
                resolved = artifact_path.resolve(strict=True)
                if ROOT.resolve() not in resolved.parents or resolved.is_symlink():
                    raise ValueError("attestation artifact outside repository")
                if (
                    hashlib.sha256(artifact_path.read_bytes()).hexdigest()
                    != expected_sha
                ):
                    raise ValueError("attestation artifact digest mismatch")
            if gate in {"security", "privacy", "accessibility"}:
                reproduced = ExternalAssuranceImporter(
                    ROOT,
                    trust_store=trust_store,
                    candidate_image=str(release_coordinates.get("candidate_image", "")),
                    build_digest=str(release_coordinates.get("build_digest", "")),
                    environment_digest=str(
                        release_coordinates.get("environment_digest", "")
                    ),
                    deployment_plan_digest=str(
                        release_coordinates.get("deployment_plan_digest", "")
                    ),
                ).import_report(report)
            else:
                reproduced = FormalBenchmarkImporter(
                    ROOT,
                    candidate_image=str(release_coordinates.get("candidate_image", "")),
                    build_digest=str(release_coordinates.get("build_digest", "")),
                    simulator_build_digest=str(
                        release_coordinates.get("simulator_build_digest", "")
                    ),
                    trust_store=trust_store,
                    environment_digest=str(
                        release_coordinates.get("environment_digest", "")
                    ),
                ).import_report(report)
            if reproduced.digest != observed_gate_digests.get(gate):
                raise ValueError("attestation does not reproduce gate evidence")
            attestation_digests[gate] = canonical_digest(attestation)
        except Exception:  # noqa: BLE001 - any attestation verification failure blocks release
            errors.append(f"invalid or mismatched source attestation {gate}")
    if attestation_gates != {
        "security",
        "privacy",
        "accessibility",
        "benchmark_150",
    }:
        errors.append("source attestation set is incomplete")

    claimed_approval_digest = approval.get("approval_digest")
    approval_payload = {
        key: value for key, value in approval.items() if key != "approval_digest"
    }
    if claimed_approval_digest != canonical_digest(approval_payload):
        errors.append("approval payload digest mismatch")
    if approval.get("gate_digests") != dict(sorted(observed_gate_digests.items())):
        errors.append("approval gate digests do not match artifacts")
    if approval.get("attestation_digests") != attestation_digests:
        errors.append("approval attestation digests do not match source reports")

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        errors.append("cryptography is required to verify closure signatories")
        Ed25519PublicKey = None  # type: ignore[assignment,misc]
    identities: set[str] = set()
    roles: set[str] = set()
    for item in data.get("signatories", []):
        identity = str(item.get("identity", ""))
        role = str(item.get("role", ""))
        if (
            not identity
            or identity in identities
            or role not in {"release_owner", "security_owner"}
            or role in roles
            or not item.get("approved")
        ):
            errors.append("signatories must be distinct approved identities")
            continue
        if item.get("approval_digest") != claimed_approval_digest:
            errors.append(f"signatory approval digest mismatch {identity}")
            continue
        try:
            if trust_store is None:
                raise ValueError("trust store unavailable")
            trust_store.verify_signer(
                identity=identity,
                purpose=f"closure_{role}",
                public_key_b64=str(item.get("public_key_b64", "")),
                signed_at=str(item.get("signed_at", "")),
            )
            if Ed25519PublicKey is None:
                raise ValueError("cryptography unavailable")
            Ed25519PublicKey.from_public_bytes(
                base64.b64decode(str(item["public_key_b64"]), validate=True)
            ).verify(
                base64.b64decode(str(item["signature_b64"]), validate=True),
                str(claimed_approval_digest).encode("ascii"),
            )
        except Exception:  # noqa: BLE001 - any signature verification failure blocks release
            errors.append(f"invalid signatory signature {identity}")
            continue
        identities.add(identity)
        roles.add(role)
    if len(identities) < 2 or not {"release_owner", "security_owner"}.issubset(roles):
        errors.append("release_owner and security_owner signatures are required")
    if errors:
        print("RELEASE_BLOCKED:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Production closure evidence is complete and digest-verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
