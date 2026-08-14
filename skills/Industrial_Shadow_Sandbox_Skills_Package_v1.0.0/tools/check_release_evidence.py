from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from shadow_sandbox.common.models import canonical_digest
from shadow_sandbox.evaluation.formal_benchmark import (
    FormalBenchmarkImporter,
    validate_s3_closure_evidence,
)
from shadow_sandbox.operations.container_scan import DockerScoutImageProbe
from shadow_sandbox.operations.evidence import read_evidence
from shadow_sandbox.operations.external_assurance import ExternalAssuranceImporter
from shadow_sandbox.operations.production_deployment import ProductionDeploymentPlan
from shadow_sandbox.operations.supply_chain import ReleaseCandidate
from shadow_sandbox.operations.trust_store import SignerTrustStore
from tools.source_integrity import source_digest

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "docs/evidence/batch-24/production-closure-input.json"
REQUIRED_GATES = {
    "production_preflight",
    "supply_chain",
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
}


def main() -> int:
    if INPUT.is_symlink() or not INPUT.is_file():
        print(f"RELEASE_BLOCKED: missing {INPUT.relative_to(ROOT)}")
        return 1
    input_stat = INPUT.stat()
    if (
        input_stat.st_nlink != 1
        or not 1 <= input_stat.st_size <= 16 * 1024 * 1024
    ):
        print("RELEASE_BLOCKED: closure input is not a safe regular file")
        return 1
    try:
        decoded = json.loads(INPUT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print("RELEASE_BLOCKED: closure input is invalid JSON")
        return 1
    if not isinstance(decoded, dict):
        print("RELEASE_BLOCKED: closure input must be an object")
        return 1
    data: dict[str, Any] = decoded
    try:
        schema = json.loads(
            (ROOT / "schemas/production/production-closure-input-v2.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(data)
    except Exception:  # noqa: BLE001 - malformed closure input must fail closed
        print("RELEASE_BLOCKED: closure input does not satisfy the production schema")
        return 1
    errors: list[str] = []
    trust_store: SignerTrustStore | None = None
    try:
        trust_store = SignerTrustStore.load_verified(
            ROOT / "docs/evidence/batch-24/production/assessor-trust-store.json",
            root_attestation_path=ROOT
            / "docs/evidence/batch-24/production/assessor-trust-root-attestation.json",
            root_public_key_path=ROOT
            / "docs/evidence/batch-24/production/assessor-trust-root-public-key.pem",
            expected_root_key_sha256=os.environ[
                "SHADOW_ASSESSOR_TRUST_ROOT_KEY_SHA256"
            ],
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
    observed_evidence: dict[str, Any] = {}
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
        if (
            ROOT.resolve() not in resolved.parents
            or path.is_symlink()
            or not resolved.is_file()
            or resolved.stat().st_nlink != 1
            or not 1 <= resolved.stat().st_size <= 64 * 1024 * 1024
        ):
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
                        or scan_path.is_symlink()
                        or not scan_resolved.is_file()
                        or scan_resolved.stat().st_nlink != 1
                        or not 1 <= scan_resolved.stat().st_size <= 64 * 1024 * 1024
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
        observed_evidence[gate] = evidence
    if set(observed_gate_digests) != SOURCE_GATES:
        errors.append("source gate evidence set is incomplete")
    if len(observed_run_ids) != 1 or len(observed_release_digests) != 1:
        errors.append("source gates do not belong to one acceptance run and release")
    try:
        ca_metrics = observed_evidence["external_ca"].metrics
        ot_metrics = observed_evidence["real_ot"].metrics
        for name in (
            "server_certificate_fingerprint",
            "client_certificate_fingerprint",
            "next_client_certificate_fingerprint",
            "client_application_uri",
            "security_policy",
        ):
            if not ca_metrics.get(name) or ca_metrics.get(name) != ot_metrics.get(name):
                raise ValueError(name)
    except (KeyError, ValueError):
        errors.append("external CA and real OT evidence coordinates do not match")
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
    candidate: ReleaseCandidate | None = None
    try:
        expected_repository = os.environ.get("GITHUB_REPOSITORY") or None
        expected_source_revision = os.environ.get("GITHUB_SHA") or None
        if expected_repository is not None and not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", expected_repository
        ):
            raise ValueError("invalid expected repository")
        if expected_source_revision is not None and not re.fullmatch(
            r"[a-f0-9]{40}", expected_source_revision
        ):
            raise ValueError("invalid expected source revision")
        candidate = ReleaseCandidate.load(
            ROOT / "docs/evidence/batch-24/production/supply-chain/release-candidate.json",
            expected_repository=expected_repository,
        )
        if (
            candidate.backend_image != release_coordinates.get("candidate_image")
            or candidate.source_digest != source_digest()
            or (
                expected_source_revision is not None
                and candidate.source_revision != expected_source_revision
            )
            or candidate.source_digest != release_coordinates.get("build_digest")
            or candidate.source_digest
            != release_coordinates.get("simulator_build_digest")
            or observed_evidence["supply_chain"].metrics.get(
                "candidate_manifest_digest"
            )
            != candidate.manifest_digest
            or observed_evidence["supply_chain"].metrics.get("release_run_attempt")
            != candidate.release_run_attempt
            or observed_evidence["supply_chain"].target_digest
            != canonical_digest(
                {
                    "repository": candidate.repository,
                    "release_run_id": candidate.release_run_id,
                    "release_run_attempt": candidate.release_run_attempt,
                    "source_revision": candidate.source_revision,
                    "source_digest": candidate.source_digest,
                    "backend_image": candidate.backend_image,
                    "web_image": candidate.web_image,
                    "candidate_manifest_digest": candidate.manifest_digest,
                    "signer_workflow": (
                        f"{candidate.repository}/.github/workflows/release.yml"
                    ),
                }
            )
        ):
            raise ValueError("candidate coordinates mismatch")
    except Exception:  # noqa: BLE001 - invalid candidate bundle blocks release
        errors.append("release candidate manifest is missing, invalid, or not closure-bound")
    deployment_plan: ProductionDeploymentPlan | None = None
    try:
        deployment_plan = ProductionDeploymentPlan.load(
            ROOT,
            ROOT / "docs/evidence/batch-24/production-deployment/deployment-plan.json",
            candidate_image=str(release_coordinates.get("candidate_image", "")),
            expected_digest=str(release_coordinates.get("deployment_plan_digest", "")),
        )
        if (
            deployment_plan.real_ot_node_allowlist_digest
            != observed_evidence["real_ot"].metrics.get("node_allowlist_digest")
            or deployment_plan.real_ot_runtime_binding_digest
            != observed_evidence["real_ot"].metrics.get("runtime_binding_digest")
        ):
            raise ValueError("real OT sealed runtime binding mismatch")
    except Exception:  # noqa: BLE001 - invalid deployment plan blocks release
        errors.append("deployment plan is missing, invalid, or not closure-bound")
    try:
        supply_metrics = observed_evidence["supply_chain"].metrics
        migration_metrics = observed_evidence["postgresql_migration"].metrics
        if (
            candidate is None
            or supply_metrics.get("postgresql_migration_manifest_sha256")
            != candidate.postgresql_migration_manifest.sha256
            or migration_metrics.get("compatibility_manifest_digest")
            != candidate.postgresql_migration_manifest.sha256
        ):
            raise ValueError("migration contract mismatch")
    except Exception:  # noqa: BLE001 - incomplete migration chain blocks release
        errors.append("PostgreSQL migration evidence is not release-candidate-bound")
    if approval.get("schema_version") != 2:
        errors.append("approval schema version is not 2")
    expected_acceptance_run_id = os.environ.get("SHADOW_EXPECTED_ACCEPTANCE_RUN_ID", "")
    if approval.get("acceptance_run_id") not in observed_run_ids or (
        expected_acceptance_run_id
        and approval.get("acceptance_run_id") != expected_acceptance_run_id
    ):
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
    signed_target_profile: dict[str, Any] | None = None
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
                or report_path.is_symlink()
                or not report_resolved.is_file()
                or report_resolved.stat().st_nlink != 1
                or not 1 <= report_resolved.stat().st_size <= 64 * 1024 * 1024
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
                if (
                    ROOT.resolve() not in resolved.parents
                    or artifact_path.is_symlink()
                    or not resolved.is_file()
                    or resolved.stat().st_nlink != 1
                    or not 1 <= resolved.stat().st_size <= 64 * 1024 * 1024
                ):
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
                reproduced, target_profile = FormalBenchmarkImporter(
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
                    deployment_plan_digest=str(
                        release_coordinates.get("deployment_plan_digest", "")
                    ),
                ).import_report_with_target_profile(report)
                signed_target_profile = dict(target_profile)
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
    try:
        if deployment_plan is None or signed_target_profile is None:
            raise ValueError("storage release binding prerequisites are incomplete")
        validate_s3_closure_evidence(
            observed_evidence["s3"], signed_target_profile, deployment_plan
        )
    except Exception:  # noqa: BLE001 - any storage binding failure blocks release
        errors.append(
            "S3 evidence is not independently bound to the signed target profile and plan"
        )

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
    key_fingerprints: set[str] = set()
    signatory_keys = {
        "identity", "role", "approved", "signed_at", "approval_digest",
        "public_key_b64", "signature_b64",
    }
    for item in data.get("signatories", []):
        identity = str(item.get("identity", ""))
        role = str(item.get("role", ""))
        if (
            not isinstance(item, dict)
            or set(item) != signatory_keys
            or not identity
            or identity in identities
            or role not in {"release_owner", "security_owner"}
            or role in roles
            or item.get("approved") is not True
        ):
            errors.append("signatories must be distinct approved identities")
            continue
        if item.get("approval_digest") != claimed_approval_digest:
            errors.append(f"signatory approval digest mismatch {identity}")
            continue
        try:
            if trust_store is None:
                raise ValueError("trust store unavailable")
            fingerprint = trust_store.verify_signer(
                identity=identity,
                purpose=f"closure_{role}",
                public_key_b64=str(item.get("public_key_b64", "")),
                signed_at=str(item.get("signed_at", "")),
            )
            if fingerprint in key_fingerprints:
                raise ValueError("closure signatories reuse one public key")
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
        key_fingerprints.add(fingerprint)
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
