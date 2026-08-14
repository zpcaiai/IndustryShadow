from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, ClassVar

from shadow_sandbox.common.models import DomainError, canonical_digest

from .evidence import GateCheck, GateEvidence, complete
from .trust_store import SignerTrustStore


class ExternalAssuranceImporter:
    """Verify a signed external assessment and every referenced artifact."""

    ALLOWED_GATES = frozenset({"security", "privacy", "accessibility"})
    REPORT_KEYS = frozenset(
        {
            "schema_version",
            "gate",
            "assessment_id",
            "assessor",
            "started_at",
            "completed_at",
            "candidate_image",
            "build_digest",
            "environment_digest",
            "deployment_plan_digest",
            "checks",
            "artifacts",
            "limitations",
            "public_key_b64",
            "report_digest",
            "signature_b64",
        }
    )
    REQUIRED_CHECKS: ClassVar[Mapping[str, frozenset[str]]] = {
        "security": frozenset(
            {
                "threat_model",
                "penetration_test",
                "dependency_review",
                "container_review",
                "kubernetes_review",
                "oidc_review",
                "tenant_isolation_review",
                "remediation_verified",
            }
        ),
        "privacy": frozenset(
            {
                "data_inventory",
                "purpose_limitation",
                "retention_deletion",
                "tenant_isolation_review",
                "access_export",
                "logging_redaction",
                "subprocessor_review",
                "dpa_review",
            }
        ),
        "accessibility": frozenset(
            {
                "wcag_aa_review",
                "keyboard_navigation",
                "screen_reader_review",
                "focus_order",
                "contrast_review",
                "zoom_reflow",
                "error_identification",
                "remediation_verified",
            }
        ),
    }
    ARTIFACT_RECORD_KEYS = frozenset({"kind", "path", "sha256", "media_type"})
    ARTIFACT_PAYLOAD_KEYS = frozenset(
        {
            "schema_version",
            "assessment_id",
            "gate",
            "artifact_kind",
            "assessor",
            "executed_at",
            "assessment_mode",
            "target_digest",
            "result",
            "sample_count",
            "findings",
        }
    )
    FINDING_KEYS = frozenset({"id", "severity", "status", "description", "digest"})

    def __init__(
        self,
        repository_root: str | Path,
        *,
        trust_store: SignerTrustStore,
        candidate_image: str,
        build_digest: str,
        environment_digest: str,
        deployment_plan_digest: str,
    ) -> None:
        self.root = Path(repository_root).resolve()
        self.trust_store = trust_store
        self.candidate_image = candidate_image
        self.build_digest = build_digest
        self.environment_digest = environment_digest
        self.deployment_plan_digest = deployment_plan_digest
        self.release_target_digest = canonical_digest(
            {
                "candidate_image": candidate_image,
                "build_digest": build_digest,
                "environment_digest": environment_digest,
                "deployment_plan_digest": deployment_plan_digest,
            }
        )

    def _artifact(
        self,
        item: Mapping[str, Any],
        *,
        gate: str,
        assessment_id: str,
        assessor: str,
        started: dt.datetime,
        completed: dt.datetime,
    ) -> tuple[str, GateCheck]:
        if (
            set(item) != self.ARTIFACT_RECORD_KEYS
            or item.get("media_type") != "application/json"
            or not str(item.get("kind", "")).strip()
            or not re.fullmatch(
            r"[a-f0-9]{64}", str(item.get("sha256", ""))
            )
        ):
            raise DomainError("ASSURANCE_ARTIFACT_INVALID", "artifact fields are invalid")
        raw_path = str(item.get("path", ""))
        relative_path = Path(raw_path)
        if (
            not raw_path
            or relative_path.is_absolute()
            or "\\" in raw_path
            or any(part in {"", ".", ".."} for part in raw_path.split("/"))
        ):
            raise DomainError("ASSURANCE_ARTIFACT_INVALID", "artifact path is invalid")
        source = self.root / relative_path
        current = self.root
        for part in relative_path.parts:
            current = current / part
            if current.is_symlink():
                raise DomainError(
                    "ASSURANCE_ARTIFACT_INVALID", "artifact symlinks are forbidden"
                )
        if source.is_symlink():
            raise DomainError("ASSURANCE_ARTIFACT_INVALID", "artifact symlinks are forbidden")
        try:
            path = source.resolve(strict=True)
        except OSError as error:
            raise DomainError(
                "ASSURANCE_ARTIFACT_INVALID", "artifact path cannot be resolved"
            ) from error
        if (
            self.root not in path.parents
            or not path.is_file()
            or path.stat().st_nlink != 1
            or not 1 <= path.stat().st_size <= 10 * 1024 * 1024
        ):
            raise DomainError("ASSURANCE_ARTIFACT_INVALID", "artifact is outside repository")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as error:
            raise DomainError(
                "ASSURANCE_ARTIFACT_INVALID", "artifact payload is invalid JSON"
            ) from error
        kind = str(item["kind"])
        if not isinstance(payload, Mapping) or set(payload) != self.ARTIFACT_PAYLOAD_KEYS:
            raise DomainError("ASSURANCE_ARTIFACT_INVALID", "artifact payload fields are invalid")
        findings = payload.get("findings")
        sample_count = payload.get("sample_count")
        try:
            executed = dt.datetime.fromisoformat(str(payload.get("executed_at", "")))
        except ValueError as error:
            raise DomainError(
                "ASSURANCE_ARTIFACT_INVALID", "artifact execution time is invalid"
            ) from error
        if (
            payload.get("schema_version") != 1
            or payload.get("assessment_id") != assessment_id
            or payload.get("gate") != gate
            or payload.get("artifact_kind") != kind
            or payload.get("assessor") != assessor
            or payload.get("target_digest") != self.release_target_digest
            or payload.get("result") != "PASSED"
            or payload.get("assessment_mode")
            not in {"human", "tool_assisted", "automated"}
            or (gate == "accessibility" and payload.get("assessment_mode") != "human")
            or isinstance(sample_count, bool)
            or not isinstance(sample_count, int)
            or sample_count < 1
            or executed.tzinfo is None
            or executed < started
            or executed > completed
            or not isinstance(findings, list)
        ):
            raise DomainError("ASSURANCE_ARTIFACT_INVALID", "artifact payload values are invalid")
        finding_ids: set[str] = set()
        finding_digests: set[str] = set()
        for finding in findings:
            finding_id = str(finding.get("id", "")) if isinstance(finding, Mapping) else ""
            finding_digest = (
                str(finding.get("digest", "")) if isinstance(finding, Mapping) else ""
            )
            if (
                not isinstance(finding, Mapping)
                or set(finding) != self.FINDING_KEYS
                or not isinstance(finding.get("id"), str)
                or finding_id != finding_id.strip()
                or not finding_id.strip()
                or finding.get("severity")
                not in {"info", "low", "medium", "high", "critical"}
                or finding.get("status") not in {"remediated", "accepted"}
                or (
                    finding.get("severity") in {"high", "critical"}
                    and finding.get("status") != "remediated"
                )
                or not isinstance(finding.get("description"), str)
                or not str(finding.get("description", "")).strip()
                or not re.fullmatch(r"[a-f0-9]{64}", finding_digest)
                or finding_digest
                != canonical_digest({**finding, "digest": ""})
                or finding_id in finding_ids
                or finding_digest in finding_digests
            ):
                raise DomainError("ASSURANCE_ARTIFACT_INVALID", "artifact finding is invalid")
            finding_ids.add(finding_id)
            finding_digests.add(finding_digest)
        return kind, GateCheck(
            "artifact_" + kind,
            actual == item.get("sha256"),
            {"size": path.stat().st_size, "samples": sample_count},
        )

    def import_report(self, report: Mapping[str, Any]) -> GateEvidence:
        if set(report) != self.REPORT_KEYS or report.get("schema_version") != 3:
            raise DomainError("ASSURANCE_REPORT_INVALID", "assurance report fields are invalid")
        gate = str(report.get("gate", ""))
        if gate not in self.ALLOWED_GATES:
            raise DomainError(
                "ASSURANCE_GATE_INVALID",
                "only security, privacy, or accessibility may be imported",
            )
        started = str(report.get("started_at", ""))
        completed = str(report.get("completed_at", ""))
        try:
            started_time = dt.datetime.fromisoformat(started)
            completed_time = dt.datetime.fromisoformat(completed)
            times_valid = (
                started_time.tzinfo is not None
                and completed_time.tzinfo is not None
                and completed_time >= started_time
                and completed_time <= dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5)
                and dt.datetime.now(dt.UTC) - completed_time <= dt.timedelta(days=90)
            )
        except ValueError as error:
            raise DomainError(
                "ASSURANCE_REPORT_INVALID", "assurance timestamps are invalid"
            ) from error
        if (
            not times_valid
            or not str(report.get("assessment_id", "")).strip()
            or not str(report.get("assessor", "")).strip()
        ):
            raise DomainError(
                "ASSURANCE_REPORT_INVALID", "assurance identity or time range is invalid"
            )
        signer_fingerprint = self.trust_store.verify_signer(
            identity=str(report.get("assessor", "")),
            purpose=f"{gate}_assessment",
            public_key_b64=str(report.get("public_key_b64", "")),
            signed_at=completed,
        )
        limitations = report.get("limitations", ())
        if not isinstance(limitations, list) or any(
            not isinstance(item, str) for item in limitations
        ):
            raise DomainError("ASSURANCE_REPORT_INVALID", "limitations must be a string list")
        payload = {key: value for key, value in report.items() if key != "signature_b64"}
        claimed_digest = str(report.get("report_digest", ""))
        digest_payload = {**payload, "report_digest": ""}
        actual_digest = canonical_digest(digest_payload)
        if claimed_digest != actual_digest:
            raise DomainError("ASSURANCE_DIGEST_INVALID", "assurance report digest mismatch")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            Ed25519PublicKey.from_public_bytes(
                base64.b64decode(str(report["public_key_b64"]), validate=True)
            ).verify(
                base64.b64decode(str(report["signature_b64"]), validate=True),
                claimed_digest.encode("ascii"),
            )
        except Exception as error:
            raise DomainError(
                "ASSURANCE_SIGNATURE_INVALID", "assurance report signature is invalid"
            ) from error
        declared_values = report.get("checks", ())
        if not isinstance(declared_values, list) or any(
            not isinstance(item, Mapping)
            or not {"name", "passed"}.issubset(item)
            or set(item) - {"name", "passed", "details"}
            or not str(item.get("name", "")).strip()
            or not isinstance(item.get("passed"), bool)
            or not isinstance(item.get("details", {}), Mapping)
            for item in declared_values
        ):
            raise DomainError("ASSURANCE_CHECKS_INVALID", "assurance checks are invalid")
        declared = tuple(
            GateCheck(str(item["name"]), item["passed"], dict(item.get("details", {})))
            for item in declared_values
        )
        if not declared:
            raise DomainError("ASSURANCE_CHECKS_REQUIRED", "assurance checks are required")
        declared_names = {item.name for item in declared}
        if len(declared_names) != len(declared) or declared_names != set(
            self.REQUIRED_CHECKS[gate]
        ):
            raise DomainError(
                "ASSURANCE_COVERAGE_INCOMPLETE", "required assurance controls are missing"
            )
        if any(
            item.name in self.REQUIRED_CHECKS[gate]
            and item.details != {"artifact_kind": item.name}
            for item in declared
        ):
            raise DomainError(
                "ASSURANCE_COVERAGE_INCOMPLETE",
                "each required control must bind its exact evidence artifact",
            )
        artifact_values = report.get("artifacts", ())
        if not isinstance(artifact_values, list) or any(
            not isinstance(item, Mapping) for item in artifact_values
        ):
            raise DomainError("ASSURANCE_ARTIFACT_INVALID", "artifact list is invalid")
        artifact_results = tuple(
            self._artifact(
                item,
                gate=gate,
                assessment_id=str(report["assessment_id"]),
                assessor=str(report["assessor"]),
                started=started_time,
                completed=completed_time,
            )
            for item in artifact_values
        )
        kinds = [kind for kind, _check in artifact_results]
        if len(kinds) != len(set(kinds)) or set(kinds) != set(self.REQUIRED_CHECKS[gate]):
            raise DomainError(
                "ASSURANCE_ARTIFACTS_REQUIRED",
                "one unique structured artifact is required for every assurance control",
            )
        artifacts = tuple(check for _kind, check in artifact_results)
        checks: Sequence[GateCheck] = (
            GateCheck("signed_report", True),
            GateCheck("trusted_assessor", bool(signer_fingerprint)),
            GateCheck(
                "exact_release_and_environment",
                report.get("candidate_image") == self.candidate_image
                and report.get("build_digest") == self.build_digest
                and report.get("environment_digest") == self.environment_digest
                and report.get("deployment_plan_digest") == self.deployment_plan_digest,
            ),
            *declared,
            *artifacts,
        )
        return complete(
            gate,
            started_at=started,
            coordinates={
                "assessment_id": str(report.get("assessment_id", "")),
                "assessor": str(report.get("assessor", "")),
                "report_digest": claimed_digest,
                "trust_store_digest": self.trust_store.digest,
                "signer_fingerprint": signer_fingerprint,
                "candidate_image": self.candidate_image,
                "build_digest": self.build_digest,
                "environment_digest": self.environment_digest,
                "deployment_plan_digest": self.deployment_plan_digest,
            },
            checks=checks,
            metrics={
                "declared_checks": len(declared),
                "artifacts": len(artifacts),
                "trust_store_id": self.trust_store.store_id,
            },
            limitations=tuple(limitations),
            completed_at=completed,
        )
