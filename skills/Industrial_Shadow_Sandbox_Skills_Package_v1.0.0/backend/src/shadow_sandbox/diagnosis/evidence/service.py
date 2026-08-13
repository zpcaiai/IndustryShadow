from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict
from typing import Any, ClassVar

from shadow_sandbox.common import DomainError
from shadow_sandbox.common.models import canonical_digest

from .entities import Claim, Evidence, Symptom


class EvidenceService:
    MAPPINGS: ClassVar[Mapping[str, str]] = {
        "robust_z_deviation": "signal-deviation",
        "slope_change": "signal-trend-change",
        "mass_balance": "mass-deficit",
        "thermal_balance": "heat-response-mismatch",
        "pump_performance": "flow-response-low",
        "command_response": "command-actual-mismatch",
        "current_load": "current-load-mismatch",
        "vibration_mechanical": "vibration-excess",
        "multi_signal_stale": "multi-signal-stale",
    }

    def __init__(self) -> None:
        self.evidence: dict[str, Evidence] = {}
        self.symptoms: dict[str, Symptom] = {}

    def materialize(
        self,
        *,
        run_id: str,
        workspace_id: str,
        observation_type: str,
        observation: Any,
        baseline: Any,
        threshold: Any,
        quality_state: str,
        source_refs: Sequence[str],
        source_hashes: Sequence[str],
        related_signals: Sequence[str],
        transformation_ref: str,
        units: str | None = None,
        role: str = "support",
        window: Mapping[str, Any] | None = None,
    ) -> tuple[Evidence, Symptom | None]:
        if role not in {"support", "contradiction", "neutral", "missing_expected", "limitation"}:
            raise DomainError("INVALID_EVIDENCE_ROLE", "unknown evidence role")
        provisional = Evidence(
            "",
            run_id,
            workspace_id,
            observation_type,
            role,
            tuple(source_refs),
            tuple(source_hashes),
            transformation_ref,
            quality_state,
            observation,
            baseline,
            threshold,
            units,
            tuple(related_signals),
            tuple(signal.split(".", 1)[0] for signal in related_signals),
            dict(window or {}),
        )
        evidence_id = "ev_" + provisional.digest[:28]
        evidence = Evidence(**{**asdict(provisional), "evidence_id": evidence_id})
        self.evidence.setdefault(evidence_id, evidence)
        catalog_id = self.MAPPINGS.get(observation_type)
        symptom = None
        if catalog_id and role == "support":
            severity = min(
                1.0, max(0.0, abs(float(observation or 0)) / max(abs(float(threshold or 1)), 1e-12))
            )
            symptom_id = "sym_" + canonical_digest([run_id, catalog_id, window or {}])[:28]
            symptom = Symptom(
                symptom_id,
                catalog_id,
                run_id,
                workspace_id,
                severity,
                quality_state,
                tuple(related_signals),
                (evidence_id,),
            )
            self.symptoms[symptom_id] = symptom
        return evidence, symptom


class EvidenceValidator:
    def __init__(self, evidence: Mapping[str, Evidence]) -> None:
        self.evidence = evidence

    def validate_claim(self, claim: Claim) -> None:
        if isinstance(claim.value, (int, float)) and not claim.evidence_refs:
            raise DomainError("EVIDENCE_REQUIRED", "numeric claims require Evidence")
        for reference in claim.evidence_refs:
            item = self.evidence.get(reference)
            if not item:
                raise DomainError("EVIDENCE_NOT_FOUND", "claim cites missing Evidence")
            if item.run_id != claim.run_id or item.workspace_id != claim.workspace_id:
                raise DomainError(
                    "CROSS_SCOPE_EVIDENCE", "claim Evidence scope differs", status=403
                )
            if item.quality_state == "UNTRUSTED" and isinstance(claim.value, (int, float)):
                raise DomainError(
                    "UNTRUSTED_CLAIM", "untrusted Evidence cannot ground a numeric claim"
                )
