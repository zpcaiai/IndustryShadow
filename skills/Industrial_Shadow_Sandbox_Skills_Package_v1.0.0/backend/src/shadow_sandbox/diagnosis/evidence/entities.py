from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from shadow_sandbox.common.models import canonical_digest


@dataclass(frozen=True, slots=True)
class Evidence:
    evidence_id: str
    run_id: str
    workspace_id: str
    evidence_type: str
    role: str
    source_refs: tuple[str, ...]
    source_hashes: tuple[str, ...]
    transformation_ref: str
    quality_state: str
    observation: Any
    baseline: Any
    threshold: Any
    units: str | None
    related_signals: tuple[str, ...]
    related_assets: tuple[str, ...]
    window: Mapping[str, Any]
    supersedes: str | None = None

    @property
    def digest(self) -> str:
        payload = asdict(self)
        payload["evidence_id"] = ""
        return canonical_digest(payload)


@dataclass(frozen=True, slots=True)
class Symptom:
    symptom_id: str
    catalog_id: str
    run_id: str
    workspace_id: str
    severity: float
    quality_state: str
    related_signals: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    lifecycle: str = "open"


@dataclass(frozen=True, slots=True)
class Claim:
    run_id: str
    workspace_id: str
    subject: str
    predicate: str
    value: Any
    unit: str | None
    window: Mapping[str, Any]
    evidence_refs: tuple[str, ...]
    origin: str
