from __future__ import annotations

from dataclasses import asdict, dataclass

from shadow_sandbox.common.models import canonical_digest


@dataclass(frozen=True, slots=True)
class ResidualObservation:
    run_id: str
    residual_ref: str
    observed: float | None
    expected: float | None
    residual: float | None
    normalized_magnitude: float | None
    direction: str | None
    applicability: str
    input_quality_refs: tuple[str, ...]
    source_event_refs: tuple[str, ...]
    units: str
    formula_digest: str

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))
