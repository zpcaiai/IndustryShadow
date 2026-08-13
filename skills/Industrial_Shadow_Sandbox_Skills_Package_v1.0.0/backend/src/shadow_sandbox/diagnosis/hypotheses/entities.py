from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Hypothesis:
    cause_id: str
    rank: int
    evidence_score: float
    feature_breakdown: Mapping[str, float]
    support: tuple[str, ...]
    contradiction: tuple[str, ...]
    missing_expected: tuple[str, ...]
    causal_paths: tuple[tuple[str, ...], ...]
    candidate_origin: tuple[str, ...]
    ranker_digest: str


@dataclass(frozen=True, slots=True)
class DiagnosisResult:
    status: str
    hypotheses: tuple[Hypothesis, ...]
    quality_state: str
    candidate_coverage: float
    reasons: tuple[str, ...] = ()
    additional_information: tuple[str, ...] = ()
