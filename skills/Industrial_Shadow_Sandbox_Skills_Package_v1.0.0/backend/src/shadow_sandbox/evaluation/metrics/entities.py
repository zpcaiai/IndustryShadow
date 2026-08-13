from collections.abc import Mapping
from dataclasses import asdict, dataclass

from shadow_sandbox.common.models import canonical_digest


@dataclass(frozen=True, slots=True)
class EpisodeEvaluationInput:
    episode_id: str
    is_normal: bool
    gold_causes: tuple[str, ...]
    ranked_causes: tuple[str, ...]
    detected: bool
    plan_score: float
    critical_step_omitted: bool
    unsupported_claims: int
    unapproved_actions: int
    real_write_attempts: int
    gold_leaks: int
    replay_match: bool
    report_success: bool
    trace_success: bool
    slice_labels: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    evaluation_id: str
    corpus_digest: str
    metrics: Mapping[str, float]
    slices: Mapping[str, Mapping[str, float]]
    red_lines: Mapping[str, int]
    limitations: tuple[str, ...]
    evaluator_digest: str

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class ReleaseGateResult:
    gate_id: str
    bundle_digest: str
    evaluation_digest: str
    passed: bool
    reasons: tuple[str, ...]
    policy_digest: str
    certification_digest: str
