from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

from shadow_sandbox.common import DomainError
from shadow_sandbox.common.models import canonical_digest

REPLAY_STAGES = (
    "quality",
    "detect",
    "residual",
    "evidence",
    "hypotheses",
    "check_plan",
    "narrative",
)


@dataclass(frozen=True, slots=True)
class ReplayManifest:
    replay_id: str
    source_run_id: str
    dataset_digest: str
    selected_stages: tuple[str, ...]
    speed: str
    source_versions: Mapping[str, str]
    override_versions: Mapping[str, str]
    output_namespace: str

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class ReplayResult:
    manifest_digest: str
    stage_outputs: Mapping[str, Any]
    output_digest: str


class ReplayExecutor:
    def __init__(self, stages: Mapping[str, Callable[[Any], Any]]) -> None:
        unknown = set(stages) - set(REPLAY_STAGES)
        if unknown:
            raise DomainError("UNREGISTERED_REPLAY_STAGE", "unknown replay stage")
        self.stages = dict(stages)

    def execute(
        self, manifest: ReplayManifest, frozen_input: Any, actual_dataset_digest: str
    ) -> ReplayResult:
        if manifest.dataset_digest != actual_dataset_digest:
            raise DomainError("DATASET_TAMPERED", "frozen dataset digest mismatch")
        if manifest.speed not in {"1x", "2x", "10x", "50x", "max"}:
            raise DomainError("INVALID_REPLAY_SPEED", "unsupported replay speed")
        value = frozen_input
        outputs: dict[str, Any] = {}
        for stage in REPLAY_STAGES:
            if stage in manifest.selected_stages:
                handler = self.stages.get(stage)
                if not handler:
                    raise DomainError("REPLAY_DEPENDENCY_MISSING", f"missing stage {stage}")
                value = handler(value)
                outputs[stage] = value
        return ReplayResult(manifest.digest, outputs, canonical_digest(outputs))


@dataclass(frozen=True, slots=True)
class ExperimentComparison:
    episode_id: str
    champion_digest: str
    challenger_digest: str
    changed: bool
    fields_changed: tuple[str, ...]


def compare_variants(
    champion: Mapping[str, Mapping[str, Any]],
    challenger: Mapping[str, Mapping[str, Any]],
) -> tuple[ExperimentComparison, ...]:
    comparisons: list[ExperimentComparison] = []
    for episode_id in sorted(set(champion) | set(challenger)):
        left = champion.get(episode_id, {})
        right = challenger.get(episode_id, {})
        fields = tuple(
            sorted(key for key in set(left) | set(right) if left.get(key) != right.get(key))
        )
        comparisons.append(
            ExperimentComparison(
                episode_id,
                canonical_digest(left),
                canonical_digest(right),
                bool(fields),
                fields,
            )
        )
    return tuple(comparisons)
