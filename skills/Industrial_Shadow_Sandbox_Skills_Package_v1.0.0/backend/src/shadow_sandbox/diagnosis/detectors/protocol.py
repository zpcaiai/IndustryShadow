from collections.abc import Sequence
from typing import Protocol

from shadow_sandbox.quality import AnomalyObservation, QualityWindow


class Detector(Protocol):
    detector_ref: str

    def detect(
        self,
        quality: QualityWindow,
        values: Sequence[float],
        baseline_values: Sequence[float],
        mode: str = "steady",
    ) -> tuple[AnomalyObservation, ...]: ...
