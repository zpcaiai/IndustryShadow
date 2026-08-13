from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DriftResult:
    metric: str
    baseline: float
    observed: float
    threshold: float

    @property
    def exceeded(self) -> bool:
        return abs(self.observed - self.baseline) > self.threshold
