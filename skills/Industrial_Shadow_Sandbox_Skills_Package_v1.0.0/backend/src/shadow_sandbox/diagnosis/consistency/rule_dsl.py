from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ConsistencyRule:
    code: str
    residual_ref: str
    minimum_magnitude: float
    direction: str | None = None
