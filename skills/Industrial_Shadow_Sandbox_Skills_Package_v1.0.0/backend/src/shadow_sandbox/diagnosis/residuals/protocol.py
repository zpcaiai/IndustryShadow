from typing import Protocol

from .entities import ResidualObservation


class RegisteredResidual(Protocol):
    residual_ref: str

    def evaluate(
        self, run_id: str, inputs: dict[str, object], quality: str
    ) -> ResidualObservation: ...
