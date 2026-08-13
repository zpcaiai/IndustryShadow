from dataclasses import dataclass

from shadow_sandbox.common import DomainError


@dataclass(frozen=True, slots=True)
class SimulatorSettings:
    seed: int = 1
    step_ms: int = 100
    speed: int = 1

    def validate(self) -> None:
        if self.step_ms <= 0 or 1000 % self.step_ms:
            raise DomainError("INVALID_STEP", "step_ms must evenly divide one second")
        if self.speed not in {0, 1, 2, 10, 50}:
            raise DomainError("INVALID_SPEED", "unsupported clock speed")
