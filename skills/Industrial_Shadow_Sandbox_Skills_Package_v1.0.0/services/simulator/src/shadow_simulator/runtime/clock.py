from dataclasses import dataclass

from shadow_sandbox.common import DomainError


@dataclass(slots=True)
class VirtualClock:
    simulation_time: float = 0
    step_ms: int = 100
    speed: int = 1

    def set_speed(self, value: int) -> None:
        if value not in {0, 1, 2, 10, 50}:
            raise DomainError("INVALID_SPEED", "unsupported speed")
        self.speed = value

    def step(self) -> float:
        self.simulation_time += self.step_ms / 1000
        return self.simulation_time
