from shadow_sandbox.common import DomainError

SPEEDS = {"1x": 1.0, "2x": 2.0, "10x": 10.0, "50x": 50.0, "max": float("inf")}


def speed_factor(speed: str) -> float:
    if speed not in SPEEDS:
        raise DomainError("INVALID_REPLAY_SPEED", "unsupported replay speed")
    return SPEEDS[speed]
