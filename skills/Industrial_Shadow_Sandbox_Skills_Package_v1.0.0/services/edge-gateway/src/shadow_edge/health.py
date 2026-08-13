from dataclasses import dataclass

from shadow_sandbox.common.models import utc_now


@dataclass(frozen=True, slots=True)
class GatewayHealth:
    state: str
    backlog: int
    last_sequence: int
    observed_at: str

    @classmethod
    def current(cls, state: str, backlog: int, last_sequence: int):
        return cls(state, backlog, last_sequence, utc_now())
