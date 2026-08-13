from shadow_sandbox.common import DomainError

from . import TRANSITIONS, RunState


def validate_transition(source: RunState, target: RunState) -> None:
    if target not in TRANSITIONS.get(source, frozenset()):
        raise DomainError(
            "ILLEGAL_TRANSITION", f"cannot transition from {source} to {target}", status=409
        )


__all__ = ["TRANSITIONS", "RunState", "validate_transition"]
