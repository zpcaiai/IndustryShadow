from shadow_sandbox.common import DomainError


def require_simulator(environment_type: str) -> None:
    if environment_type != "simulator":
        raise DomainError("REAL_ACTION_DENIED", "actions target simulator only", status=403)
