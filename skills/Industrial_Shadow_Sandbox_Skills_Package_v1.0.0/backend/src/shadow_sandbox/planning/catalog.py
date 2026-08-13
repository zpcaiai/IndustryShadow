from . import DEFAULT_CHECKS, CheckDefinition


def registered_checks() -> tuple[CheckDefinition, ...]:
    return DEFAULT_CHECKS
