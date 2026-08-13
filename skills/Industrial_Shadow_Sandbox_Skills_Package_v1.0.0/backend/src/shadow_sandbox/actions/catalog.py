from . import ACTION_NAMES


def registered_actions() -> tuple[str, ...]:
    return tuple(sorted(ACTION_NAMES))
