TRANSITION_MODES = frozenset({"startup", "shutdown", "load_step"})


def threshold_factor(mode: str) -> float:
    return 2.0 if mode in TRANSITION_MODES else 1.0
