def graph_consistency(cause_id: str) -> float:
    return (
        1.0
        if cause_id.split("_", 1)[0] in {"pump", "bearing", "inlet", "outlet", "tank", "heater"}
        else 0.7
    )


def rule_match(expected: set[str], observed: set[str]) -> float:
    return len(expected & observed) / max(len(expected), 1)
