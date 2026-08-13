from . import CheckDefinition


def utility(check: CheckDefinition, candidates: set[str]) -> float:
    return len(candidates.intersection(check.distinguishes)) * 2.0 - check.cost - check.risk * 0.5
