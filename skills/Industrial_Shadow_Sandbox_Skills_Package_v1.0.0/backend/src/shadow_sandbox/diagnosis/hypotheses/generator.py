from .ranker import DEFAULT_CATALOG


def candidates(observed_symptoms: set[str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            cause
            for cause, definition in DEFAULT_CATALOG.items()
            if observed_symptoms & set(definition["symptoms"])
        )
    )
