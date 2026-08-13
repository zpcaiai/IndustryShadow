def metric_delta(champion: dict[str, float], challenger: dict[str, float]) -> dict[str, float]:
    return {
        key: challenger.get(key, 0) - champion.get(key, 0)
        for key in sorted(set(champion) | set(challenger))
    }
