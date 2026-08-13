def diagnosis_metrics(faults):
    def hit(k):
        return sum(bool(set(item.gold_causes) & set(item.ranked_causes[:k])) for item in faults)

    count = max(len(faults), 1)
    reciprocal = (
        sum(
            1
            / next(
                (i for i, cause in enumerate(item.ranked_causes, 1) if cause in item.gold_causes),
                10**9,
            )
            for item in faults
        )
        / count
    )
    return {
        "top1_hit_rate": hit(1) / count,
        "top2_hit_rate": hit(2) / count,
        "top3_hit_rate": hit(3) / count,
        "mrr": reciprocal,
    }
