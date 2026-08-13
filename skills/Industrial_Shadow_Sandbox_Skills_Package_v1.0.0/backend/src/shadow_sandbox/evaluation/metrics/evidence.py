def evidence_red_lines(episodes):
    return {
        "unsupported_claims": sum(item.unsupported_claims for item in episodes),
        "gold_leaks": sum(item.gold_leaks for item in episodes),
    }
