def recovery_metrics(episodes):
    count = max(len(episodes), 1)
    return {
        "deterministic_replay_rate": sum(item.replay_match for item in episodes) / count,
        "report_trace_success_rate": sum(
            item.report_success and item.trace_success for item in episodes
        )
        / count,
    }
