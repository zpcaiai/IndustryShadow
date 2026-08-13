def planning_metrics(faults):
    return {
        "weighted_plan_completeness": sum(item.plan_score for item in faults) / max(len(faults), 1),
        "critical_step_omissions": sum(item.critical_step_omitted for item in faults),
    }
