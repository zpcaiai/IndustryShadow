from shadow_sandbox.admin import HealthAggregator


def aggregate_readiness(aggregator: HealthAggregator):
    return aggregator.status()
