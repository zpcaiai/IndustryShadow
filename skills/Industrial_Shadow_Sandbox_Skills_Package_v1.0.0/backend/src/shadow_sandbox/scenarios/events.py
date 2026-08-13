from shadow_sandbox.common import ActorContext, EventEnvelope

from . import ScenarioSpec


def published_event(actor: ActorContext, spec: ScenarioSpec) -> EventEnvelope:
    return EventEnvelope(
        "scenario.published.v1",
        {"scenario_id": spec.scenario_id, "version": spec.scenario_version, "digest": spec.digest},
        actor.tenant_id,
        actor.workspace_id,
        trace_id=actor.trace_id,
    )
