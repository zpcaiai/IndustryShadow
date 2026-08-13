from shadow_sandbox.common import ActorContext, EventEnvelope

from . import AssetModel


def published_event(actor: ActorContext, model: AssetModel) -> EventEnvelope:
    return EventEnvelope(
        "asset_model.published.v1",
        {"model_id": model.model_id, "version": model.version, "digest": model.digest},
        actor.tenant_id,
        actor.workspace_id,
        trace_id=actor.trace_id,
    )
