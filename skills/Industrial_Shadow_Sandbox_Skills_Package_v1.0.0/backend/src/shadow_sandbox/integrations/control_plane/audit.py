from shadow_sandbox.common import ActorContext, SqliteStore


def record_tool_decision(
    store: SqliteStore, actor: ActorContext, tool: str, result: str, details=None
) -> str:
    return store.audit(
        actor_id=actor.actor_id,
        tenant_id=actor.tenant_id,
        workspace_id=actor.workspace_id,
        action="tool.invoke",
        target=tool,
        result=result,
        trace_id=actor.trace_id,
        details=details,
    )
