from shadow_sandbox.common import ActorContext, SqliteStore


class AuditService:
    def __init__(self, store: SqliteStore) -> None:
        self.store = store

    def record(
        self, actor: ActorContext, action: str, target: str, result: str, details=None
    ) -> str:
        return self.store.audit(
            actor_id=actor.actor_id,
            tenant_id=actor.tenant_id,
            workspace_id=actor.workspace_id,
            action=action,
            target=target,
            result=result,
            trace_id=actor.trace_id,
            details=details,
        )
