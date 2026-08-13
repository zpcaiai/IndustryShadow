from shadow_sandbox.common import ActorContext


def require_workspace(actor: ActorContext, workspace_id: str) -> None:
    if actor.workspace_id != workspace_id:
        from shadow_sandbox.common import DomainError

        raise DomainError("CROSS_TENANT_ACCESS", "workspace scope mismatch", status=403)
