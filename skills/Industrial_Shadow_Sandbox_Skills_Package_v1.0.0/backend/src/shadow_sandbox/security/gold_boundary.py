from shadow_sandbox.common import ActorContext, DomainError

from . import redact


def require_evaluator(actor: ActorContext) -> None:
    if not actor.service or "EvaluatorService" not in actor.roles:
        raise DomainError("GOLD_ACCESS_DENIED", "Gold is evaluator-service only", status=403)


__all__ = ["redact", "require_evaluator"]
