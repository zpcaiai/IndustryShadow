from shadow_sandbox.common import DomainError

from . import CheckPlan


def validate_environment(plan: CheckPlan) -> None:
    if plan.environment_type != "simulator" and any(step.simulation_only for step in plan.steps):
        raise DomainError(
            "REAL_CHECK_DENIED",
            "simulation-only checks cannot target real environments",
            status=403,
        )
