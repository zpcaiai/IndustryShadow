from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from typing import ClassVar

from shadow_sandbox.common import DomainError
from shadow_sandbox.common.models import canonical_digest
from shadow_sandbox.diagnosis.hypotheses import DiagnosisResult


@dataclass(frozen=True, slots=True)
class CheckDefinition:
    check_id: str
    category: str
    distinguishes: tuple[str, ...]
    required_signals: tuple[str, ...]
    duration_seconds: int
    cost: float
    risk: int
    simulation_only: bool
    active: bool
    prerequisites: tuple[str, ...]
    rollback: str | None


@dataclass(frozen=True, slots=True)
class CheckStep:
    step_id: str
    sequence: int
    check_id: str
    rationale: str
    hypotheses_distinguished: tuple[str, ...]
    expected_results: Mapping[str, str]
    risk: int
    approval_required: bool
    simulation_only: bool
    prerequisites: tuple[str, ...]
    rollback: str | None


@dataclass(frozen=True, slots=True)
class CheckPlan:
    plan_id: str
    run_id: str
    diagnosis_digest: str
    environment_type: str
    steps: tuple[CheckStep, ...]
    rejected_checks: tuple[str, ...]
    status: str
    policy_digest: str
    plan_hash: str = ""

    def with_hash(self) -> CheckPlan:
        data = asdict(self)
        data["plan_hash"] = ""
        return replace(self, plan_hash=canonical_digest(data))


DEFAULT_CHECKS = (
    CheckDefinition("verify_data_quality", "quality", (), (), 30, 0.1, 0, False, False, (), None),
    CheckDefinition(
        "compare_command_actual",
        "noninvasive",
        ("inlet_valve_stiction", "heater_stuck"),
        (),
        60,
        0.2,
        0,
        False,
        False,
        ("verify_data_quality",),
        None,
    ),
    CheckDefinition(
        "pressure_flow_curve",
        "residual",
        ("pump_efficiency_loss", "outlet_blockage"),
        (),
        60,
        0.3,
        0,
        False,
        False,
        ("verify_data_quality",),
        None,
    ),
    CheckDefinition(
        "current_vibration",
        "residual",
        ("pump_efficiency_loss", "bearing_friction"),
        (),
        60,
        0.3,
        0,
        False,
        False,
        ("verify_data_quality",),
        None,
    ),
    CheckDefinition(
        "mass_balance",
        "residual",
        ("sensor_bias", "tank_leak"),
        (),
        60,
        0.3,
        0,
        False,
        False,
        ("verify_data_quality",),
        None,
    ),
    CheckDefinition(
        "virtual_step_test",
        "active",
        ("inlet_valve_stiction", "pump_efficiency_loss"),
        (),
        90,
        1.0,
        2,
        True,
        True,
        ("verify_data_quality",),
        "restore_snapshot",
    ),
    CheckDefinition(
        "post_recovery_verification", "verification", (), (), 120, 0.2, 0, False, False, (), None
    ),
)


class CheckPlanner:
    ORDER: ClassVar[Mapping[str, int]] = {
        "quality": 0,
        "noninvasive": 1,
        "residual": 2,
        "active": 3,
        "isolation": 4,
        "verification": 5,
    }

    def __init__(self, checks: Sequence[CheckDefinition] = DEFAULT_CHECKS) -> None:
        self.checks = tuple(checks)
        self.policy_digest = canonical_digest([self.checks, self.ORDER, "planner-v1"])

    def plan(self, run_id: str, diagnosis: DiagnosisResult, environment_type: str) -> CheckPlan:
        candidates = {hypothesis.cause_id for hypothesis in diagnosis.hypotheses}
        selected: list[tuple[float, CheckDefinition]] = []
        rejected: list[str] = []
        for check in self.checks:
            if check.simulation_only and environment_type != "simulator":
                rejected.append(check.check_id + ":real_environment")
                continue
            overlap = len(candidates.intersection(check.distinguishes))
            utility = overlap * 2.0 - check.cost - check.risk * 0.5
            if check.category in {"quality", "verification"} or overlap > 0:
                selected.append((utility, check))
        if diagnosis.status == "INCONCLUSIVE":
            selected = [item for item in selected if not item[1].active]
        selected.sort(key=lambda item: (self.ORDER[item[1].category], -item[0], item[1].check_id))
        steps: list[CheckStep] = []
        selected_ids = {check.check_id for _, check in selected}
        for _, check in selected:
            if any(dependency not in selected_ids for dependency in check.prerequisites):
                rejected.append(check.check_id + ":missing_prerequisite")
                continue
            step_id = "step_" + canonical_digest([run_id, check.check_id, len(steps)])[:20]
            steps.append(
                CheckStep(
                    step_id,
                    len(steps) + 1,
                    check.check_id,
                    "distinguish " + ", ".join(check.distinguishes or ("data trust",)),
                    tuple(sorted(candidates.intersection(check.distinguishes))),
                    {cause: "compare versioned expected observation" for cause in candidates},
                    check.risk,
                    check.active or check.risk > 0,
                    check.simulation_only,
                    check.prerequisites,
                    check.rollback,
                )
            )
        if (
            environment_type == "simulator"
            and any(step.approval_required for step in steps)
            and not any(step.check_id == "post_recovery_verification" for step in steps)
        ):
            raise DomainError("POST_VERIFICATION_REQUIRED", "active plans require verification")
        diagnosis_digest = canonical_digest(diagnosis)
        plan_id = "plan_" + canonical_digest([run_id, diagnosis_digest, self.policy_digest])[:24]
        return CheckPlan(
            plan_id,
            run_id,
            diagnosis_digest,
            environment_type,
            tuple(steps),
            tuple(rejected),
            "PROPOSED" if steps else "NO_SAFE_CHECK",
            self.policy_digest,
        ).with_hash()
