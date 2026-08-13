from __future__ import annotations

from enum import StrEnum

from shadow_sandbox.common.models import DomainError


class PilotMode(StrEnum):
    CONNECTION_ASSESSMENT = "CONNECTION_ASSESSMENT"
    SILENT_SHADOW = "SILENT_SHADOW"
    ADVISORY = "ADVISORY"
    PAUSED = "PAUSED"
    OFFBOARDED = "OFFBOARDED"


TRANSITIONS = {
    PilotMode.CONNECTION_ASSESSMENT: {
        PilotMode.SILENT_SHADOW,
        PilotMode.PAUSED,
        PilotMode.OFFBOARDED,
    },
    PilotMode.SILENT_SHADOW: {PilotMode.ADVISORY, PilotMode.PAUSED, PilotMode.OFFBOARDED},
    PilotMode.ADVISORY: {PilotMode.PAUSED, PilotMode.SILENT_SHADOW, PilotMode.OFFBOARDED},
    PilotMode.PAUSED: {PilotMode.SILENT_SHADOW, PilotMode.OFFBOARDED},
    PilotMode.OFFBOARDED: set(),
}


def transition(
    current: PilotMode, target: PilotMode, gate_passed: bool = False, site_approved: bool = False
) -> PilotMode:
    if target not in TRANSITIONS[current]:
        raise DomainError("PILOT_TRANSITION_DENIED", "invalid pilot transition", status=409)
    if target == PilotMode.ADVISORY and not (gate_passed and site_approved):
        raise DomainError(
            "ADVISORY_GATE_REQUIRED", "advisory requires pilot Gate and site approval"
        )
    return target


def assert_no_action_surface(environment_type: str) -> None:
    if environment_type != "simulator":
        raise DomainError(
            "REAL_RUN_ACTION_DENIED",
            "real read-only Runs have no approval/action surface",
            status=403,
        )
