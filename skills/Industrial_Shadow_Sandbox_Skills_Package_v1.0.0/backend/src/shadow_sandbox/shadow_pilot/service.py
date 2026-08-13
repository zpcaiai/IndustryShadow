from . import PilotMode, assert_no_action_surface, transition


class ShadowPilotService:
    def change_mode(
        self,
        current: PilotMode,
        target: PilotMode,
        gate_passed: bool = False,
        site_approved: bool = False,
    ) -> PilotMode:
        return transition(current, target, gate_passed, site_approved)

    def verify_environment(self, environment_type: str) -> None:
        assert_no_action_surface(environment_type)
