from dataclasses import dataclass

from shadow_sandbox.common.models import utc_now


@dataclass(frozen=True, slots=True)
class HumanFeedback:
    diagnosis_id: str
    outcome: str
    actor_id: str
    reason: str
    recorded_at: str

    @classmethod
    def record(cls, diagnosis_id: str, outcome: str, actor_id: str, reason: str):
        return cls(diagnosis_id, outcome, actor_id, reason, utc_now())
