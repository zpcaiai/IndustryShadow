from dataclasses import dataclass

from shadow_sandbox.common.models import utc_now


@dataclass(frozen=True, slots=True)
class Incident:
    incident_id: str
    severity: str
    owner: str
    state: str
    opened_at: str

    @classmethod
    def open(cls, incident_id: str, severity: str, owner: str):
        return cls(incident_id, severity, owner, "OPEN", utc_now())
