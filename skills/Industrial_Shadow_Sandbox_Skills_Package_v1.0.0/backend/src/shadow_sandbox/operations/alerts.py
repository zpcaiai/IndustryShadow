from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AlertDefinition:
    name: str
    sli: str
    threshold: float
    owner: str
    dashboard_url: str
    runbook_url: str

    def validate(self) -> None:
        if not self.owner or not self.runbook_url:
            raise ValueError("alerts require an owner and runbook")
