from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EdgeAuditEvent:
    operation: str
    target: str
    result: str
    sequence: int
