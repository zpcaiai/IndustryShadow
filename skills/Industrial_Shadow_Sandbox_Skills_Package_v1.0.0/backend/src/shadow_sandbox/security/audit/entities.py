from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class AuditRecord:
    actor_id: str
    tenant_id: str
    workspace_id: str
    action: str
    target: str
    result: str
    trace_id: str
    details: Mapping[str, Any]
