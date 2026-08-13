from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from shadow_sandbox.common.models import canonical_digest, utc_now


@dataclass(frozen=True, slots=True)
class OpcUaEvent:
    event_type: str
    severity: int
    message: str
    fields: Mapping[str, Any]
    occurred_at: str = ""

    def normalized(self) -> OpcUaEvent:
        return OpcUaEvent(
            self.event_type,
            min(1000, max(1, self.severity)),
            self.message[:512],
            dict(self.fields),
            self.occurred_at or utc_now(),
        )

    @property
    def digest(self) -> str:
        return canonical_digest(
            self.normalized().__dict__
            if hasattr(self, "__dict__")
            else [
                self.event_type,
                self.severity,
                self.message,
                self.fields,
                self.occurred_at,
            ]
        )
