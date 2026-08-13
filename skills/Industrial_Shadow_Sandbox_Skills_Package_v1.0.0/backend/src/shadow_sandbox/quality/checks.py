from __future__ import annotations

from collections.abc import Sequence
from typing import Any


def issue_codes(events: Sequence[Any], expected_count: int) -> tuple[str, ...]:
    issues = []
    if len(events) < expected_count:
        issues.append("missing")
    if any("duplicate" in event.flags for event in events):
        issues.append("duplicate")
    if any("reordered" in event.flags for event in events):
        issues.append("reorder")
    if any(event.status_code not in {"Good", "GoodLocalOverride"} for event in events):
        issues.append("bad_status")
    return tuple(issues)
