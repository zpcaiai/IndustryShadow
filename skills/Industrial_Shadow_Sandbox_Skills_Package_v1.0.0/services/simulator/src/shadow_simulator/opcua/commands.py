from __future__ import annotations

from typing import Any

from shadow_sandbox.asset_registry import SignalDefinition
from shadow_sandbox.common.models import DomainError


def validate_simulator_command(signal: SignalDefinition, value: Any) -> float:
    if (
        signal.access_mode != "simulation_write"
        or "command" not in signal.semantic_tags
    ):
        raise DomainError(
            "OPCUA_WRITE_DENIED", "node is not a simulator command", status=403
        )
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DomainError("OPCUA_TYPE_MISMATCH", "simulator command must be numeric")
    numeric = float(value)
    if signal.minimum is not None and numeric < signal.minimum:
        raise DomainError("OPCUA_RANGE", "simulator command is below range")
    if signal.maximum is not None and numeric > signal.maximum:
        raise DomainError("OPCUA_RANGE", "simulator command is above range")
    return numeric
