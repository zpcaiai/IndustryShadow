from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from shadow_sandbox.common import Store


@dataclass(frozen=True, slots=True)
class HealthProbe:
    name: str
    critical: bool
    check: Callable[[], Mapping[str, Any]]


class HealthAggregator:
    def __init__(self, probes: list[HealthProbe]) -> None:
        self.probes = probes

    def status(self) -> dict[str, Any]:
        components: dict[str, Any] = {}
        ready = True
        for probe in self.probes:
            try:
                result = dict(probe.check())
            except Exception as exc:  # noqa: BLE001 - health checks isolate dependency faults
                result = {"status": "unavailable", "code": type(exc).__name__}
            components[probe.name] = result
            if probe.critical and result.get("status") not in {"ready", "healthy"}:
                ready = False
        return {"status": "ready" if ready else "unready", "components": components}


def database_probe(store: Store, expected_migration: int = 2) -> dict[str, Any]:
    rows = store.query("SELECT MAX(version) AS version FROM schema_migrations")
    version = rows[0]["version"] if rows else None
    return {
        "status": "ready" if version == expected_migration else "migration_drift",
        "migration_version": version,
        "expected_version": expected_migration,
    }
