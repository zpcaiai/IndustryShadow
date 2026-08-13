from __future__ import annotations

from typing import Any

from shadow_sandbox.admin import database_probe
from shadow_sandbox.common import Store


def liveness() -> dict[str, str]:
    return {"status": "live"}


def readiness(store: Store) -> dict[str, Any]:
    return database_probe(store)
