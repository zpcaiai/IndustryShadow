from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import DomainError


def problem(
    code: str, detail: str, *, status: int = 400, context: Mapping[str, Any] | None = None
) -> DomainError:
    return DomainError(code, detail, context, status)
