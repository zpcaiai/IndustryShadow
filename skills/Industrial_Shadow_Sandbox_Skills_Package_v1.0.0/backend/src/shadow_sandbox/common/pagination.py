from __future__ import annotations

import base64

from .models import DomainError


def encode_cursor(resource_id: str) -> str:
    return base64.urlsafe_b64encode(resource_id.encode()).decode().rstrip("=")


def decode_cursor(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode()
    except Exception as exc:
        raise DomainError("CURSOR_INVALID", "pagination cursor is malformed") from exc
