from __future__ import annotations

import contextlib
import contextvars
from collections.abc import Iterator

_workspace_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "shadow_workspace_id", default=None
)


def current_workspace_id() -> str | None:
    """Return the trusted request/job workspace bound to this execution context."""
    return _workspace_id.get()


@contextlib.contextmanager
def workspace_scope(workspace_id: str) -> Iterator[None]:
    if (
        not workspace_id
        or len(workspace_id) > 256
        or any(ord(character) < 32 for character in workspace_id)
    ):
        raise ValueError("workspace_id must be a bounded non-empty identifier")
    token = _workspace_id.set(workspace_id)
    try:
        yield
    finally:
        _workspace_id.reset(token)
