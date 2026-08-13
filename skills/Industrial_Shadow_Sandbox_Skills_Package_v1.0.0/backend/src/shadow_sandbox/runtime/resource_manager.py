from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from shadow_sandbox.common import DomainError


class ResourceManager:
    def __init__(self, maximum: int = 4) -> None:
        self._slots = threading.BoundedSemaphore(maximum)

    @contextmanager
    def lease(self) -> Iterator[None]:
        if not self._slots.acquire(blocking=False):
            raise DomainError("RESOURCE_QUOTA_EXCEEDED", "no worker slots available", status=429)
        try:
            yield
        finally:
            self._slots.release()
