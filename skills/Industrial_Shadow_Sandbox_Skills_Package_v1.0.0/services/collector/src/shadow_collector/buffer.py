from __future__ import annotations

from collections import deque
from typing import Generic, TypeVar

from shadow_sandbox.common.models import DomainError

T = TypeVar("T")


class BoundedBuffer(Generic[T]):
    def __init__(self, capacity: int, high_watermark: float = 0.8) -> None:
        if capacity <= 0 or not 0 < high_watermark < 1:
            raise ValueError("invalid buffer policy")
        self.capacity = capacity
        self.high_watermark = high_watermark
        self.items: deque[T] = deque()
        self.degraded = False

    def put(self, item: T) -> None:
        if len(self.items) >= self.capacity:
            self.degraded = True
            raise DomainError(
                "COLLECTOR_BACKPRESSURE",
                "bounded collector buffer is full; acquisition must stop rather than drop data",
                status=503,
            )
        self.items.append(item)
        self.degraded = len(self.items) >= int(self.capacity * self.high_watermark)

    def take(self, limit: int) -> list[T]:
        batch = [self.items.popleft() for _ in range(min(limit, len(self.items)))]
        self.degraded = len(self.items) >= int(self.capacity * self.high_watermark)
        return batch

    def __len__(self) -> int:
        return len(self.items)
