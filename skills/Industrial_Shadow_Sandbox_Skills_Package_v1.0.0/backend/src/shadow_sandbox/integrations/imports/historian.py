from collections.abc import Iterator, Mapping
from typing import Any, Protocol


class ReadonlyHistorian(Protocol):
    def query(
        self, tags: tuple[str, ...], start: str, end: str, limit: int
    ) -> Iterator[Mapping[str, Any]]: ...
