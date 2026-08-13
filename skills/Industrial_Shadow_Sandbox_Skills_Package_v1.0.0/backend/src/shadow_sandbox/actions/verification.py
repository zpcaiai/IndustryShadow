from typing import Protocol


class PostActionVerifier(Protocol):
    def __call__(self, engine: object) -> tuple[str, tuple[str, ...]]: ...
