from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GraphNode:
    id: str
    kind: str
    version: int = 1


@dataclass(frozen=True, slots=True)
class GraphEdge:
    source: str
    target: str
    kind: str
    condition: str | None = None
    version: int = 1
    source_ref: str = "domain-pack"
