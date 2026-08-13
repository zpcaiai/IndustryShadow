from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from shadow_sandbox.common.models import DomainError

from .config import EdgeConfig


class ReadonlyOpcUaAdapter:
    """Real Edge surface contains session, browse, read, and subscription only."""

    OPERATIONS = frozenset(
        {"Browse", "Read", "CreateSubscription", "MonitoredItem", "Publish"}
    )

    def __init__(self, config: EdgeConfig, client: Any) -> None:
        config.validate()
        self.config = config
        self.client = client

    def _nodes(self, node_ids: Iterable[str]) -> tuple[str, ...]:
        values = tuple(node_ids)
        if len(values) > self.config.max_nodes:
            raise DomainError("EDGE_NODE_BUDGET", "Edge Node budget exceeded")
        denied = [node for node in values if node not in self.config.node_allowlist]
        if denied:
            raise DomainError(
                "EDGE_NODE_DENIED", "Edge Node is not allowlisted", status=403
            )
        return values

    def browse_nodes(self) -> tuple[Any, ...]:
        return tuple(self.client.browse())

    def read_nodes(self, node_ids: Iterable[str]) -> tuple[Any, ...]:
        return tuple(self.client.read(node) for node in self._nodes(node_ids))

    def create_subscription(
        self, node_ids: Iterable[str], handler: Callable[[Any], None]
    ) -> Any:
        return self.client.subscribe(self._nodes(node_ids), handler)
