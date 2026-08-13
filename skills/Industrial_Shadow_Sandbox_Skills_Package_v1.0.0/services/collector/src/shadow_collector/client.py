from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from shadow_sandbox.common.models import DomainError


@dataclass(frozen=True, slots=True)
class CollectorPolicy:
    environment_type: str
    endpoint_uri: str
    application_uri: str
    certificate_fingerprint: str
    namespace_uri: str
    allowed_node_prefixes: tuple[str, ...]
    maximum_nodes: int = 500
    sampling_interval_ms: int = 500

    def validate_identity(
        self,
        *,
        application_uri: str,
        certificate_fingerprint: str,
        namespace_uri: str,
    ) -> None:
        if self.environment_type not in {"simulator", "real_readonly"}:
            raise DomainError(
                "ENDPOINT_TYPE_DENIED", "collector endpoint type is not read-only"
            )
        if application_uri != self.application_uri:
            raise DomainError(
                "APPLICATION_URI_MISMATCH", "endpoint application URI mismatch"
            )
        if certificate_fingerprint != self.certificate_fingerprint:
            raise DomainError("CERTIFICATE_MISMATCH", "endpoint certificate mismatch")
        if namespace_uri != self.namespace_uri:
            raise DomainError("NAMESPACE_MISMATCH", "endpoint namespace mismatch")

    def validate_nodes(self, node_ids: Iterable[str]) -> tuple[str, ...]:
        nodes = tuple(node_ids)
        if len(nodes) > self.maximum_nodes:
            raise DomainError("NODE_BUDGET_EXCEEDED", "too many subscription nodes")
        for node_id in nodes:
            if not any(
                node_id.startswith(prefix) for prefix in self.allowed_node_prefixes
            ):
                raise DomainError(
                    "NODE_DENIED", f"NodeId is not allowlisted: {node_id}", status=403
                )
        return nodes


class ReadonlySubscriptionClient:
    """Collector dependency surface deliberately contains acquisition operations only."""

    ALLOWED_OPERATIONS = frozenset({"Browse", "Read", "Subscribe"})

    def __init__(self, policy: CollectorPolicy, adapter: Any) -> None:
        self.policy = policy
        self.adapter = adapter
        self.connected = False
        self.connection_events: list[dict[str, Any]] = []

    def connect(
        self,
        *,
        application_uri: str,
        certificate_fingerprint: str,
        namespace_uri: str,
    ) -> None:
        self.policy.validate_identity(
            application_uri=application_uri,
            certificate_fingerprint=certificate_fingerprint,
            namespace_uri=namespace_uri,
        )
        self.connected = True
        self.connection_events.append(
            {"kind": "connect", "application_uri": application_uri}
        )

    def browse(self) -> tuple[Any, ...]:
        if not self.connected:
            raise DomainError("COLLECTOR_DISCONNECTED", "collector is not connected")
        return tuple(self.adapter.browse("shadow"))

    def read_nodes(self, node_ids: Iterable[str]) -> tuple[Any, ...]:
        nodes = self.policy.validate_nodes(node_ids)
        if not self.connected:
            raise DomainError("COLLECTOR_DISCONNECTED", "collector is not connected")
        return tuple(self.adapter.read("shadow", node_id) for node_id in nodes)

    def subscribe(
        self, node_ids: Iterable[str], callback: Callable[[Any], None]
    ) -> None:
        nodes = self.policy.validate_nodes(node_ids)
        if not self.connected:
            raise DomainError("COLLECTOR_DISCONNECTED", "collector is not connected")
        for node_id in nodes:
            self.adapter.subscribe("shadow", node_id, callback)
        self.connection_events.append(
            {"kind": "subscription_created", "node_count": len(nodes)}
        )

    def disconnect(self) -> None:
        self.connected = False
        self.connection_events.append({"kind": "disconnect"})
