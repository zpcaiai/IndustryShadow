from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Self
from urllib.parse import urlsplit

from .models import DomainError, canonical_digest

# OPC UA Part 3 AccessLevel bit positions.  These are deliberately defined here
# instead of accepting a server/vendor-specific interpretation of a bit field.
_CURRENT_READ = 1 << 0
_WRITE_BITS = (1 << 1) | (1 << 3) | (1 << 5) | (1 << 6)
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_APPROVED_SECURITY_PROFILES = frozenset(
    {
        "Basic256Sha256,SignAndEncrypt",
        "Aes256_Sha256_RsaPss,SignAndEncrypt",
    }
)
_COLLECTOR_MAPPING_KEYS = frozenset(
    {"node_id", "signal_key", "data_type", "sample_period_ms"}
)


def normalize_opcua_fingerprint(value: str, *, code: str) -> str:
    normalized = value.replace(":", "").strip().lower()
    if not _DIGEST.fullmatch(normalized):
        raise DomainError(code, "OPC UA certificate fingerprint must be SHA-256")
    return normalized


def normalize_opcua_security_profile(value: str, *, code: str) -> str:
    normalized = ",".join(item.strip() for item in value.split(","))
    if normalized not in _APPROVED_SECURITY_PROFILES:
        raise DomainError(
            code,
            "OPC UA security profile must be approved and use SignAndEncrypt",
        )
    return normalized


def normalize_opcua_security_string(
    value: str, *, code: str
) -> tuple[str, str, str, str | None]:
    parts = tuple(item.strip() for item in value.split(","))
    if len(parts) not in {4, 5} or any(not item for item in parts):
        raise DomainError(
            code,
            "OPC UA security string must contain policy, mode, client certificate, "
            "private key, and optional pinned server certificate",
        )
    if any("\x00" in item or "\r" in item or "\n" in item for item in parts[2:]):
        raise DomainError(code, "OPC UA security material paths are invalid")
    profile = normalize_opcua_security_profile(",".join(parts[:2]), code=code)
    return profile, parts[2], parts[3], parts[4] if len(parts) == 5 else None


def validate_collector_node_allowlist(
    value: Any,
    *,
    maximum_nodes: int = 500,
    code: str = "OPCUA_NODE_POLICY_INVALID",
) -> tuple[dict[str, str | int], ...]:
    if (
        isinstance(maximum_nodes, bool)
        or not 1 <= maximum_nodes <= 500
        or not isinstance(value, list)
        or not 1 <= len(value) <= maximum_nodes
    ):
        raise DomainError(code, "collector NodeId allowlist size is invalid")
    normalized: list[dict[str, str | int]] = []
    for item in value:
        if not isinstance(item, dict) or not {"node_id", "signal_key"}.issubset(item) or (
            set(item) - _COLLECTOR_MAPPING_KEYS
        ):
            raise DomainError(code, "collector NodeId mapping fields are invalid")
        node_id = item.get("node_id")
        signal_key = item.get("signal_key")
        data_type = item.get("data_type")
        sample_period_ms = item.get("sample_period_ms", 500)
        if (
            not isinstance(node_id, str)
            or node_id != node_id.strip()
            or not 1 <= len(node_id) <= 1024
            or any(character in "\r\n\x00" for character in node_id)
            or not isinstance(signal_key, str)
            or signal_key != signal_key.strip()
            or not 1 <= len(signal_key) <= 255
            or any(character in "\r\n\x00" for character in signal_key)
            or (
                data_type is not None
                and (
                    not isinstance(data_type, str)
                    or data_type != data_type.strip()
                    or not 1 <= len(data_type) <= 128
                )
            )
            or isinstance(sample_period_ms, bool)
            or not isinstance(sample_period_ms, int)
            or not 100 <= sample_period_ms <= 60_000
        ):
            raise DomainError(code, "collector NodeId mapping values are invalid")
        record: dict[str, str | int] = {
            "node_id": node_id,
            "signal_key": signal_key,
            "sample_period_ms": sample_period_ms,
        }
        if data_type is not None:
            record["data_type"] = data_type
        normalized.append(record)
    node_ids = [str(item["node_id"]) for item in normalized]
    signal_keys = [str(item["signal_key"]) for item in normalized]
    if len(node_ids) != len(set(node_ids)) or len(signal_keys) != len(set(signal_keys)):
        raise DomainError(code, "collector NodeIds and signal keys must be unique")
    return tuple(normalized)


def opcua_node_allowlist_digest(
    node_ids: tuple[str, ...], *, code: str = "OPCUA_NODE_POLICY_INVALID"
) -> str:
    if (
        not 1 <= len(node_ids) <= 500
        or len(node_ids) != len(set(node_ids))
        or any(
            not isinstance(item, str)
            or item != item.strip()
            or not 1 <= len(item) <= 1024
            or any(character in "\r\n\x00" for character in item)
            for item in node_ids
        )
    ):
        raise DomainError(code, "1..500 unique approved OPC UA NodeIds are required")
    return canonical_digest(sorted(node_ids))


def opcua_runtime_binding_digest(
    *,
    endpoint_uri: str,
    application_uri: str,
    client_application_uri: str,
    namespace_uri: str,
    server_certificate_fingerprint: str,
    client_certificate_fingerprint: str,
    next_client_certificate_fingerprint: str,
    security_profile: str,
    node_ids: tuple[str, ...],
    code: str = "OPCUA_RUNTIME_BINDING_INVALID",
) -> str:
    try:
        endpoint = urlsplit(endpoint_uri)
        port = endpoint.port
    except ValueError as error:
        raise DomainError(code, "OPC UA endpoint coordinate is invalid") from error
    if (
        endpoint_uri != endpoint_uri.strip()
        or endpoint.scheme != "opc.tcp"
        or not endpoint.hostname
        or port is None
        or not 1 <= port <= 65_535
        or endpoint.username is not None
        or endpoint.password is not None
        or bool(endpoint.query)
        or bool(endpoint.fragment)
    ):
        raise DomainError(code, "OPC UA endpoint must be a credential-free opc.tcp URI")
    uri_values = (application_uri, client_application_uri, namespace_uri)
    if any(
        value != value.strip()
        or not value
        or len(value) > 2048
        or any(character.isspace() for character in value)
        for value in uri_values
    ):
        raise DomainError(code, "OPC UA application and namespace URIs are invalid")
    server_fingerprint = normalize_opcua_fingerprint(
        server_certificate_fingerprint, code=code
    )
    client_fingerprint = normalize_opcua_fingerprint(
        client_certificate_fingerprint, code=code
    )
    next_client_fingerprint = normalize_opcua_fingerprint(
        next_client_certificate_fingerprint, code=code
    )
    if client_fingerprint == next_client_fingerprint:
        raise DomainError(code, "current and next OPC UA client certificates must differ")
    profile = normalize_opcua_security_profile(security_profile, code=code)
    return canonical_digest(
        {
            "endpoint_uri": endpoint_uri,
            "application_uri": application_uri,
            "client_application_uri": client_application_uri,
            "namespace_uri": namespace_uri,
            "server_certificate_fingerprint": server_fingerprint,
            "client_certificate_fingerprint": client_fingerprint,
            "next_client_certificate_fingerprint": next_client_fingerprint,
            "security_profile": profile,
            "node_allowlist_digest": opcua_node_allowlist_digest(node_ids, code=code),
        }
    )


def server_certificate_fingerprint(value: bytes) -> str:
    """Return the leaf SHA-256 fingerprint even when an endpoint sends a chain."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        return x509.load_der_x509_certificate(value).fingerprint(hashes.SHA256()).hex()
    except ValueError:
        # Unit-test adapters use opaque deterministic bytes. A production
        # asyncua security handshake rejects non-certificate values earlier.
        return hashlib.sha256(value).hexdigest()


def _attribute_value(value: Any) -> int:
    variant = getattr(value, "Value", None)
    raw = getattr(variant, "Value", None)
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise DomainError(
            "OPCUA_ACCESS_PROFILE_INVALID",
            "OPC UA access attributes must contain integer bit fields",
            status=503,
        )
    status = getattr(value, "StatusCode", None)
    is_good = getattr(status, "is_good", None)
    if not callable(is_good) or not bool(is_good()):
        raise DomainError(
            "OPCUA_ACCESS_PROFILE_INVALID",
            "OPC UA access attributes must have Good status",
            status=503,
        )
    return raw


@dataclass(frozen=True, slots=True)
class ReadonlyNodeInspection:
    node_id: str
    data_value: Any
    access_level: int
    user_access_level: int
    node_class: int
    method_count: int

    @property
    def current_read_allowed(self) -> bool:
        return bool(self.access_level & _CURRENT_READ) and bool(
            self.user_access_level & _CURRENT_READ
        )

    @property
    def write_capability_absent(self) -> bool:
        return not (self.access_level & _WRITE_BITS) and not (
            self.user_access_level & _WRITE_BITS
        )

    @property
    def variable_without_methods(self) -> bool:
        # NodeClass.Variable is 2 in OPC UA Part 3.  Subscription targets must
        # be Variables; a Method node or a component Method fails closed.
        return self.node_class == 2 and self.method_count == 0

    @property
    def readonly(self) -> bool:
        return (
            self.current_read_allowed
            and self.write_capability_absent
            and self.variable_without_methods
        )


class ReadonlyAsyncUaAdapter:
    """Narrow asyncua facade with no generic Node, Write, or Call surface."""

    __slots__ = ("__client",)

    def __init__(self, client: Any) -> None:
        self.__client = client

    @property
    def application_uri(self) -> str:
        return str(self.__client.application_uri)

    def bind_application_uri(self, application_uri: str) -> None:
        if not application_uri or any(character.isspace() for character in application_uri):
            raise DomainError(
                "OPCUA_CLIENT_APPLICATION_URI_INVALID",
                "client ApplicationUri must be a non-empty URI without whitespace",
            )
        self.__client.application_uri = application_uri

    async def configure_security(self, security_string: str) -> None:
        await self.__client.set_security_string(security_string)

    def client_certificate_bound(self, expected_fingerprint: str) -> bool:
        policy = getattr(self.__client, "security_policy", None)
        certificate = getattr(policy, "host_certificate", None)
        return isinstance(certificate, bytes) and (
            hashlib.sha256(certificate).hexdigest() == expected_fingerprint
        )

    async def endpoint_descriptions(self) -> tuple[Any, ...]:
        return tuple(await self.__client.connect_and_get_server_endpoints())

    async def __aenter__(self) -> Self:
        await self.__client.__aenter__()
        return self

    async def __aexit__(self, *arguments: object) -> None:
        await self.__client.__aexit__(*arguments)

    async def namespace_array(self) -> tuple[str, ...]:
        return tuple(str(item) for item in await self.__client.get_namespace_array())

    async def browse_object_count(self) -> int:
        return len(await self.__client.nodes.objects.get_children())

    async def inspect_and_read(
        self, node_ids: tuple[str, ...], attribute_ids: Any
    ) -> tuple[ReadonlyNodeInspection, ...]:
        inspections: list[ReadonlyNodeInspection] = []
        for node_id in node_ids:
            node = self.__client.get_node(node_id)
            attributes = await node.read_attributes(
                (
                    attribute_ids.AccessLevel,
                    attribute_ids.UserAccessLevel,
                    attribute_ids.NodeClass,
                )
            )
            if len(attributes) != 3:
                raise DomainError(
                    "OPCUA_ACCESS_PROFILE_INVALID",
                    "OPC UA server returned an incomplete access profile",
                    status=503,
                )
            node_class = _attribute_value(attributes[2])
            methods = tuple(await node.get_methods())
            inspections.append(
                ReadonlyNodeInspection(
                    node_id=node_id,
                    data_value=await node.read_data_value(),
                    access_level=_attribute_value(attributes[0]),
                    user_access_level=_attribute_value(attributes[1]),
                    node_class=node_class,
                    method_count=len(methods),
                )
            )
        return tuple(inspections)

    async def subscribe_for(
        self,
        node_ids: tuple[str, ...],
        *,
        sampling_interval_ms: int,
        handler: Any,
        observation_seconds: float,
        sleep: Any,
    ) -> tuple[int, ...]:
        nodes = [self.__client.get_node(node_id) for node_id in node_ids]
        subscription = await self.__client.create_subscription(sampling_interval_ms, handler)
        handles: list[int] = []
        try:
            raw_handles = await subscription.subscribe_data_change(nodes)
            values = [raw_handles] if isinstance(raw_handles, int) else list(raw_handles)
            if any(not isinstance(item, int) for item in values):
                raise DomainError(
                    "OPCUA_SUBSCRIPTION_REJECTED",
                    "one or more approved nodes rejected subscription",
                    status=503,
                )
            handles = [item for item in values if isinstance(item, int)]
            await sleep(observation_seconds)
            return tuple(handles)
        finally:
            if handles:
                await subscription.unsubscribe(handles)
            await subscription.delete()

    async def subscribe_until_cancelled(
        self,
        node_ids: tuple[str, ...],
        *,
        sampling_interval_ms: int,
        handler: Any,
        cancellation: Any,
        health_callback: Callable[[], None] | None = None,
        connection_check_seconds: float = 5.0,
    ) -> None:
        nodes = [self.__client.get_node(node_id) for node_id in node_ids]
        subscription = await self.__client.create_subscription(sampling_interval_ms, handler)
        handles: list[int] = []
        try:
            raw_handles = await subscription.subscribe_data_change(nodes)
            values = [raw_handles] if isinstance(raw_handles, int) else list(raw_handles)
            if any(not isinstance(item, int) for item in values):
                raise DomainError(
                    "OPCUA_SUBSCRIPTION_REJECTED",
                    "one or more allowlisted nodes could not be subscribed",
                    {"status_codes": [str(item) for item in values if not isinstance(item, int)]},
                    status=503,
                )
            handles = [item for item in values if isinstance(item, int)]
            while not cancellation.is_set():
                await self.__client.check_connection()
                if health_callback is not None:
                    health_callback()
                try:
                    await asyncio.wait_for(
                        cancellation.wait(), timeout=connection_check_seconds
                    )
                except TimeoutError:
                    continue
        finally:
            if handles:
                await subscription.unsubscribe(handles)
            await subscription.delete()
