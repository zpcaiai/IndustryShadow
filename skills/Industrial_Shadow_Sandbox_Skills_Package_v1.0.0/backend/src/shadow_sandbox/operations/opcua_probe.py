from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Sequence
from typing import Any, cast

from shadow_sandbox.common.models import DomainError, utc_now

from .evidence import GateCheck, GateEvidence, complete


class _SubscriptionHandler:
    def __init__(self) -> None:
        self.notifications = 0
        self.node_ids: set[str] = set()

    def datachange_notification(self, node: Any, val: Any, data: Any) -> None:
        del val, data
        self.notifications += 1
        self.node_ids.add(node.nodeid.to_string())

    def event_notification(self, event: Any) -> None:
        del event

    def status_change_notification(self, status: Any) -> None:
        del status


class ReadonlyOpcUaProbe:
    """Browse/read/subscribe acceptance for a real endpoint; no write/call API exists."""

    OPERATIONS = frozenset({"Browse", "Read", "CreateSubscription", "MonitoredItem", "Publish"})

    def __init__(
        self,
        *,
        endpoint_uri: str,
        application_uri: str,
        namespace_uri: str,
        certificate_fingerprint: str,
        node_ids: Sequence[str],
        security_string: str,
        sampling_interval_ms: int = 500,
        observation_seconds: float = 10.0,
        allowed_security_policies: Sequence[str] = (
            "Basic256Sha256",
            "Aes256_Sha256_RsaPss",
        ),
    ) -> None:
        if not endpoint_uri.startswith("opc.tcp://"):
            raise DomainError("OPCUA_ENDPOINT_INVALID", "OPC UA endpoint must use opc.tcp")
        if not node_ids or len(node_ids) > 500:
            raise DomainError("OPCUA_NODE_POLICY_INVALID", "1..500 approved nodes are required")
        security_parts = [item.strip() for item in security_string.split(",")]
        if len(security_parts) < 2 or security_parts[1] != "SignAndEncrypt":
            raise DomainError(
                "OPCUA_SECURITY_REQUIRED", "real OT probe requires SignAndEncrypt security"
            )
        if security_parts[0] not in set(allowed_security_policies):
            raise DomainError(
                "OPCUA_SECURITY_POLICY_INVALID", "OPC UA security policy is not approved"
            )
        if not 100 <= sampling_interval_ms <= 60_000 or not 5 <= observation_seconds <= 3600:
            raise DomainError(
                "OPCUA_OBSERVATION_POLICY_INVALID", "sampling or observation window is invalid"
            )
        normalized_fingerprint = certificate_fingerprint.replace(":", "").strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", normalized_fingerprint):
            raise DomainError(
                "OPCUA_CERTIFICATE_FINGERPRINT_INVALID",
                "real OT certificate fingerprint must be SHA-256",
            )
        self.endpoint_uri = endpoint_uri
        self.application_uri = application_uri
        self.namespace_uri = namespace_uri
        self.certificate_fingerprint = normalized_fingerprint
        self.node_ids = tuple(dict.fromkeys(node_ids))
        self.security_string = security_string
        self.sampling_interval_ms = sampling_interval_ms
        self.observation_seconds = observation_seconds
        self.security_policy = security_parts[0]

    async def run(self) -> GateEvidence:
        try:
            async with asyncio.timeout(self.observation_seconds + 30.0):
                return await self._run_bounded()
        except TimeoutError as error:
            raise DomainError(
                "OPCUA_PROBE_TIMEOUT", "real OT probe exceeded its bounded execution window", status=503
            ) from error

    async def _run_bounded(self) -> GateEvidence:
        started = utc_now()
        try:
            from asyncua import Client
        except ImportError as error:
            raise DomainError(
                "ASYNCUA_DEPENDENCY_UNAVAILABLE", "asyncua is required", status=503
            ) from error
        client = Client(url=self.endpoint_uri)
        await client.set_security_string(self.security_string)
        endpoints = await client.connect_and_get_server_endpoints()
        matches = [
            item
            for item in endpoints
            if str(item.Server.ApplicationUri) == self.application_uri
            and str(item.SecurityMode).endswith("SignAndEncrypt")
            and str(item.SecurityPolicyUri).endswith("#" + self.security_policy)
        ]
        fingerprints = {
            hashlib.sha256(bytes(item.ServerCertificate)).hexdigest() for item in matches
        }
        endpoint_identity = bool(matches)
        handler = _SubscriptionHandler()
        read_count = 0
        browse_count = 0
        namespace_match = False
        good_values = 0
        timestamped_values = 0
        subscription = None
        handles: list[int] = []
        async with client:
            namespace_match = self.namespace_uri in await client.get_namespace_array()
            browse_count = len(await client.nodes.objects.get_children())
            nodes = [client.get_node(node_id) for node_id in self.node_ids]
            for node in nodes:
                data_value = await node.read_data_value()
                good_values += int(data_value.StatusCode.is_good())
                timestamped_values += int(
                    data_value.SourceTimestamp is not None
                    or data_value.ServerTimestamp is not None
                )
                read_count += 1
            subscription = await client.create_subscription(self.sampling_interval_ms, handler)
            try:
                raw_handles = await subscription.subscribe_data_change(nodes)
                values = [raw_handles] if isinstance(raw_handles, int) else list(raw_handles)
                for item in values:
                    if not isinstance(item, int):
                        raise DomainError(
                            "OPCUA_SUBSCRIPTION_REJECTED",
                            "one or more approved nodes rejected subscription",
                            status=503,
                        )
                    handles.append(cast(int, item))
                await asyncio.sleep(self.observation_seconds)
            finally:
                if handles:
                    await subscription.unsubscribe(handles)
                await subscription.delete()

        forbidden = self.OPERATIONS.intersection({"Write", "Call", "HistoryUpdate"})
        checks = (
            GateCheck("endpoint_application_uri", endpoint_identity),
            GateCheck("endpoint_certificate", self.certificate_fingerprint in fingerprints),
            GateCheck("namespace", namespace_match),
            GateCheck("browse_service", browse_count > 0),
            GateCheck("allowlisted_reads", read_count == len(self.node_ids)),
            GateCheck(
                "read_quality_and_timestamps",
                good_values == len(self.node_ids)
                and timestamped_values == len(self.node_ids),
            ),
            GateCheck(
                "allowlisted_subscription",
                handler.notifications >= len(self.node_ids)
                and set(self.node_ids).issubset(handler.node_ids),
                {"notifications": handler.notifications, "observed_nodes": len(handler.node_ids)},
            ),
            GateCheck("read_only_surface", not forbidden),
        )
        return complete(
            "real_ot",
            started_at=started,
            coordinates={
                "endpoint_digest": hashlib.sha256(self.endpoint_uri.encode()).hexdigest(),
                "application_uri": self.application_uri,
                "namespace_uri": self.namespace_uri,
                "security_policy": self.security_policy,
            },
            checks=checks,
            metrics={
                "approved_nodes": len(self.node_ids),
                "reads": read_count,
                "browsed_objects": browse_count,
                "notifications": handler.notifications,
                "good_values": good_values,
                "timestamped_values": timestamped_values,
                "observation_seconds": self.observation_seconds,
            },
        )
