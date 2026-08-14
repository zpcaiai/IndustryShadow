from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Sequence
from typing import Any

from shadow_sandbox.common.models import DomainError, utc_now
from shadow_sandbox.common.opcua_readonly import (
    ReadonlyAsyncUaAdapter,
    normalize_opcua_security_string,
    opcua_node_allowlist_digest,
    opcua_runtime_binding_digest,
    server_certificate_fingerprint,
)

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

    def __init__(
        self,
        *,
        endpoint_uri: str,
        application_uri: str,
        client_application_uri: str,
        namespace_uri: str,
        certificate_fingerprint: str,
        client_certificate_fingerprint: str,
        next_client_certificate_fingerprint: str,
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
        if (
            not node_ids
            or len(node_ids) > 500
            or len(set(node_ids)) != len(node_ids)
            or any(not node_id.strip() for node_id in node_ids)
        ):
            raise DomainError("OPCUA_NODE_POLICY_INVALID", "1..500 approved nodes are required")
        security_profile, _certificate_path, _key_path, _server_path = (
            normalize_opcua_security_string(
                security_string, code="OPCUA_SECURITY_REQUIRED"
            )
        )
        security_policy = security_profile.split(",", 1)[0]
        if security_policy not in set(allowed_security_policies):
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
        if not client_application_uri or any(
            character.isspace() for character in client_application_uri
        ):
            raise DomainError(
                "OPCUA_CLIENT_APPLICATION_URI_INVALID",
                "real OT client ApplicationUri must be explicitly bound",
            )
        normalized_client_fingerprint = (
            client_certificate_fingerprint.replace(":", "").strip().lower()
        )
        if not re.fullmatch(r"[a-f0-9]{64}", normalized_client_fingerprint):
            raise DomainError(
                "OPCUA_CLIENT_CERTIFICATE_FINGERPRINT_INVALID",
                "real OT client certificate fingerprint must be SHA-256",
            )
        self.application_uri = application_uri
        self.client_application_uri = client_application_uri
        self.namespace_uri = namespace_uri
        self.certificate_fingerprint = normalized_fingerprint
        self.client_certificate_fingerprint = normalized_client_fingerprint
        self.next_client_certificate_fingerprint = (
            next_client_certificate_fingerprint.replace(":", "").strip().lower()
        )
        if (
            not re.fullmatch(r"[a-f0-9]{64}", self.next_client_certificate_fingerprint)
            or self.next_client_certificate_fingerprint
            == self.client_certificate_fingerprint
        ):
            raise DomainError(
                "OPCUA_NEXT_CLIENT_CERTIFICATE_FINGERPRINT_INVALID",
                "next client certificate must be a distinct SHA-256 fingerprint",
            )
        self.node_ids = tuple(dict.fromkeys(node_ids))
        self.security_string = security_string
        self.sampling_interval_ms = sampling_interval_ms
        self.observation_seconds = observation_seconds
        self.security_policy = security_policy
        self.security_profile = security_profile
        self.node_allowlist_digest = opcua_node_allowlist_digest(self.node_ids)
        self.runtime_binding_digest = opcua_runtime_binding_digest(
            endpoint_uri=self.endpoint_uri,
            application_uri=self.application_uri,
            client_application_uri=self.client_application_uri,
            namespace_uri=self.namespace_uri,
            server_certificate_fingerprint=self.certificate_fingerprint,
            client_certificate_fingerprint=self.client_certificate_fingerprint,
            next_client_certificate_fingerprint=self.next_client_certificate_fingerprint,
            security_profile=self.security_profile,
            node_ids=self.node_ids,
            code="OPCUA_RUNTIME_BINDING_INVALID",
        )

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
            from asyncua import Client, ua
        except ImportError as error:
            raise DomainError(
                "ASYNCUA_DEPENDENCY_UNAVAILABLE", "asyncua is required", status=503
            ) from error
        adapter = ReadonlyAsyncUaAdapter(Client(url=self.endpoint_uri))
        adapter.bind_application_uri(self.client_application_uri)
        await adapter.configure_security(self.security_string)
        client_certificate_bound = adapter.client_certificate_bound(
            self.client_certificate_fingerprint
        )
        endpoints = await adapter.endpoint_descriptions()
        matches = [
            item
            for item in endpoints
            if str(item.Server.ApplicationUri) == self.application_uri
            and str(item.SecurityMode).endswith("SignAndEncrypt")
            and str(item.SecurityPolicyUri).endswith("#" + self.security_policy)
        ]
        fingerprints = {
            server_certificate_fingerprint(bytes(item.ServerCertificate))
            for item in matches
        }
        endpoint_identity = bool(matches)
        handler = _SubscriptionHandler()
        read_count = 0
        browse_count = 0
        namespace_match = False
        good_values = 0
        timestamped_values = 0
        readonly_nodes = 0
        method_free_nodes = 0
        access_profiles_checked = 0
        async with adapter:
            client_certificate_bound = client_certificate_bound and (
                adapter.client_certificate_bound(self.client_certificate_fingerprint)
                and adapter.application_uri == self.client_application_uri
            )
            namespace_match = self.namespace_uri in await adapter.namespace_array()
            browse_count = await adapter.browse_object_count()
            inspections = await adapter.inspect_and_read(self.node_ids, ua.AttributeIds)
            for inspection in inspections:
                data_value = inspection.data_value
                good_values += int(data_value.StatusCode.is_good())
                timestamped_values += int(
                    data_value.SourceTimestamp is not None
                    or data_value.ServerTimestamp is not None
                )
                read_count += 1
                access_profiles_checked += 1
                readonly_nodes += int(inspection.readonly)
                method_free_nodes += int(inspection.variable_without_methods)
            if readonly_nodes == len(self.node_ids):
                await adapter.subscribe_for(
                    self.node_ids,
                    sampling_interval_ms=self.sampling_interval_ms,
                    handler=handler,
                    observation_seconds=self.observation_seconds,
                    sleep=asyncio.sleep,
                )

        checks = (
            GateCheck("endpoint_application_uri", endpoint_identity),
            GateCheck("endpoint_certificate", self.certificate_fingerprint in fingerprints),
            GateCheck(
                "client_application_uri",
                adapter.application_uri == self.client_application_uri,
            ),
            GateCheck("client_certificate_session_binding", client_certificate_bound),
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
            GateCheck(
                "access_levels_read_only",
                access_profiles_checked == len(self.node_ids)
                and readonly_nodes == len(self.node_ids),
                {
                    "profiles_checked": access_profiles_checked,
                    "readonly_nodes": readonly_nodes,
                },
            ),
            GateCheck(
                "method_execution_unavailable",
                method_free_nodes == len(self.node_ids),
                {"method_free_nodes": method_free_nodes},
            ),
            GateCheck(
                "read_only_adapter_surface",
                not any(
                    hasattr(adapter, name)
                    for name in ("write", "write_value", "call", "call_method", "get_node")
                ),
            ),
        )
        return complete(
            "real_ot",
            started_at=started,
            coordinates={
                "endpoint_digest": hashlib.sha256(self.endpoint_uri.encode()).hexdigest(),
                "application_uri": self.application_uri,
                "server_application_uri": self.application_uri,
                "client_application_uri": self.client_application_uri,
                "namespace_uri": self.namespace_uri,
                "server_certificate_fingerprint": self.certificate_fingerprint,
                "client_certificate_fingerprint": self.client_certificate_fingerprint,
                "node_allowlist_digest": self.node_allowlist_digest,
                "runtime_binding_digest": self.runtime_binding_digest,
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
                "access_profiles_checked": access_profiles_checked,
                "readonly_nodes": readonly_nodes,
                "method_free_nodes": method_free_nodes,
                "server_certificate_fingerprint": self.certificate_fingerprint,
                "client_certificate_fingerprint": self.client_certificate_fingerprint,
                "next_client_certificate_fingerprint": (
                    self.next_client_certificate_fingerprint
                ),
                "client_application_uri": self.client_application_uri,
                "node_allowlist_digest": self.node_allowlist_digest,
                "runtime_binding_digest": self.runtime_binding_digest,
                "security_policy": self.security_policy,
                "observation_seconds": self.observation_seconds,
            },
        )
