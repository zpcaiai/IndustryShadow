from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import hashlib
import json
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shadow_sandbox.common.db import open_store
from shadow_sandbox.common.models import DomainError

from .client import CollectorPolicy
from .models import RawSignalNormalizer
from .writer import RawEventWriter


@dataclass(frozen=True, slots=True)
class NetworkNotification:
    node_id: str
    signal_key: str
    data_type: str
    value: Any
    source_timestamp: str
    server_timestamp: str
    status_code: str


def _timestamp(value: dt.datetime | None) -> str:
    current = value or dt.datetime.now(dt.UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=dt.UTC)
    return current.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")


async def collect() -> None:
    required = (
        "SHADOW_ENDPOINT_URI",
        "SHADOW_APPLICATION_URI",
        "SHADOW_CERTIFICATE_FINGERPRINT",
        "SHADOW_NAMESPACE_URI",
        "SHADOW_NODE_ALLOWLIST",
        "SHADOW_TRUSTED_RUN_CONTEXT",
    )
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise DomainError(
            "COLLECTOR_CONFIGURATION_MISSING",
            "collector refuses to start without pinned endpoint identity",
            {"missing": missing},
        )
    try:
        from asyncua import Client  # type: ignore[import-not-found]
    except ImportError as exc:
        raise DomainError(
            "ASYNCUA_DEPENDENCY_UNAVAILABLE",
            "install the opcua optional dependency for network collection",
            status=503,
        ) from exc
    try:
        mapping_list = json.loads(os.environ["SHADOW_NODE_ALLOWLIST"])
        context = json.loads(os.environ["SHADOW_TRUSTED_RUN_CONTEXT"])
    except (KeyError, json.JSONDecodeError) as exc:
        raise DomainError(
            "COLLECTOR_SITE_BINDING_REQUIRED",
            "supply JSON Node allowlist and trusted Run binding",
        ) from exc
    if not isinstance(mapping_list, list) or not mapping_list or any(
        not isinstance(item, dict)
        or not isinstance(item.get("node_id"), str)
        or not item["node_id"]
        or not isinstance(item.get("signal_key"), str)
        or not item["signal_key"]
        for item in mapping_list
    ):
        raise DomainError(
            "COLLECTOR_NODE_ALLOWLIST_INVALID",
            "Node allowlist must be a non-empty array of node_id/signal_key mappings",
        )
    node_ids = [item["node_id"] for item in mapping_list]
    if len(node_ids) != len(set(node_ids)):
        raise DomainError(
            "COLLECTOR_NODE_ALLOWLIST_INVALID", "Node allowlist contains duplicate NodeIds"
        )
    context_fields = {"tenant_id", "workspace_id", "run_id", "scenario_id", "endpoint_id"}
    if not isinstance(context, dict) or any(
        not isinstance(context.get(field), str) or not context[field] for field in context_fields
    ):
        raise DomainError(
            "COLLECTOR_RUN_CONTEXT_INVALID", "trusted Run context is incomplete or malformed"
        )
    fingerprint = os.environ["SHADOW_CERTIFICATE_FINGERPRINT"].replace(":", "").lower()
    if not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
        raise DomainError(
            "COLLECTOR_CERTIFICATE_FINGERPRINT_INVALID",
            "certificate fingerprint must be a SHA-256 digest",
        )
    mapping = {item["node_id"]: item for item in mapping_list}
    environment_type = os.environ.get("SHADOW_ENVIRONMENT_TYPE", "real_readonly")
    security = os.environ.get("SHADOW_OPCUA_SECURITY_STRING")
    if environment_type == "real_readonly" and (
        not security or ",SignAndEncrypt," not in f",{security},"
    ):
        raise DomainError(
            "COLLECTOR_OPCUA_SECURITY_REQUIRED",
            "real read-only collection requires SignAndEncrypt OPC UA security",
        )
    policy = CollectorPolicy(
        environment_type,
        os.environ["SHADOW_ENDPOINT_URI"],
        os.environ["SHADOW_APPLICATION_URI"],
        fingerprint,
        os.environ["SHADOW_NAMESPACE_URI"],
        tuple(mapping),
        maximum_nodes=int(os.environ.get("SHADOW_MAXIMUM_NODES", "500")),
        sampling_interval_ms=int(os.environ.get("SHADOW_SAMPLING_INTERVAL_MS", "500")),
    )
    policy.validate_nodes(mapping)
    database_url = os.environ.get(
        "SHADOW_DATABASE_URL",
        f"sqlite:///{os.environ.get('SHADOW_DATABASE_PATH', '.runtime/collector.db')}",
    )
    migrations = Path(__file__).resolve().parents[4] / "migrations"
    database = open_store(
        database_url,
        migrations,
        migrate=os.environ.get("SHADOW_AUTO_MIGRATE", "false").lower() == "true",
    )
    writer = RawEventWriter(database)
    normalizer = RawSignalNormalizer(
        {
            item["signal_key"]: int(item.get("sample_period_ms", 500))
            for item in mapping_list
        }
    )
    client = Client(url=policy.endpoint_uri)
    if security:
        await client.set_security_string(security)
    try:
        endpoints = await client.connect_and_get_server_endpoints()
        matching = [
            endpoint
            for endpoint in endpoints
            if str(endpoint.Server.ApplicationUri) == policy.application_uri
            and hashlib.sha256(bytes(endpoint.ServerCertificate)).hexdigest()
            == policy.certificate_fingerprint
        ]
        if not matching:
            raise DomainError(
                "ENDPOINT_IDENTITY_MISMATCH",
                "pinned OPC UA Application URI and certificate pair not found",
            )

        class Handler:
            def datachange_notification(self, node: Any, val: Any, data: Any) -> None:
                node_id = node.nodeid.to_string()
                metadata = mapping.get(node_id)
                if not metadata:
                    return
                variant = data.monitored_item.Value
                notification = NetworkNotification(
                    node_id,
                    metadata["signal_key"],
                    metadata.get("data_type", type(val).__name__),
                    val,
                    _timestamp(variant.SourceTimestamp),
                    _timestamp(variant.ServerTimestamp),
                    str(variant.StatusCode),
                )
                event = normalizer.normalize(
                    trusted_context=context, notification=notification
                )
                writer.persist([event])

            def event_notification(self, _event: Any) -> None:
                return None

            def status_change_notification(self, _status: Any) -> None:
                return None

        async with client:
            namespaces = await client.get_namespace_array()
            observed_namespace = policy.namespace_uri if policy.namespace_uri in namespaces else ""
            policy.validate_identity(
                application_uri=str(matching[0].Server.ApplicationUri),
                certificate_fingerprint=hashlib.sha256(
                    bytes(matching[0].ServerCertificate)
                ).hexdigest(),
                namespace_uri=observed_namespace,
            )
            nodes = [client.get_node(node_id) for node_id in mapping]
            subscription = await client.create_subscription(
                policy.sampling_interval_ms, Handler()
            )
            subscribed: list[int] = []
            try:
                raw_handles = await subscription.subscribe_data_change(nodes)
                handles = (
                    [raw_handles] if isinstance(raw_handles, int) else list(raw_handles)
                )
                subscribed = [handle for handle in handles if isinstance(handle, int)]
                failures = [handle for handle in handles if not isinstance(handle, int)]
                if failures:
                    raise DomainError(
                        "OPCUA_SUBSCRIPTION_REJECTED",
                        "one or more allowlisted nodes could not be subscribed",
                        {"status_codes": [str(status) for status in failures]},
                        status=503,
                    )
                await asyncio.Event().wait()
            finally:
                if subscribed:
                    await subscription.unsubscribe(subscribed)
                await subscription.delete()
    finally:
        database.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the pinned, Browse/Read/Subscribe-only OPC UA collector"
    )
    parser.parse_args(argv)
    asyncio.run(collect())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
