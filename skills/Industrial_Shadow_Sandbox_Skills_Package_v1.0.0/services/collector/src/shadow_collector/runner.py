from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import hashlib
import json
import os
import re
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from shadow_sandbox.common.db import open_store
from shadow_sandbox.common.models import DomainError
from shadow_sandbox.common.opcua_readonly import (
    ReadonlyAsyncUaAdapter,
    opcua_runtime_binding_digest,
    server_certificate_fingerprint,
    validate_collector_node_allowlist,
)

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


@dataclass(frozen=True, slots=True)
class CollectorPki:
    current_certificate: Path
    current_private_key: Path
    next_certificate: Path
    next_private_key: Path
    server_certificate: Path
    current_fingerprint: str
    next_fingerprint: str

    @property
    def rotation_ready(self) -> bool:
        return self.current_fingerprint != self.next_fingerprint

    def security_string(self, profile: str) -> str:
        return ",".join(
            (
                profile,
                str(self.current_certificate),
                str(self.current_private_key),
                str(self.server_certificate),
            )
        )


def _load_certificate(path: Path) -> Any:
    from cryptography import x509

    value = path.read_bytes()
    try:
        return x509.load_pem_x509_certificate(value)
    except ValueError:
        return x509.load_der_x509_certificate(value)


def _certificate_fingerprint(path: Path) -> str:
    from cryptography.hazmat.primitives import hashes

    return str(_load_certificate(path).fingerprint(hashes.SHA256()).hex())


def _validate_client_certificate(
    certificate_path: Path, private_key_path: Path, application_uri: str
) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

    if not certificate_path.is_file() or not private_key_path.is_file():
        raise DomainError(
            "COLLECTOR_PKI_FILE_MISSING",
            "current and next collector client PKI files are required",
        )
    if stat.S_IMODE(private_key_path.stat().st_mode) & 0o037:
        raise DomainError(
            "COLLECTOR_PKI_KEY_PERMISSIONS_INVALID",
            "collector client private keys may be owner/group readable but never group-writable or other-accessible",
        )
    certificate = _load_certificate(certificate_path)
    now = dt.datetime.now(dt.UTC)
    try:
        san = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        uri_bound = application_uri in san.get_values_for_type(
            x509.UniformResourceIdentifier
        )
        extended_usage = certificate.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
        client_auth = ExtendedKeyUsageOID.CLIENT_AUTH in extended_usage
        basic = certificate.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound:
        uri_bound = False
        client_auth = False
        basic = None
    try:
        private_key = serialization.load_pem_private_key(
            private_key_path.read_bytes(), password=None
        )
    except (TypeError, ValueError) as error:
        raise DomainError(
            "COLLECTOR_PKI_PRIVATE_KEY_INVALID", "collector private key is invalid"
        ) from error
    public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    key_matches = certificate.public_key().public_bytes(
        serialization.Encoding.DER, public_format
    ) == private_key.public_key().public_bytes(serialization.Encoding.DER, public_format)
    if not (
        certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc
        and uri_bound
        and client_auth
        and basic is not None
        and not basic.ca
        and key_matches
    ):
        raise DomainError(
            "COLLECTOR_PKI_IDENTITY_INVALID",
            "collector client certificate must be current, URI-bound, clientAuth, and key-matched",
        )
    return certificate.fingerprint(hashes.SHA256()).hex()


def _load_collector_pki(
    application_uri: str,
    server_fingerprint: str,
    *,
    expected_current_fingerprint: str,
    expected_next_fingerprint: str,
) -> CollectorPki:
    paths = {
        "current_certificate": Path(os.environ["SHADOW_OPCUA_CLIENT_CERTIFICATE_CURRENT_PATH"]),
        "current_private_key": Path(os.environ["SHADOW_OPCUA_CLIENT_PRIVATE_KEY_CURRENT_PATH"]),
        "next_certificate": Path(os.environ["SHADOW_OPCUA_CLIENT_CERTIFICATE_NEXT_PATH"]),
        "next_private_key": Path(os.environ["SHADOW_OPCUA_CLIENT_PRIVATE_KEY_NEXT_PATH"]),
        "server_certificate": Path(os.environ["SHADOW_OPCUA_SERVER_CERTIFICATE_PATH"]),
    }
    if not paths["server_certificate"].is_file():
        raise DomainError(
            "COLLECTOR_PKI_FILE_MISSING", "pinned OPC UA server certificate is required"
        )
    current = _validate_client_certificate(
        paths["current_certificate"], paths["current_private_key"], application_uri
    )
    next_fingerprint = _validate_client_certificate(
        paths["next_certificate"], paths["next_private_key"], application_uri
    )
    normalized_current = expected_current_fingerprint.replace(":", "").strip().lower()
    normalized_next = expected_next_fingerprint.replace(":", "").strip().lower()
    if (
        current != normalized_current
        or next_fingerprint != normalized_next
        or current == next_fingerprint
    ):
        raise DomainError(
            "COLLECTOR_PKI_ROTATION_INVALID",
            "mounted current/next client certificates must match distinct pinned fingerprints",
        )
    if _certificate_fingerprint(paths["server_certificate"]) != server_fingerprint:
        raise DomainError(
            "COLLECTOR_SERVER_CERTIFICATE_MISMATCH",
            "mounted server certificate does not match the pinned endpoint fingerprint",
        )
    return CollectorPki(
        current_certificate=paths["current_certificate"],
        current_private_key=paths["current_private_key"],
        next_certificate=paths["next_certificate"],
        next_private_key=paths["next_private_key"],
        server_certificate=paths["server_certificate"],
        current_fingerprint=current,
        next_fingerprint=next_fingerprint,
    )


def _validate_collector_plane(identity: str, environment_type: str, endpoint_uri: str) -> None:
    host = (urlsplit(endpoint_uri).hostname or "").lower().rstrip(".")
    simulator_host = host == "simulator" or host.startswith("simulator.")
    if identity == "real_ot":
        valid = environment_type == "real_readonly" and not simulator_host
    elif identity == "simulator":
        valid = environment_type == "simulator" and simulator_host
    else:
        valid = False
    if not valid:
        raise DomainError(
            "COLLECTOR_PLANE_BINDING_INVALID",
            "collector identity, endpoint type, and target plane are not mutually consistent",
        )


def _timestamp(value: dt.datetime | None) -> str:
    current = value or dt.datetime.now(dt.UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=dt.UTC)
    return current.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")


async def collect() -> None:
    required = (
        "SHADOW_COLLECTOR_IDENTITY",
        "SHADOW_ENDPOINT_URI",
        "SHADOW_APPLICATION_URI",
        "SHADOW_CLIENT_APPLICATION_URI",
        "SHADOW_CERTIFICATE_FINGERPRINT",
        "SHADOW_CLIENT_CERTIFICATE_FINGERPRINT",
        "SHADOW_NEXT_CLIENT_CERTIFICATE_FINGERPRINT",
        "SHADOW_NAMESPACE_URI",
        "SHADOW_NODE_ALLOWLIST",
        "SHADOW_TRUSTED_RUN_CONTEXT",
        "SHADOW_OPCUA_SECURITY_PROFILE",
        "SHADOW_OPCUA_CLIENT_CERTIFICATE_CURRENT_PATH",
        "SHADOW_OPCUA_CLIENT_PRIVATE_KEY_CURRENT_PATH",
        "SHADOW_OPCUA_CLIENT_CERTIFICATE_NEXT_PATH",
        "SHADOW_OPCUA_CLIENT_PRIVATE_KEY_NEXT_PATH",
        "SHADOW_OPCUA_SERVER_CERTIFICATE_PATH",
    )
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise DomainError(
            "COLLECTOR_CONFIGURATION_MISSING",
            "collector refuses to start without pinned endpoint identity",
            {"missing": missing},
        )
    try:
        from asyncua import Client, ua  # type: ignore[import-not-found]
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
    mapping_list = list(
        validate_collector_node_allowlist(
            mapping_list,
            maximum_nodes=int(os.environ.get("SHADOW_MAXIMUM_NODES", "500")),
            code="COLLECTOR_NODE_ALLOWLIST_INVALID",
        )
    )
    node_ids = [str(item["node_id"]) for item in mapping_list]
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
    collector_identity = os.environ["SHADOW_COLLECTOR_IDENTITY"]
    _validate_collector_plane(
        collector_identity, environment_type, os.environ["SHADOW_ENDPOINT_URI"]
    )
    security_profile = os.environ["SHADOW_OPCUA_SECURITY_PROFILE"]
    security_parts = tuple(item.strip() for item in security_profile.split(","))
    if security_parts not in {
        ("Basic256Sha256", "SignAndEncrypt"),
        ("Aes256_Sha256_RsaPss", "SignAndEncrypt"),
    }:
        raise DomainError(
            "COLLECTOR_OPCUA_SECURITY_REQUIRED",
            "collection requires an approved SignAndEncrypt OPC UA security profile",
        )
    client_application_uri = os.environ["SHADOW_CLIENT_APPLICATION_URI"]
    pki = _load_collector_pki(
        client_application_uri,
        fingerprint,
        expected_current_fingerprint=os.environ[
            "SHADOW_CLIENT_CERTIFICATE_FINGERPRINT"
        ],
        expected_next_fingerprint=os.environ[
            "SHADOW_NEXT_CLIENT_CERTIFICATE_FINGERPRINT"
        ],
    )
    opcua_runtime_binding_digest(
        endpoint_uri=os.environ["SHADOW_ENDPOINT_URI"],
        application_uri=os.environ["SHADOW_APPLICATION_URI"],
        client_application_uri=client_application_uri,
        namespace_uri=os.environ["SHADOW_NAMESPACE_URI"],
        server_certificate_fingerprint=fingerprint,
        client_certificate_fingerprint=pki.current_fingerprint,
        next_client_certificate_fingerprint=pki.next_fingerprint,
        security_profile=security_profile,
        node_ids=tuple(node_ids),
        code="COLLECTOR_RUNTIME_BINDING_INVALID",
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
    try:
        writer = RawEventWriter(database)
        session_health_path = Path("/tmp/collector-session-health")
        ingestion_health_path = Path("/tmp/collector-ingestion-health")
        session_health_path.unlink(missing_ok=True)
        ingestion_health_path.unlink(missing_ok=True)
        fatal_errors: list[Exception] = []

        def mark_session_healthy() -> None:
            if fatal_errors:
                raise DomainError(
                    "COLLECTOR_PERSISTENCE_FAILED",
                    "collector persistence callback failed; process restart is required",
                    status=503,
                )
            session_health_path.touch(mode=0o600, exist_ok=True)

        def mark_ingestion_healthy() -> None:
            ingestion_health_path.touch(mode=0o600, exist_ok=True)

        normalizer = RawSignalNormalizer(
            {
                item["signal_key"]: int(item.get("sample_period_ms", 500))
                for item in mapping_list
            }
        )
        adapter = ReadonlyAsyncUaAdapter(Client(url=policy.endpoint_uri))
        adapter.bind_application_uri(client_application_uri)
    except Exception:
        database.close()
        raise
    try:
        await adapter.configure_security(pki.security_string(security_profile))
        if not adapter.client_certificate_bound(pki.current_fingerprint):
            raise DomainError(
                "COLLECTOR_CLIENT_SESSION_BINDING_INVALID",
                "active OPC UA security policy is not bound to the mounted current client certificate",
            )
        endpoints = await adapter.endpoint_descriptions()
        matching = [
            endpoint
            for endpoint in endpoints
            if str(endpoint.Server.ApplicationUri) == policy.application_uri
            and server_certificate_fingerprint(bytes(endpoint.ServerCertificate))
            == policy.certificate_fingerprint
            and str(endpoint.SecurityMode).endswith("SignAndEncrypt")
            and str(endpoint.SecurityPolicyUri).endswith("#" + security_parts[0])
        ]
        if not matching:
            raise DomainError(
                "ENDPOINT_IDENTITY_MISMATCH",
                "pinned OPC UA Application URI and certificate pair not found",
            )

        class Handler:
            def datachange_notification(self, node: Any, val: Any, data: Any) -> None:
                try:
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
                    mark_ingestion_healthy()
                # asyncua owns this synchronous callback boundary. Capture every
                # persistence/normalization failure and surface it on the monitored
                # connection loop so Kubernetes restarts the process.
                except Exception as error:  # noqa: BLE001
                    if not fatal_errors:
                        fatal_errors.append(error)

            def event_notification(self, _event: Any) -> None:
                return None

            def status_change_notification(self, _status: Any) -> None:
                return None

        async with adapter:
            if not (
                adapter.client_certificate_bound(pki.current_fingerprint)
                and adapter.application_uri == client_application_uri
            ):
                raise DomainError(
                    "COLLECTOR_CLIENT_SESSION_BINDING_INVALID",
                    "active OPC UA session identity changed after connection",
                )
            namespaces = await adapter.namespace_array()
            observed_namespace = policy.namespace_uri if policy.namespace_uri in namespaces else ""
            policy.validate_identity(
                application_uri=str(matching[0].Server.ApplicationUri),
                certificate_fingerprint=server_certificate_fingerprint(
                    bytes(matching[0].ServerCertificate)
                ),
                namespace_uri=observed_namespace,
            )
            inspections = await adapter.inspect_and_read(tuple(mapping), ua.AttributeIds)
            rejected = [inspection.node_id for inspection in inspections if not inspection.readonly]
            if rejected:
                raise DomainError(
                    "COLLECTOR_WRITE_CAPABILITY_DETECTED",
                    "one or more allowlisted nodes expose write or method capability",
                    {
                        "rejected_node_digests": [
                            hashlib.sha256(node_id.encode()).hexdigest()
                            for node_id in rejected
                        ]
                    },
                    status=403,
                )
            handler = Handler()
            await adapter.subscribe_until_cancelled(
                tuple(mapping),
                sampling_interval_ms=policy.sampling_interval_ms,
                handler=handler,
                cancellation=asyncio.Event(),
                health_callback=mark_session_healthy,
            )
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
