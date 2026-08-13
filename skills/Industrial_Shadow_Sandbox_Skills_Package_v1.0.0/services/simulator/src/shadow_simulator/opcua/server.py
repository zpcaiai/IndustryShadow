from __future__ import annotations

import datetime as dt
import hmac
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shadow_sandbox.asset_registry import AssetModel
from shadow_sandbox.common.models import DomainError, canonical_digest

from ..model import SimulatorEngine, StateFrame
from .address_space import build_address_space
from .publisher import FramePublisher
from .security import OpcUaSecurityConfig


@dataclass(frozen=True, slots=True)
class OpcUaServerConfig:
    endpoint: str = "opc.tcp://0.0.0.0:4840/shadow"
    application_uri: str = "urn:industrial-shadow:simulator"
    namespace_uri: str = "urn:industrial-shadow:model"
    server_name: str = "Industrial Shadow Simulator"
    certificate_path: Path | None = None
    private_key_path: Path | None = None
    trusted_client_fingerprints: frozenset[str] = frozenset()
    allow_insecure_development: bool = False


class AsyncUaSimulatorServer:
    """Real asyncua publisher with a generated, network-read-only address space.

    Simulation commands stay on the typed, approval-gated action API. Deliberately
    not setting OPC UA variables writable guarantees Collector credentials cannot
    become an alternate control path.
    """

    def __init__(
        self, model: AssetModel, engine: SimulatorEngine, config: OpcUaServerConfig
    ) -> None:
        self.model = model
        self.engine = engine
        self.config = config
        self.server: Any | None = None
        self.publisher: FramePublisher | None = None
        self.nodes: dict[str, Any] = {}
        self.namespace_index: int | None = None
        self.certificate_fingerprint: str | None = None

    @property
    def identity_digest(self) -> str:
        return canonical_digest(
            {
                "application_uri": self.config.application_uri,
                "namespace_uri": self.config.namespace_uri,
                "model_digest": self.model.digest,
                "simulator_model_digest": self.engine.model_digest,
                "certificate_fingerprint": self.certificate_fingerprint,
                "trusted_client_fingerprints": sorted(
                    self.config.trusted_client_fingerprints
                ),
            }
        )

    async def start(self) -> None:
        security = OpcUaSecurityConfig(
            self.config.certificate_path,
            self.config.private_key_path,
            self.config.allow_insecure_development,
        )
        security.validate()
        try:
            from asyncua import Server, ua
        except ImportError as exc:
            raise DomainError(
                "ASYNCUA_DEPENDENCY_UNAVAILABLE",
                "install the opcua dependency to expose the network server",
                status=503,
            ) from exc
        server = Server()
        await server.init()
        server.set_endpoint(self.config.endpoint)
        server.set_server_name(self.config.server_name)
        await server.set_application_uri(self.config.application_uri)
        if security.certificate_path and security.private_key_path:
            from asyncua.common.utils import ServiceError
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.x509.oid import ExtensionOID

            trusted = self.config.trusted_client_fingerprints
            if not trusted and not self.config.allow_insecure_development:
                raise DomainError(
                    "OPCUA_CLIENT_TRUST_REQUIRED",
                    "secure OPC UA requires at least one pinned client certificate",
                    status=503,
                )

            async def validate_client_certificate(
                certificate: Any, application: Any
            ) -> None:
                fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
                if not any(
                    hmac.compare_digest(fingerprint, expected) for expected in trusted
                ):
                    raise ServiceError(ua.StatusCodes.BadCertificateUntrusted)
                now = dt.datetime.now(dt.UTC)
                not_before = certificate.not_valid_before_utc
                not_after = certificate.not_valid_after_utc
                if not not_before <= now <= not_after:
                    raise ServiceError(ua.StatusCodes.BadCertificateTimeInvalid)
                try:
                    names = certificate.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                    ).value
                    application_uris = set(
                        names.get_values_for_type(x509.UniformResourceIdentifier)
                    )
                except x509.ExtensionNotFound:
                    application_uris = set()
                if str(application.ApplicationUri) not in application_uris:
                    raise ServiceError(ua.StatusCodes.BadCertificateUriInvalid)

            certificate_bytes = security.certificate_path.read_bytes()
            private_key_bytes = security.private_key_path.read_bytes()
            certificate_format = (
                "pem" if certificate_bytes.lstrip().startswith(b"-----BEGIN") else "der"
            )
            private_key_format = (
                "pem" if private_key_bytes.lstrip().startswith(b"-----BEGIN") else "der"
            )
            await server.load_certificate(
                security.certificate_path, format=certificate_format
            )
            await server.load_private_key(
                security.private_key_path, format=private_key_format
            )
            server.set_certificate_validator(validate_client_certificate)
            server.set_security_policy(
                [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt]
            )
            server.set_identity_tokens([ua.X509IdentityToken])
            try:
                certificate = x509.load_pem_x509_certificate(certificate_bytes)
            except ValueError:
                certificate = x509.load_der_x509_certificate(certificate_bytes)
            self.certificate_fingerprint = certificate.fingerprint(
                hashes.SHA256()
            ).hex()
            # Loading and fingerprinting normalize PEM and DER to the same
            # certificate identity used by endpoint-verification clients.
        else:
            server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
            server.set_identity_tokens([ua.AnonymousIdentityToken])
        index = await server.register_namespace(self.config.namespace_uri)
        self.namespace_index = index
        asset_nodes: dict[str, Any] = {}
        remaining = list(self.model.assets)
        while remaining:
            created = 0
            for asset in tuple(remaining):
                if asset.parent and asset.parent not in asset_nodes:
                    continue
                parent = (
                    asset_nodes[asset.parent] if asset.parent else server.nodes.objects
                )
                asset_nodes[asset.key] = await parent.add_object(
                    ua.NodeId.from_string(f"ns={index};s=asset:{asset.key}"),
                    asset.display_name,
                )
                remaining.remove(asset)
                created += 1
            if not created:
                raise DomainError(
                    "OPCUA_MAPPING_INVALID",
                    "asset containment cannot be resolved",
                    status=503,
                )
        type_map = {
            "Double": ua.VariantType.Double,
            "Float": ua.VariantType.Float,
            "Int32": ua.VariantType.Int32,
            "Int64": ua.VariantType.Int64,
            "Boolean": ua.VariantType.Boolean,
            "String": ua.VariantType.String,
            "Enum": ua.VariantType.String,
        }
        initial_by_type: dict[str, Any] = {
            "Double": 0.0,
            "Float": 0.0,
            "Int32": 0,
            "Int64": 0,
            "Boolean": False,
            "String": "",
            "Enum": "",
        }
        build_address_space(self.model)
        for signal in self.model.signals:
            try:
                variant_type = type_map[signal.data_type]
            except KeyError as exc:
                raise DomainError(
                    "OPCUA_DATA_TYPE_UNSUPPORTED", signal.data_type, status=503
                ) from exc
            node = await asset_nodes[signal.asset_key].add_variable(
                ua.NodeId.from_string(f"ns={index};s={signal.key}"),
                signal.display_name,
                initial_by_type[signal.data_type],
                varianttype=variant_type,
            )
            self.nodes[signal.key] = node
        self.publisher = FramePublisher(ua, self.nodes)
        await server.start()
        self.server = server

    async def publish(self, frame: StateFrame) -> None:
        if not self.publisher:
            raise DomainError(
                "OPCUA_SERVER_NOT_STARTED", "OPC UA server is not running", status=503
            )
        await self.publisher.publish(frame)

    async def stop(self) -> None:
        if self.server:
            await self.server.stop()
            self.server = None
            self.publisher = None
