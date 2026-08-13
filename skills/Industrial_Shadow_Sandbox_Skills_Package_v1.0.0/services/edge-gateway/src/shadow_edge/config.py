from __future__ import annotations

import base64
import datetime as dt
from dataclasses import asdict, dataclass

from shadow_sandbox.common.models import DomainError, canonical_json


@dataclass(frozen=True, slots=True)
class EdgeConfig:
    gateway_id: str
    site_id: str
    workspace_id: str
    environment_type: str
    endpoint_application_uri: str
    certificate_fingerprint: str
    namespace_uri: str
    node_allowlist: tuple[str, ...]
    sampling_interval_ms: int
    max_nodes: int
    max_spool_bytes: int
    expires_at: str

    def validate(self) -> None:
        if self.environment_type != "real_readonly":
            raise DomainError(
                "EDGE_ENVIRONMENT_DENIED", "Edge config must be real_readonly"
            )
        if not self.node_allowlist or len(self.node_allowlist) > self.max_nodes:
            raise DomainError("EDGE_NODE_POLICY_INVALID", "invalid Edge Node allowlist")
        expiry = dt.datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        if expiry <= dt.datetime.now(dt.UTC):
            raise DomainError("EDGE_CONFIG_EXPIRED", "Edge config expired")


class Ed25519ConfigVerifier:
    def __init__(self, public_key: bytes) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )  # type: ignore[import-not-found]
        except ImportError as exc:
            raise DomainError(
                "CRYPTOGRAPHY_DEPENDENCY_UNAVAILABLE",
                "cryptography required",
                status=503,
            ) from exc
        self.key = Ed25519PublicKey.from_public_bytes(public_key)

    def verify(self, config: EdgeConfig, signature_b64: str) -> None:
        try:
            self.key.verify(
                base64.b64decode(signature_b64),
                canonical_json(asdict(config)).encode("utf-8"),
            )
        except Exception as exc:
            raise DomainError(
                "EDGE_CONFIG_SIGNATURE_INVALID",
                "signed Edge config failed verification",
            ) from exc
        config.validate()
