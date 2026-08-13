from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from shadow_sandbox.common.models import DomainError


@dataclass(frozen=True, slots=True)
class OpcUaSecurityConfig:
    certificate_path: Path | None = None
    private_key_path: Path | None = None
    allow_insecure_development: bool = False

    def validate(self) -> None:
        if bool(self.certificate_path) != bool(self.private_key_path):
            raise DomainError(
                "OPCUA_PKI_INCOMPLETE",
                "certificate and private key must be configured together",
                status=503,
            )
        for path in (self.certificate_path, self.private_key_path):
            if path and (not path.is_file() or path.is_symlink()):
                raise DomainError(
                    "OPCUA_PKI_INVALID",
                    "OPC UA key material is unavailable",
                    status=503,
                )
        if not self.certificate_path and not self.allow_insecure_development:
            raise DomainError(
                "OPCUA_SECURE_ENDPOINT_REQUIRED",
                "OPC UA requires certificate-based SignAndEncrypt outside development",
                status=503,
            )
