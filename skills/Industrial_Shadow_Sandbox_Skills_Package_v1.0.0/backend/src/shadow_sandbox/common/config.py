from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .models import DomainError

RELEASE_DIGEST = re.compile(r"^(?:sha256:)?([a-f0-9]{64})$")
PLACEHOLDER_FRAGMENT = re.compile(r"(?:replace[-_ ]?with|change[-_ ]?me)", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str = "sqlite:///.runtime/shadow-sandbox.db"
    database_path: Path = Path(".runtime/shadow-sandbox.db")
    import_directory: Path = Path(".runtime/imports")
    environment: str = "development"
    build_digest: str = "source-tree-uncommitted"
    allowed_origins: tuple[str, ...] = ("http://localhost:5173",)
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_client_id: str | None = None
    oidc_authorization_url: str | None = None
    oidc_token_url: str | None = None
    oidc_end_session_url: str | None = None
    oidc_scopes: tuple[str, ...] = ("openid", "profile")
    action_service_url: str | None = None
    internal_service_token: str | None = None
    simulator_url: str | None = None
    simulator_id: str = "default"
    simulator_digest: str | None = None
    auto_migrate: bool = True

    @classmethod
    def from_environment(cls) -> Settings:
        environment = os.getenv("SHADOW_ENVIRONMENT", "development")
        if environment not in {"development", "test", "production"}:
            raise DomainError("CONFIG_INVALID", "SHADOW_ENVIRONMENT is invalid", status=503)
        origins = tuple(
            item.strip()
            for item in os.getenv("SHADOW_ALLOWED_ORIGINS", "http://localhost:5173").split(",")
            if item.strip()
        )
        return cls(
            database_url=os.getenv("SHADOW_DATABASE_URL", "sqlite:///.runtime/shadow-sandbox.db"),
            database_path=Path(os.getenv("SHADOW_DATABASE_PATH", ".runtime/shadow-sandbox.db")),
            import_directory=Path(os.getenv("SHADOW_IMPORT_DIRECTORY", ".runtime/imports")),
            environment=environment,
            build_digest=os.getenv("SHADOW_BUILD_DIGEST", "source-tree-uncommitted"),
            allowed_origins=origins,
            oidc_issuer=os.getenv("SHADOW_OIDC_ISSUER"),
            oidc_audience=os.getenv("SHADOW_OIDC_AUDIENCE"),
            oidc_jwks_url=os.getenv("SHADOW_OIDC_JWKS_URL"),
            oidc_client_id=os.getenv("SHADOW_OIDC_CLIENT_ID"),
            oidc_authorization_url=os.getenv("SHADOW_OIDC_AUTHORIZATION_URL"),
            oidc_token_url=os.getenv("SHADOW_OIDC_TOKEN_URL"),
            oidc_end_session_url=os.getenv("SHADOW_OIDC_END_SESSION_URL"),
            oidc_scopes=tuple(
                scope
                for scope in os.getenv("SHADOW_OIDC_SCOPES", "openid profile").split()
                if scope
            ),
            action_service_url=os.getenv("SHADOW_ACTION_SERVICE_URL"),
            internal_service_token=os.getenv("SHADOW_INTERNAL_SERVICE_TOKEN"),
            simulator_url=os.getenv("SHADOW_SIMULATOR_URL"),
            simulator_id=os.getenv("SHADOW_SIMULATOR_ID", "default"),
            simulator_digest=os.getenv("SHADOW_SIMULATOR_DIGEST"),
            auto_migrate=os.getenv(
                "SHADOW_AUTO_MIGRATE", "true" if environment != "production" else "false"
            ).lower()
            == "true",
        )

    def validate(self) -> None:
        self._validate_build_digest()
        if not self.allowed_origins:
            raise DomainError(
                "ALLOWED_ORIGINS_REQUIRED", "at least one explicit origin is required", status=503
            )
        if self.environment == "production" and not self._is_secure_postgresql_url(
            self.database_url
        ):
            raise DomainError(
                "POSTGRESQL_TLS_REQUIRED",
                "production requires a valid PostgreSQL URL with TLS",
                status=503,
            )
        if self.environment == "production" and (
            not self.oidc_issuer
            or not self.oidc_audience
            or not self.oidc_jwks_url
            or not self.oidc_client_id
            or not self.oidc_authorization_url
            or not self.oidc_token_url
        ):
            raise DomainError(
                "OIDC_CONFIG_REQUIRED",
                "production requires OIDC issuer, audience, JWKS, client, authorization, and token coordinates",
                status=503,
            )
        if self.environment == "production":
            self._validate_https_url(self.oidc_issuer or "", "OIDC_ISSUER_INVALID")
            self._validate_https_url(self.oidc_jwks_url or "", "OIDC_JWKS_URL_INVALID")
            self._validate_https_url(
                self.oidc_authorization_url or "", "OIDC_AUTHORIZATION_URL_INVALID"
            )
            self._validate_https_url(self.oidc_token_url or "", "OIDC_TOKEN_URL_INVALID")
            if self.oidc_end_session_url:
                self._validate_https_url(
                    self.oidc_end_session_url, "OIDC_END_SESSION_URL_INVALID"
                )
            if not (self.oidc_audience or "").strip():
                raise DomainError(
                    "OIDC_AUDIENCE_INVALID",
                    "production OIDC audience must not be blank",
                    status=503,
                )
            if not (self.oidc_client_id or "").strip():
                raise DomainError(
                    "OIDC_CLIENT_ID_INVALID",
                    "production OIDC client ID must not be blank",
                    status=503,
                )
            if "openid" not in self.oidc_scopes or len(self.oidc_scopes) != len(
                set(self.oidc_scopes)
            ):
                raise DomainError(
                    "OIDC_SCOPES_INVALID",
                    "production OIDC scopes must be unique and include openid",
                    status=503,
                )
            if any(not self._is_https_origin(origin) for origin in self.allowed_origins):
                raise DomainError(
                    "ALLOWED_ORIGINS_INVALID",
                    "production origins must be explicit HTTPS URLs",
                    status=503,
                )

    def public_auth_config(self) -> dict[str, object]:
        if self.environment != "production":
            return {"mode": "development"}
        return {
            "mode": "oidc_pkce",
            "issuer": self.oidc_issuer,
            "audience": self.oidc_audience,
            "client_id": self.oidc_client_id,
            "authorization_endpoint": self.oidc_authorization_url,
            "token_endpoint": self.oidc_token_url,
            "end_session_endpoint": self.oidc_end_session_url,
            "scopes": list(self.oidc_scopes),
            "redirect_path": "/auth/callback",
        }

    def validate_control_plane(self) -> None:
        self.validate()
        if self.environment == "production" and (
            not self.action_service_url or not self.internal_service_token
        ):
            raise DomainError(
                "ACTION_SERVICE_CONFIG_REQUIRED",
                "production control plane requires the isolated action service",
                status=503,
            )
        if self.environment == "production" and self.auto_migrate:
            raise DomainError(
                "AUTO_MIGRATE_FORBIDDEN",
                "production services require the versioned migration job",
                status=503,
            )
        self._validate_internal_token()

    def validate_action_plane(self) -> None:
        self._validate_build_digest()
        if self.environment == "production" and not self._is_secure_postgresql_url(
            self.database_url
        ):
            raise DomainError(
                "POSTGRESQL_TLS_REQUIRED",
                "production requires a valid PostgreSQL URL with TLS",
                status=503,
            )
        if self.environment == "production" and self.auto_migrate:
            raise DomainError(
                "AUTO_MIGRATE_FORBIDDEN", "production requires the migration job", status=503
            )
        if not self.simulator_url or not self.simulator_digest:
            raise DomainError(
                "SIMULATOR_CONFIG_REQUIRED",
                "action plane requires a fixed simulator URL and digest",
                status=503,
            )
        if self.environment == "production" and not self._valid_digest(
            self.simulator_digest or ""
        ):
            raise DomainError(
                "SIMULATOR_DIGEST_INVALID",
                "production requires a non-placeholder simulator identity digest",
                status=503,
            )
        self._validate_internal_token(required=True)

    def validate_worker(self) -> None:
        self._validate_build_digest()
        if self.environment == "production" and not self._is_secure_postgresql_url(
            self.database_url
        ):
            raise DomainError(
                "POSTGRESQL_TLS_REQUIRED",
                "production requires a valid PostgreSQL URL with TLS",
                status=503,
            )
        if self.environment == "production" and self.auto_migrate:
            raise DomainError(
                "AUTO_MIGRATE_FORBIDDEN", "production requires the migration job", status=503
            )

    def _validate_internal_token(self, *, required: bool = False) -> None:
        if required and not self.internal_service_token:
            raise DomainError(
                "INTERNAL_TOKEN_REQUIRED", "internal service token is required", status=503
            )
        if self.internal_service_token and len(self.internal_service_token) < 32:
            raise DomainError(
                "INTERNAL_TOKEN_WEAK",
                "internal service token must contain at least 32 characters",
                status=503,
            )

    def _validate_build_digest(self) -> None:
        if self.environment == "production" and not self._valid_digest(self.build_digest):
            raise DomainError(
                "BUILD_DIGEST_INVALID",
                "production requires a non-placeholder SHA-256 build digest",
                status=503,
            )

    @staticmethod
    def _valid_digest(value: str) -> bool:
        match = RELEASE_DIGEST.fullmatch(value)
        return bool(match and match.group(1) != "0" * 64)

    @staticmethod
    def _is_secure_postgresql_url(value: str) -> bool:
        normalized = value.replace("postgresql+psycopg://", "postgresql://", 1)
        parsed = urlsplit(normalized)
        sslmode = parse_qs(parsed.query).get("sslmode", [""])[-1]
        return bool(
            parsed.scheme == "postgresql"
            and parsed.hostname
            and parsed.path.strip("/")
            and sslmode in {"require", "verify-ca", "verify-full"}
        )

    @staticmethod
    def _validate_https_url(value: str, code: str) -> None:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
            or Settings._placeholder_host(parsed.hostname)
            or PLACEHOLDER_FRAGMENT.search(value)
        ):
            raise DomainError(code, "production identity URL must use HTTPS", status=503)

    @staticmethod
    def _is_https_origin(value: str) -> bool:
        parsed = urlsplit(value)
        return bool(
            parsed.scheme == "https"
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
            and parsed.path in {"", "/"}
            and not Settings._placeholder_host(parsed.hostname or "")
            and not PLACEHOLDER_FRAGMENT.search(value)
        )

    @staticmethod
    def _placeholder_host(hostname: str) -> bool:
        lowered = hostname.lower().rstrip(".")
        return lowered in {"localhost", "0.0.0.0", "127.0.0.1", "::1"} or lowered.endswith(
            (".invalid", ".example", ".test")
        )
