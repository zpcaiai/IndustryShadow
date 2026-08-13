from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from shadow_sandbox.common import ActorContext, DomainError

OIDC_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/|+-]{0,255}$")


def _identifier(value: str, field: str) -> str:
    if not OIDC_IDENTIFIER.fullmatch(value):
        raise DomainError("TOKEN_SCOPE_INVALID", f"OIDC {field} claim is invalid", status=403)
    return value


@dataclass(frozen=True, slots=True)
class OidcClaims:
    subject: str
    tenant_id: str
    workspace_id: str
    roles: tuple[str, ...]
    service: bool


class OidcValidator:
    """Validates signed OIDC JWTs against issuer JWKS, audience, time, and scope."""

    def __init__(self, issuer: str, audience: str, jwks_url: str) -> None:
        try:
            import jwt
        except ImportError as exc:
            raise DomainError(
                "OIDC_DEPENDENCY_UNAVAILABLE", "PyJWT is required for OIDC", status=503
            ) from exc
        self.jwt = jwt
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.keys = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=300)

    def validate(self, authorization: str | None) -> ActorContext:
        if not authorization or not authorization.startswith("Bearer "):
            raise DomainError("AUTHENTICATION_REQUIRED", "Bearer token is required", status=401)
        token = authorization.removeprefix("Bearer ").strip()
        try:
            header = self.jwt.get_unverified_header(token)
            if (
                header.get("alg") not in {"RS256", "ES256", "EdDSA"}
                or not str(header.get("kid", "")).strip()
                or header.get("typ", "JWT") not in {"JWT", "at+jwt"}
            ):
                raise ValueError("JWT protected header is invalid")
            key = self.keys.get_signing_key_from_jwt(token)
            claims: Mapping[str, Any] = self.jwt.decode(
                token,
                key.key,
                algorithms=["RS256", "ES256", "EdDSA"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except Exception as exc:
            raise DomainError("TOKEN_INVALID", "OIDC token validation failed", status=401) from exc
        tenant_id = str(claims.get("tenant_id", ""))
        workspace_id = str(claims.get("workspace_id", ""))
        roles_value = claims.get("roles", ())
        roles = tuple(roles_value) if isinstance(roles_value, list) else ()
        audience = claims.get("aud")
        multiple_audiences = isinstance(audience, list) and len(audience) > 1
        service = claims.get("service", False)
        if (
            not tenant_id
            or not workspace_id
            or not roles
            or any(not isinstance(role, str) or not role.strip() for role in roles)
            or len(roles) != len(set(roles))
            or not isinstance(service, bool)
            or (multiple_audiences and claims.get("azp") != self.audience)
        ):
            raise DomainError(
                "TOKEN_SCOPE_MISSING",
                "tenant, workspace, and roles claims are required",
                status=403,
            )
        return ActorContext(
            _identifier(str(claims["sub"]), "subject"),
            _identifier(tenant_id, "tenant_id"),
            _identifier(workspace_id, "workspace_id"),
            frozenset(roles),
            service,
        )
