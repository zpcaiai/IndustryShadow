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
    """Validate signed OIDC JWTs and bind them to an authorized OAuth client."""

    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str,
        client_id: str,
        *,
        service_client_ids: tuple[str, ...] = (),
        algorithms: tuple[str, ...] = ("RS256",),
    ) -> None:
        try:
            import jwt
        except ImportError as exc:
            raise DomainError(
                "OIDC_DEPENDENCY_UNAVAILABLE", "PyJWT is required for OIDC", status=503
            ) from exc
        self.jwt = jwt
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.client_id = client_id.strip()
        self.service_client_ids = frozenset(item.strip() for item in service_client_ids)
        self.algorithms = tuple(algorithms)
        if (
            not self.audience.strip()
            or not self.client_id
            or any(not item for item in service_client_ids)
            or len(self.service_client_ids) != len(service_client_ids)
            or self.client_id in self.service_client_ids
            or not self.algorithms
            or len(self.algorithms) != len(set(self.algorithms))
            or any(
                item
                not in {
                    "RS256",
                    "RS384",
                    "RS512",
                    "PS256",
                    "PS384",
                    "PS512",
                    "ES256",
                    "ES384",
                    "ES512",
                    "EdDSA",
                }
                for item in self.algorithms
            )
        ):
            raise DomainError(
                "OIDC_CLIENT_POLICY_INVALID",
                "OIDC human and service client policy is invalid",
                status=503,
            )
        self.keys = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=300)

    def _validate_authorized_client(self, claims: Mapping[str, Any], *, service: bool) -> None:
        audience_value = claims.get("aud")
        if isinstance(audience_value, str):
            audiences = (audience_value,)
        elif isinstance(audience_value, list) and all(
            isinstance(item, str) and item for item in audience_value
        ):
            audiences = tuple(audience_value)
        else:
            audiences = ()
        azp_value = claims.get("azp")
        azp = azp_value if isinstance(azp_value, str) and azp_value else None
        multiple_audiences = len(audiences) > 1
        audience_valid = (
            bool(audiences) and len(audiences) == len(set(audiences)) and self.audience in audiences
        )
        if service:
            client_valid = bool(
                self.service_client_ids and azp is not None and azp in self.service_client_ids
            )
        else:
            client_valid = (azp is None and not multiple_audiences) or azp == self.client_id
        if (
            not audience_valid
            or (azp_value is not None and azp is None)
            or (multiple_audiences and azp is None)
            or not client_valid
        ):
            raise DomainError(
                "TOKEN_CLIENT_INVALID",
                "OIDC token is not authorized for this API client policy",
                status=403,
            )

    def validate(self, authorization: str | None) -> ActorContext:
        if not authorization or not authorization.startswith("Bearer "):
            raise DomainError("AUTHENTICATION_REQUIRED", "Bearer token is required", status=401)
        token = authorization.removeprefix("Bearer ").strip()
        try:
            header = self.jwt.get_unverified_header(token)
            if (
                header.get("alg") not in self.algorithms
                or not str(header.get("kid", "")).strip()
                or header.get("typ") not in {"JWT", "at+jwt"}
                or any(name in header for name in ("crit", "jku", "jwk", "x5u"))
            ):
                raise ValueError("JWT protected header is invalid")
            key = self.keys.get_signing_key_from_jwt(token)
            claims: Mapping[str, Any] = self.jwt.decode(
                token,
                key.key,
                algorithms=list(self.algorithms),
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
        service = claims.get("service", False)
        if (
            not tenant_id
            or not workspace_id
            or not roles
            or any(not isinstance(role, str) or not role.strip() for role in roles)
            or len(roles) != len(set(roles))
            or not isinstance(service, bool)
        ):
            raise DomainError(
                "TOKEN_SCOPE_MISSING",
                "tenant, workspace, and roles claims are required",
                status=403,
            )
        self._validate_authorized_client(claims, service=service)
        return ActorContext(
            _identifier(str(claims["sub"]), "subject"),
            _identifier(tenant_id, "tenant_id"),
            _identifier(workspace_id, "workspace_id"),
            frozenset(roles),
            service,
        )
