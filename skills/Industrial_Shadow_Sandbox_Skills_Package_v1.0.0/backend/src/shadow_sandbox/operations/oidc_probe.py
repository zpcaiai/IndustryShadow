from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any, ClassVar
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

from shadow_sandbox.common.models import DomainError, utc_now
from shadow_sandbox.security.oidc import OidcValidator

from .evidence import GateCheck, GateEvidence, complete

HttpGet = Callable[[str, Mapping[str, str]], tuple[int, Mapping[str, Any]]]


def _https_url(value: str, name: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise DomainError("OIDC_PROBE_URL_INVALID", f"{name} must be an HTTPS URL")
    return value.rstrip("/")


def _http_get(url: str, headers: Mapping[str, str]) -> tuple[int, Mapping[str, Any]]:
    request = Request(url, headers=dict(headers), method="GET")
    try:
        with urlopen(request, timeout=15) as response:
            if response.geturl() != url:
                raise DomainError(
                    "OIDC_PROBE_REDIRECT_FORBIDDEN", "OIDC probe targets must not redirect"
                )
            status = int(response.status)
            body = response.read(1_048_577)
    except HTTPError as error:
        status = int(error.code)
        body = error.read(1_048_577)
    if len(body) > 1_048_576:
        raise DomainError("OIDC_PROBE_RESPONSE_TOO_LARGE", "probe response exceeds 1 MiB")
    try:
        payload = json.loads(body) if body else {}
    except json.JSONDecodeError:
        payload = {}
    return status, payload if isinstance(payload, Mapping) else {}


class OidcLiveProbe:
    """Verify live discovery, signatures, persona claims, and server-side RBAC."""

    REQUIRED_PERSONAS: ClassVar[Mapping[str, frozenset[str]]] = {
        "viewer": frozenset({"Viewer"}),
        "engineer": frozenset({"Engineer"}),
        "admin": frozenset({"Admin"}),
    }
    FORBIDDEN_PERSONA_ROLES: ClassVar[Mapping[str, frozenset[str]]] = {
        "viewer": frozenset({"Engineer", "Admin"}),
        "engineer": frozenset({"Admin"}),
        "admin": frozenset(),
    }

    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str,
        api_base_url: str,
        *,
        http_get: HttpGet = _http_get,
        validator: OidcValidator | None = None,
    ) -> None:
        self.issuer = _https_url(issuer, "issuer")
        self.jwks_url = _https_url(jwks_url, "JWKS URL")
        self.api_base_url = _https_url(api_base_url, "API base URL")
        self.audience = audience
        if not audience.strip():
            raise DomainError("OIDC_PROBE_AUDIENCE_INVALID", "audience must not be blank")
        self.http_get = http_get
        self.validator = validator or OidcValidator(self.issuer, audience, self.jwks_url)

    def run(self, persona_tokens: Mapping[str, str]) -> GateEvidence:
        started = utc_now()
        if set(persona_tokens) != set(self.REQUIRED_PERSONAS):
            raise DomainError(
                "OIDC_PROBE_PERSONAS_REQUIRED",
                "viewer, engineer, and admin bearer values are required",
            )
        discovery_url = self.issuer + "/.well-known/openid-configuration"
        discovery_status, discovery = self.http_get(discovery_url, {})
        jwks_status, jwks = self.http_get(self.jwks_url, {})
        keys = jwks.get("keys", ())
        supported_algorithms = discovery.get("id_token_signing_alg_values_supported", ())
        checks: list[GateCheck] = [
            GateCheck("discovery_https", discovery_status == 200),
            GateCheck("discovery_issuer", discovery.get("issuer") == self.issuer),
            GateCheck("discovery_jwks", discovery.get("jwks_uri") == self.jwks_url),
            GateCheck(
                "discovery_algorithms",
                isinstance(supported_algorithms, list)
                and bool({"RS256", "ES256", "EdDSA"}.intersection(supported_algorithms))
                and "none" not in supported_algorithms,
            ),
            GateCheck(
                "jwks_keys",
                jwks_status == 200
                and isinstance(keys, list)
                and bool(keys)
                and all(bool(str(item.get("kid", "")).strip()) for item in keys)
                and len({str(item.get("kid", "")) for item in keys}) == len(keys)
                and all(item.get("kty") in {"RSA", "EC", "OKP"} for item in keys),
            ),
        ]
        actors = {}
        for persona, expected_roles in self.REQUIRED_PERSONAS.items():
            actor = self.validator.validate("Bearer " + persona_tokens[persona])
            actors[persona] = actor
            checks.append(
                GateCheck(
                    f"{persona}_claims",
                    bool(actor.actor_id and actor.tenant_id and actor.workspace_id)
                    and expected_roles.issubset(actor.roles)
                    and not self.FORBIDDEN_PERSONA_ROLES[persona].intersection(actor.roles),
                    {"role_count": len(actor.roles), "service_identity": actor.service},
                )
            )
            me_status, me = self.http_get(
                urljoin(self.api_base_url + "/", "api/v1/me"),
                {"Authorization": "Bearer " + persona_tokens[persona]},
            )
            checks.append(
                GateCheck(
                    f"{persona}_server_identity",
                    me_status == 200
                    and me.get("actor_id") == actor.actor_id
                    and me.get("tenant_id") == actor.tenant_id
                    and me.get("workspace_id") == actor.workspace_id,
                )
            )
        tenant_scope = {(actor.tenant_id, actor.workspace_id) for actor in actors.values()}
        checks.append(GateCheck("persona_scope_consistency", len(tenant_scope) == 1))
        checks.append(
            GateCheck(
                "persona_subjects_distinct",
                len({actor.actor_id for actor in actors.values()}) == len(actors),
            )
        )

        admin_path = urljoin(self.api_base_url + "/", "api/v1/admin/quotas")
        viewer_status, _ = self.http_get(
            admin_path,
            {
                "Authorization": "Bearer " + persona_tokens["viewer"],
                "X-Actor-Id": "forged-admin",
                "X-Roles": "Admin",
            },
        )
        engineer_status, _ = self.http_get(
            admin_path, {"Authorization": "Bearer " + persona_tokens["engineer"]}
        )
        admin_status, _ = self.http_get(
            admin_path, {"Authorization": "Bearer " + persona_tokens["admin"]}
        )
        anonymous_status, _ = self.http_get(admin_path, {})
        invalid_status, _ = self.http_get(
            admin_path, {"Authorization": "Bearer invalid-production-probe-token"}
        )
        checks.extend(
            (
                GateCheck("viewer_forgery_denied", viewer_status == 403),
                GateCheck("engineer_admin_denied", engineer_status == 403),
                GateCheck("admin_authorized", admin_status == 200),
                GateCheck("anonymous_denied", anonymous_status == 401),
                GateCheck("invalid_token_denied", invalid_status == 401),
            )
        )
        return complete(
            "oidc",
            started_at=started,
            coordinates={
                "issuer": self.issuer,
                "audience_digest": hashlib.sha256(self.audience.encode()).hexdigest(),
                "api_origin": f"{urlsplit(self.api_base_url).scheme}://{urlsplit(self.api_base_url).netloc}",
            },
            checks=checks,
            metrics={"personas": len(actors), "discovery_status": discovery_status},
        )
