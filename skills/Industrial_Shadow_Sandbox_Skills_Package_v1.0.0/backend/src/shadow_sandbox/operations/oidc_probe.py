from __future__ import annotations

import datetime as dt
import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any, ClassVar
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from shadow_sandbox.common.models import DomainError, utc_now
from shadow_sandbox.security.oidc import OidcValidator

from .evidence import GateCheck, GateEvidence, complete

HttpGet = Callable[[str, Mapping[str, str]], tuple[int, Mapping[str, Any]]]


class _RejectRedirects(HTTPRedirectHandler):
    """Do not replay bearer values to a redirect target."""

    def redirect_request(  # type: ignore[override]
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl


_NO_REDIRECT_OPENER = build_opener(_RejectRedirects())


def _https_url(value: str, name: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise DomainError("OIDC_PROBE_URL_INVALID", f"{name} must be an HTTPS URL")
    return value.rstrip("/")


def _http_get(url: str, headers: Mapping[str, str]) -> tuple[int, Mapping[str, Any]]:
    request = Request(url, headers=dict(headers), method="GET")
    try:
        with _NO_REDIRECT_OPENER.open(request, timeout=15) as response:
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

    REQUIRED_IDENTITIES: ClassVar[Mapping[str, tuple[frozenset[str], bool]]] = {
        "viewer": (frozenset({"Viewer"}), False),
        "engineer": (frozenset({"Engineer"}), False),
        "approver": (frozenset({"Approver"}), False),
        "pack_author": (frozenset({"PackAuthor"}), False),
        "admin": (frozenset({"Admin"}), False),
        "auditor": (frozenset({"Auditor"}), False),
        "evaluator_service": (frozenset({"EvaluatorService"}), True),
    }
    CAPABILITIES: ClassVar[Mapping[str, str]] = {
        "viewer": "viewer",
        "engineer": "engineer",
        "approver": "approver",
        "pack_author": "pack-author",
        "admin": "admin",
        "auditor": "auditor",
        "evaluator_service": "evaluator-service",
    }
    ALLOWED_CAPABILITIES: ClassVar[Mapping[str, frozenset[str]]] = {
        "viewer": frozenset({"viewer"}),
        "engineer": frozenset({"viewer", "engineer"}),
        "approver": frozenset({"viewer", "approver"}),
        "pack_author": frozenset({"viewer", "pack_author"}),
        "admin": frozenset({"viewer", "admin"}),
        "auditor": frozenset({"viewer", "auditor"}),
        "evaluator_service": frozenset({"evaluator_service"}),
    }
    BROWSER_CHECKS: ClassVar[frozenset[str]] = frozenset(
        {
            "authorization_code",
            "pkce_s256",
            "token_exchange",
            "id_token_verified",
            "access_token_api",
            "logout",
            "no_cross_origin_redirect",
        }
    )

    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str,
        api_base_url: str,
        *,
        client_id: str | None = None,
        authorization_url: str | None = None,
        token_url: str | None = None,
        end_session_url: str | None = None,
        web_base_url: str | None = None,
        service_client_ids: tuple[str, ...] = (),
        algorithms: tuple[str, ...] = ("RS256",),
        http_get: HttpGet = _http_get,
        validator: OidcValidator | None = None,
    ) -> None:
        self.issuer = _https_url(issuer, "issuer")
        self.jwks_url = _https_url(jwks_url, "JWKS URL")
        self.api_base_url = _https_url(api_base_url, "API base URL")
        self.web_base_url = _https_url(web_base_url or api_base_url, "Web base URL")
        if not authorization_url or not token_url or not end_session_url:
            raise DomainError(
                "OIDC_PROBE_ENDPOINTS_REQUIRED",
                "authorization, token, and end-session endpoints are required",
            )
        self.authorization_url = _https_url(authorization_url, "authorization endpoint")
        self.token_url = _https_url(token_url, "token endpoint")
        self.end_session_url = _https_url(end_session_url, "end-session endpoint")
        self.audience = audience
        if (
            not audience.strip()
            or audience == client_id
            or self.issuer != issuer
            or self.jwks_url != jwks_url
            or self.api_base_url != api_base_url
            or self.web_base_url != (web_base_url or api_base_url)
            or not service_client_ids
            or len(service_client_ids) != len(set(service_client_ids))
            or any(not item.strip() for item in service_client_ids)
            or client_id in service_client_ids
        ):
            raise DomainError(
                "OIDC_PROBE_CLIENT_POLICY_INVALID",
                "OIDC endpoints, API audience, and one evaluator service client must be exact",
            )
        self.http_get = http_get
        if validator is None and not client_id:
            raise DomainError(
                "OIDC_PROBE_CLIENT_INVALID",
                "the authorized OIDC human client ID is required",
            )
        if not client_id:
            raise DomainError("OIDC_PROBE_CLIENT_INVALID", "OIDC client ID is required")
        self.client_id = client_id
        self.algorithms = tuple(algorithms)
        if not self.algorithms:
            raise DomainError("OIDC_PROBE_ALGORITHMS_INVALID", "OIDC algorithms are required")
        self.validator = validator or OidcValidator(
            self.issuer,
            audience,
            self.jwks_url,
            client_id or "",
            service_client_ids=service_client_ids,
            algorithms=algorithms,
        )

    def run(
        self,
        persona_tokens: Mapping[str, str],
        *,
        browser_journey: Mapping[str, Any] | None = None,
    ) -> GateEvidence:
        started = utc_now()
        if set(persona_tokens) != set(self.REQUIRED_IDENTITIES) or any(
            not value.strip() for value in persona_tokens.values()
        ):
            raise DomainError(
                "OIDC_PROBE_PERSONAS_REQUIRED",
                "six human personas and one evaluator service bearer value are required",
            )
        discovery_url = self.issuer + "/.well-known/openid-configuration"
        discovery_status, discovery = self.http_get(discovery_url, {})
        jwks_status, jwks = self.http_get(self.jwks_url, {})
        keys = jwks.get("keys", ())
        supported_algorithms = discovery.get("id_token_signing_alg_values_supported", ())
        code_challenge_methods = discovery.get("code_challenge_methods_supported", ())
        grant_types = discovery.get("grant_types_supported", ())
        response_types = discovery.get("response_types_supported", ())
        scopes = discovery.get("scopes_supported", ())
        token_auth_methods = discovery.get("token_endpoint_auth_methods_supported", ())
        checks: list[GateCheck] = [
            GateCheck("discovery_https", discovery_status == 200),
            GateCheck("discovery_issuer", discovery.get("issuer") == self.issuer),
            GateCheck("discovery_jwks", discovery.get("jwks_uri") == self.jwks_url),
            GateCheck(
                "discovery_endpoints",
                discovery.get("authorization_endpoint") == self.authorization_url
                and discovery.get("token_endpoint") == self.token_url
                and discovery.get("end_session_endpoint") == self.end_session_url,
            ),
            GateCheck(
                "authorization_code_pkce",
                isinstance(code_challenge_methods, list)
                and set(code_challenge_methods) == {"S256"}
                and isinstance(grant_types, list)
                and "authorization_code" in grant_types
                and isinstance(response_types, list)
                and "code" in response_types
                and isinstance(scopes, list)
                and "openid" in scopes
                and isinstance(token_auth_methods, list)
                and "none" in token_auth_methods,
            ),
            GateCheck(
                "discovery_algorithms",
                isinstance(supported_algorithms, list)
                and set(self.algorithms).issubset(supported_algorithms)
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
        actors: dict[str, Any] = {}
        for identity, (expected_roles, expected_service) in self.REQUIRED_IDENTITIES.items():
            actor = self.validator.validate("Bearer " + persona_tokens[identity])
            actors[identity] = actor
            checks.append(
                GateCheck(
                    f"{identity}_claims",
                    bool(actor.actor_id and actor.tenant_id and actor.workspace_id)
                    and actor.roles == expected_roles
                    and actor.service is expected_service,
                    {"role_count": len(actor.roles), "service_identity": actor.service},
                )
            )
            me_status, me = self.http_get(
                urljoin(self.api_base_url + "/", "api/v1/me"),
                {"Authorization": "Bearer " + persona_tokens[identity]},
            )
            checks.append(
                GateCheck(
                    f"{identity}_server_identity",
                    me_status == 200
                    and me.get("actor_id") == actor.actor_id
                    and me.get("tenant_id") == actor.tenant_id
                    and me.get("workspace_id") == actor.workspace_id
                    and set(me.get("roles", ())) == set(expected_roles)
                    and me.get("service") is expected_service,
                )
            )
            for capability_identity, capability in self.CAPABILITIES.items():
                status, response = self.http_get(
                    urljoin(
                        self.api_base_url + "/",
                        f"api/v1/authorization-probe/{capability}",
                    ),
                    {"Authorization": "Bearer " + persona_tokens[identity]},
                )
                allowed = capability_identity in self.ALLOWED_CAPABILITIES[identity]
                checks.append(
                    GateCheck(
                        f"{identity}_to_{capability_identity}",
                        (status == 200 and response.get("authorized") is True)
                        if allowed
                        else status == 403,
                    )
                )
        tenant_scope = {(actor.tenant_id, actor.workspace_id) for actor in actors.values()}
        checks.append(GateCheck("identity_scope_consistency", len(tenant_scope) == 1))
        checks.append(
            GateCheck(
                "identity_subjects_distinct",
                len({actor.actor_id for actor in actors.values()}) == len(actors),
            )
        )

        admin_path = urljoin(self.api_base_url + "/", "api/v1/authorization-probe/admin")
        viewer_status, _ = self.http_get(
            admin_path,
            {
                "Authorization": "Bearer " + persona_tokens["viewer"],
                "X-Actor-Id": "forged-admin",
                "X-Roles": "Admin",
            },
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
                GateCheck("admin_authorized", admin_status == 200),
                GateCheck("anonymous_denied", anonymous_status == 401),
                GateCheck("invalid_token_denied", invalid_status == 401),
            )
        )
        checks.extend(self._browser_checks(browser_journey))
        return complete(
            "oidc",
            started_at=started,
            coordinates={
                "issuer": self.issuer,
                "audience_digest": hashlib.sha256(self.audience.encode()).hexdigest(),
                "client_id_digest": hashlib.sha256(self.client_id.encode()).hexdigest(),
                "browser_journey_digest": canonical_browser_digest(browser_journey),
                "api_origin": f"{urlsplit(self.api_base_url).scheme}://{urlsplit(self.api_base_url).netloc}",
            },
            checks=checks,
            metrics={
                "human_personas": 6,
                "service_identities": 1,
                "authorization_matrix_checks": len(actors) * len(self.CAPABILITIES),
                "discovery_status": discovery_status,
            },
        )

    def _browser_checks(self, journey: Mapping[str, Any] | None) -> list[GateCheck]:
        if journey is None or set(journey) != {
            "schema_version",
            "started_at",
            "completed_at",
            "web_origin",
            "issuer",
            "client_id_digest",
            "personas",
            "checks",
        }:
            return [GateCheck("browser_pkce_journey", False)]
        try:
            started = dt.datetime.fromisoformat(str(journey["started_at"]))
            completed = dt.datetime.fromisoformat(str(journey["completed_at"]))
        except (ValueError, TypeError):
            return [GateCheck("browser_pkce_journey", False)]
        values = journey.get("checks")
        personas = journey.get("personas")
        expected_origin = (
            f"{urlsplit(self.web_base_url).scheme}://{urlsplit(self.web_base_url).netloc}"
        )
        valid = (
            journey.get("schema_version") == 1
            and started.tzinfo is not None
            and completed.tzinfo is not None
            and started <= completed
            and (dt.datetime.now(dt.UTC) - completed.astimezone(dt.UTC)).total_seconds() <= 4 * 3600
            and journey.get("web_origin") == expected_origin
            and journey.get("issuer") == self.issuer
            and journey.get("client_id_digest")
            == hashlib.sha256(self.client_id.encode()).hexdigest()
            and isinstance(personas, list)
            and set(personas) == set(self.REQUIRED_IDENTITIES).difference({"evaluator_service"})
            and isinstance(values, Mapping)
            and set(values) == self.BROWSER_CHECKS
            and all(value is True for value in values.values())
        )
        return [GateCheck("browser_pkce_journey", valid)]


def canonical_browser_digest(journey: Mapping[str, Any] | None) -> str:
    from shadow_sandbox.common.models import canonical_digest

    return canonical_digest(journey or {"status": "missing"})
