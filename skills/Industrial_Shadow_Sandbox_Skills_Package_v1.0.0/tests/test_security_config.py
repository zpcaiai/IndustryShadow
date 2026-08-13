from __future__ import annotations

import tempfile
import unittest
from unittest.mock import MagicMock, patch

import httpx
from shadow_sandbox.api.router import API_ROUTE_CONTRACT
from shadow_sandbox.common import ActorContext, DomainError
from shadow_sandbox.common.config import Settings
from shadow_sandbox.main import create_app
from shadow_sandbox.security.oidc import OidcValidator


def production_environment() -> dict[str, str]:
    return {
        "SHADOW_ENVIRONMENT": "production",
        "SHADOW_DATABASE_URL": "postgresql+psycopg://app@database/shadow?sslmode=require",
        "SHADOW_BUILD_DIGEST": "sha256:" + "a" * 64,
        "SHADOW_ALLOWED_ORIGINS": "https://shadow.corp.internal",
        "SHADOW_OIDC_ISSUER": "https://identity.corp.internal/tenant",
        "SHADOW_OIDC_AUDIENCE": "industrial-shadow",
        "SHADOW_OIDC_JWKS_URL": "https://identity.corp.internal/tenant/keys",
        "SHADOW_OIDC_CLIENT_ID": "industrial-shadow-web",
        "SHADOW_OIDC_AUTHORIZATION_URL": "https://identity.corp.internal/tenant/authorize",
        "SHADOW_OIDC_TOKEN_URL": "https://identity.corp.internal/tenant/token",
        "SHADOW_OIDC_END_SESSION_URL": "https://identity.corp.internal/tenant/logout",
    }


class SecurityConfigurationTests(unittest.IsolatedAsyncioTestCase):
    def test_openapi_is_renderable_and_matches_the_declared_route_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = create_app(f"{directory}/openapi.db")
            schema = app.openapi()
            actual = {
                (method.upper(), path)
                for path, operations in schema["paths"].items()
                for method in operations
                if method.lower() in {"get", "post", "patch", "put", "delete"}
            }
            self.assertEqual(set(API_ROUTE_CONTRACT), actual)
            app.state.store.close()

    def test_production_identity_coordinates_are_fail_closed(self) -> None:
        environment = production_environment()
        environment.pop("SHADOW_OIDC_JWKS_URL")
        with (
            patch.dict("os.environ", environment, clear=True),
            self.assertRaises(DomainError) as caught,
        ):
            Settings.from_environment().validate()
        self.assertEqual("OIDC_CONFIG_REQUIRED", caught.exception.code)

    def test_production_rejects_placeholder_digest_and_database_without_tls(self) -> None:
        for key, value, code in (
            ("SHADOW_BUILD_DIGEST", "sha256:" + "0" * 64, "BUILD_DIGEST_INVALID"),
            (
                "SHADOW_BUILD_DIGEST",
                "replace-with-attested-build-digest",
                "BUILD_DIGEST_INVALID",
            ),
            (
                "SHADOW_DATABASE_URL",
                "postgresql+psycopg://app@database/shadow",
                "POSTGRESQL_TLS_REQUIRED",
            ),
        ):
            environment = production_environment()
            environment[key] = value
            with (
                patch.dict("os.environ", environment, clear=True),
                self.assertRaises(DomainError) as caught,
            ):
                Settings.from_environment().validate()
            self.assertEqual(code, caught.exception.code)

    def test_production_rejects_insecure_identity_and_browser_origins(self) -> None:
        for key, value, code in (
            ("SHADOW_OIDC_ISSUER", "http://identity.invalid", "OIDC_ISSUER_INVALID"),
            ("SHADOW_OIDC_JWKS_URL", "file:///tmp/keys", "OIDC_JWKS_URL_INVALID"),
            ("SHADOW_OIDC_TOKEN_URL", "http://identity.invalid/token", "OIDC_TOKEN_URL_INVALID"),
            ("SHADOW_ALLOWED_ORIGINS", "*", "ALLOWED_ORIGINS_INVALID"),
        ):
            environment = production_environment()
            environment[key] = value
            with (
                patch.dict("os.environ", environment, clear=True),
                self.assertRaises(DomainError) as caught,
            ):
                Settings.from_environment().validate()
            self.assertEqual(code, caught.exception.code)

    async def test_public_oidc_pkce_configuration_contains_no_secret(self) -> None:
        environment = {**production_environment(), "SHADOW_AUTO_MIGRATE": "true"}
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ", environment, clear=True
        ):
            app = create_app(f"{directory}/api.db")
            transport = httpx.ASGITransport(app=app)
            async with app.router.lifespan_context(app), httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                response = await client.get("/api/v1/auth/config")
                self.assertEqual(200, response.status_code)
                value = response.json()
                self.assertEqual("oidc_pkce", value["mode"])
                self.assertEqual("industrial-shadow-web", value["client_id"])
                self.assertNotIn("client_secret", value)
                version = (await client.get("/api/v1/version")).json()
                self.assertEqual("sha256:" + "a" * 64, version["build_digest"])

    @patch("jwt.PyJWKClient")
    def test_oidc_validation_binds_required_scope(self, key_client: MagicMock) -> None:
        key_client.return_value.get_signing_key_from_jwt.return_value.key = "public-key"
        validator = OidcValidator(
            "https://identity.example.invalid/tenant",
            "industrial-shadow",
            "https://identity.example.invalid/tenant/keys",
        )
        validator.jwt.get_unverified_header = MagicMock(
            return_value={"alg": "RS256", "kid": "key-1", "typ": "at+jwt"}
        )
        validator.jwt.decode = MagicMock(
            return_value={
                "sub": "engineer-1",
                "tenant_id": "tenant-1",
                "workspace_id": "workspace-1",
                "roles": ["Engineer", "Viewer"],
            }
        )
        actor = validator.validate("Bearer signed-token")
        self.assertEqual("workspace-1", actor.workspace_id)
        self.assertEqual(frozenset({"Engineer", "Viewer"}), actor.roles)
        validator.jwt.decode.assert_called_once()

        validator.jwt.decode = MagicMock(return_value={"sub": "missing-scope"})
        with self.assertRaises(DomainError) as caught:
            validator.validate("Bearer signed-token")
        self.assertEqual("TOKEN_SCOPE_MISSING", caught.exception.code)

    async def test_production_middleware_overwrites_forged_identity_headers(self) -> None:
        environment = {
            **production_environment(),
            "SHADOW_AUTO_MIGRATE": "true",
        }
        viewer = ActorContext(
            "viewer-1", "tenant-1", "workspace-1", frozenset({"Viewer"})
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict("os.environ", environment, clear=True),
            patch(
                "shadow_sandbox.security.oidc.OidcValidator.validate",
                return_value=viewer,
            ) as validate,
        ):
            app = create_app(f"{directory}/api.db")
            transport = httpx.ASGITransport(app=app)
            async with app.router.lifespan_context(app), httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                public = await client.get("/api/v1/health/live")
                self.assertEqual(200, public.status_code)
                forbidden = await client.get(
                    "/api/v1/admin/quotas",
                    headers={
                        "Authorization": "Bearer signed-token",
                        "X-Actor-Id": "forged-admin",
                        "X-Tenant-Id": "forged-tenant",
                        "X-Workspace-Id": "forged-workspace",
                        "X-Roles": "Admin",
                    },
                )
                self.assertEqual(403, forbidden.status_code)
                self.assertEqual("FORBIDDEN", forbidden.json()["code"])
        validate.assert_called_once_with("Bearer signed-token")


if __name__ == "__main__":
    unittest.main()
