from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from shadow_sandbox import __version__
from shadow_sandbox.api import create_api_router
from shadow_sandbox.application import ApplicationService
from shadow_sandbox.common import DomainError
from shadow_sandbox.common.config import Settings
from shadow_sandbox.common.db import open_store
from shadow_sandbox.common.tenant_scope import workspace_scope
from shadow_sandbox.observability import instrument_application


def create_app(database_path: str | None = None) -> Any:
    """Create the optional FastAPI adapter without coupling the domain core to FastAPI."""
    try:
        from fastapi import FastAPI, Request
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import JSONResponse
    except ImportError as exc:
        raise DomainError(
            "FASTAPI_DEPENDENCY_UNAVAILABLE",
            "install backend dependencies to start the HTTP API",
            status=503,
        ) from exc

    migration_directory = Path(__file__).resolve().parents[3] / "migrations"
    settings = Settings.from_environment()
    if database_path is None:
        settings.validate_control_plane()
        database = settings.database_url
    else:
        database = database_path
    store = open_store(database, migration_directory, migrate=settings.auto_migrate)
    action_executor = None
    if settings.action_service_url and settings.internal_service_token:
        from shadow_sandbox.actions.remote import ActionServiceClient

        action_executor = ActionServiceClient(
            settings.action_service_url,
            settings.internal_service_token,
        )
    application = ApplicationService(
        store,
        import_directory=settings.import_directory,
        action_executor=action_executor,
        build_digest=settings.build_digest,
    )

    @asynccontextmanager
    async def lifespan(_app: Any) -> AsyncIterator[None]:
        try:
            yield
        finally:
            store.close()

    app = FastAPI(
        title="Industrial Shadow Sandbox",
        version=__version__,
        description="Read-only industrial diagnosis validation and simulation-only recovery",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=[
            "Accept",
            "Content-Type",
            "Authorization",
            "Idempotency-Key",
            "If-Match",
            "X-Actor-Id",
            "X-Tenant-Id",
            "X-Workspace-Id",
            "X-Roles",
            "X-Service-Identity",
        ],
    )

    if settings.environment == "production":
        from starlette.middleware.base import BaseHTTPMiddleware

        from shadow_sandbox.security.oidc import OidcValidator

        validator = OidcValidator(
            settings.oidc_issuer or "",
            settings.oidc_audience or "",
            settings.oidc_jwks_url or "",
        )

        class OidcIdentityMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: Request, call_next: Any) -> Any:
                if request.url.path in {
                    "/api/v1/health/live",
                    "/api/v1/health/ready",
                    "/api/v1/version",
                    "/api/v1/auth/config",
                    "/internal/metrics",
                }:
                    return await call_next(request)
                try:
                    authorization = next(
                        (
                            value.decode("latin-1")
                            for key, value in request.scope["headers"]
                            if key == b"authorization"
                        ),
                        None,
                    )
                    actor = validator.validate(authorization)
                except DomainError as error:
                    return JSONResponse(
                        error.problem(str(request.url.path)),
                        status_code=error.status,
                        media_type="application/problem+json",
                    )
                replacements = {
                    b"x-actor-id": actor.actor_id.encode(),
                    b"x-tenant-id": actor.tenant_id.encode(),
                    b"x-workspace-id": actor.workspace_id.encode(),
                    b"x-roles": ",".join(sorted(actor.roles)).encode(),
                    b"x-service-identity": str(actor.service).lower().encode(),
                }
                headers = [
                    (key, value)
                    for key, value in request.scope["headers"]
                    if key not in replacements
                ]
                request.scope["headers"] = headers + list(replacements.items())
                with workspace_scope(actor.workspace_id):
                    return await call_next(request)

        app.add_middleware(OidcIdentityMiddleware)

    @app.exception_handler(DomainError)
    async def domain_error(request: Request, error: DomainError) -> JSONResponse:
        return JSONResponse(
            status_code=error.status,
            content=error.problem(str(request.url.path)),
            media_type="application/problem+json",
        )

    app.include_router(
        create_api_router(application, public_auth_config=settings.public_auth_config())
    )

    app.state.store = store
    app.state.application = application
    return instrument_application(app)


def export_openapi(database_path: str = ":memory:") -> dict[str, Any]:
    return create_app(database_path).openapi()
