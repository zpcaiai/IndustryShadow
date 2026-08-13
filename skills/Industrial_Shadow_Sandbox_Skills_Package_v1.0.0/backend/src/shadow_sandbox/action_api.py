from __future__ import annotations

import hmac
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from shadow_sandbox.actions import ActionRequest
from shadow_sandbox.actions.remote import RemoteActionExecutor, SimulatorServiceClient
from shadow_sandbox.approvals import ApprovalService
from shadow_sandbox.common import DomainError
from shadow_sandbox.common.config import Settings
from shadow_sandbox.common.db import open_store
from shadow_sandbox.common.tenant_scope import workspace_scope
from shadow_sandbox.observability.bootstrap import instrument_application


def create_app() -> Any:
    """Create the isolated simulator-action service.

    This service exposes no user API and has no route capable of addressing a real
    endpoint. Its simulator base URL is immutable process configuration.
    """
    try:
        from fastapi import FastAPI, Header, Request
        from fastapi.responses import JSONResponse
    except ImportError as exc:
        raise DomainError(
            "FASTAPI_DEPENDENCY_UNAVAILABLE", "FastAPI is required", status=503
        ) from exc

    settings = Settings.from_environment()
    settings.validate_action_plane()
    token = settings.internal_service_token or ""
    store = open_store(
        settings.database_url,
        Path(__file__).resolve().parents[3] / "migrations",
        migrate=settings.auto_migrate,
    )
    simulator = SimulatorServiceClient(
        settings.simulator_url or "",
        token,
        settings.simulator_id,
    )
    executor = RemoteActionExecutor(
        store,
        ApprovalService(store),
        simulator,
        settings.simulator_digest or "",
    )

    @asynccontextmanager
    async def lifespan(_app: Any) -> AsyncIterator[None]:
        try:
            yield
        finally:
            store.close()

    app = FastAPI(
        title="Industrial Shadow Isolated Action Executor",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.exception_handler(DomainError)
    async def domain_error(request: Request, error: DomainError) -> JSONResponse:
        return JSONResponse(
            status_code=error.status,
            content=error.problem(str(request.url.path)),
            media_type="application/problem+json",
        )

    def authenticate(provided: str | None) -> None:
        if not provided or not hmac.compare_digest(provided, token):
            raise DomainError("INTERNAL_AUTH_FAILED", "internal authentication failed", status=401)

    @app.get("/internal/v1/health")
    def health(
        x_internal_token: str | None = Header(default=None, alias="X-Internal-Token"),
    ) -> dict[str, Any]:
        authenticate(x_internal_token)
        identity = simulator.identity()
        return {
            "status": "ready",
            "environment_type": "simulator-action-plane",
            "simulator_identity_digest": identity.get("identity_digest"),
        }

    @app.post("/internal/v1/actions")
    def execute(
        body: dict[str, Any],
        x_internal_token: str | None = Header(default=None, alias="X-Internal-Token"),
    ) -> dict[str, Any]:
        authenticate(x_internal_token)
        if set(body) != {"workspace_id", "request"} or not isinstance(body["request"], dict):
            raise DomainError("ACTION_REQUEST_INVALID", "unexpected action envelope")
        request_data = body["request"]
        if set(request_data) != set(ActionRequest.__dataclass_fields__):
            raise DomainError(
                "ACTION_REQUEST_INVALID", "action request fields do not match contract"
            )
        request = ActionRequest(**request_data)
        workspace_id = str(body["workspace_id"])
        with workspace_scope(workspace_id):
            result = executor.execute(request, workspace_id, lambda _engine: ("UNCHANGED", ()))
        return asdict(result)

    app.state.executor = executor
    app.state.store = store
    return instrument_application(app)
