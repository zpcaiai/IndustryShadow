from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict
from typing import Any

from shadow_sandbox.application import ApplicationService
from shadow_sandbox.common import ActorContext, DomainError
from shadow_sandbox.security import authorize

API_ROUTE_CONTRACT: tuple[tuple[str, str], ...] = (
    ("GET", "/api/v1/health/live"),
    ("GET", "/api/v1/health/ready"),
    ("GET", "/api/v1/version"),
    ("GET", "/api/v1/auth/config"),
    ("GET", "/api/v1/me"),
    ("GET", "/api/v1/permissions"),
    ("GET", "/api/v1/authorization-probe/{capability}"),
    ("POST", "/api/v1/asset-models"),
    ("GET", "/api/v1/asset-models/{model_id}"),
    ("PATCH", "/api/v1/asset-models/{model_id}"),
    ("POST", "/api/v1/asset-models/{model_id}/validate"),
    ("POST", "/api/v1/asset-models/{model_id}/publish"),
    ("GET", "/api/v1/asset-model-versions/{version_id}"),
    ("GET", "/api/v1/asset-model-versions/{version_id}/topology"),
    ("POST", "/api/v1/scenarios"),
    ("GET", "/api/v1/scenarios/{scenario_id}"),
    ("PATCH", "/api/v1/scenarios/{scenario_id}"),
    ("POST", "/api/v1/scenarios/{scenario_id}/validate"),
    ("POST", "/api/v1/scenarios/{scenario_id}/preview"),
    ("POST", "/api/v1/scenarios/{scenario_id}/publish"),
    ("GET", "/api/v1/scenario-versions/{version_id}"),
    ("POST", "/api/v1/scenario-suites/{suite_id}/validate"),
    ("POST", "/api/v1/scenario-suites/{suite_id}/publish"),
    ("POST", "/api/v1/scenario-suites/{suite_id}/expand"),
    ("POST", "/api/v1/runs"),
    ("GET", "/api/v1/runs/{run_id}"),
    ("GET", "/api/v1/runs/{run_id}/timeline"),
    ("GET", "/api/v1/runs/{run_id}/tasks"),
    ("POST", "/api/v1/runs/{run_id}/pause"),
    ("POST", "/api/v1/runs/{run_id}/resume"),
    ("POST", "/api/v1/runs/{run_id}/cancel"),
    ("POST", "/api/v1/runs/{run_id}/retry"),
    ("GET", "/api/v1/runs/{run_id}/signals/{signal_key}/events"),
    ("POST", "/api/v1/runs/{run_id}/exports/parquet"),
    ("GET", "/api/v1/connectors/{connector_id}/health"),
    ("POST", "/api/v1/runs/{run_id}/quality-and-detect"),
    ("GET", "/api/v1/runs/{run_id}/quality"),
    ("GET", "/api/v1/runs/{run_id}/anomalies"),
    ("POST", "/api/v1/runs/{run_id}/residuals-and-consistency"),
    ("GET", "/api/v1/runs/{run_id}/residuals"),
    ("GET", "/api/v1/runs/{run_id}/consistency-observations"),
    ("POST", "/api/v1/runs/{run_id}/materialize-evidence"),
    ("GET", "/api/v1/runs/{run_id}/evidence"),
    ("GET", "/api/v1/evidence/{evidence_id}"),
    ("GET", "/api/v1/runs/{run_id}/symptoms"),
    ("GET", "/api/v1/runs/{run_id}/evidence-timeline"),
    ("POST", "/api/v1/runs/{run_id}/hypotheses"),
    ("GET", "/api/v1/runs/{run_id}/hypotheses"),
    ("GET", "/api/v1/runs/{run_id}/causal-subgraph"),
    ("POST", "/api/v1/runs/{run_id}/check-plans"),
    ("GET", "/api/v1/runs/{run_id}/check-plan"),
    ("POST", "/api/v1/check-plans/{plan_id}/reorder-preview"),
    ("POST", "/api/v1/approval-requests"),
    ("GET", "/api/v1/approvals/inbox"),
    ("GET", "/api/v1/approvals/{approval_id}"),
    ("POST", "/api/v1/approvals/{approval_id}/decide"),
    ("POST", "/api/v1/approvals/{approval_id}/transfer"),
    ("POST", "/api/v1/approvals/{approval_id}/revoke"),
    ("POST", "/api/v1/actions"),
    ("GET", "/api/v1/actions/{action_id}"),
    ("GET", "/api/v1/runs/{run_id}/actions"),
    ("POST", "/api/v1/runs/{run_id}/replays"),
    ("GET", "/api/v1/replays/{resource_id}"),
    ("POST", "/api/v1/experiments"),
    ("GET", "/api/v1/experiments/{resource_id}"),
    ("GET", "/api/v1/experiments/{resource_id}/comparison"),
    ("GET", "/api/v1/experiments/{resource_id}/episodes"),
    ("POST", "/api/v1/evaluations"),
    ("GET", "/api/v1/evaluations/{resource_id}"),
    ("GET", "/api/v1/evaluations/{resource_id}/slices"),
    ("GET", "/api/v1/evaluations/{resource_id}/episodes"),
    ("POST", "/api/v1/release-gates/evaluate"),
    ("POST", "/api/v1/release-gates/{gate_id}/promote"),
    ("POST", "/api/v1/reports"),
    ("GET", "/api/v1/reports/{report_id}"),
    ("POST", "/api/v1/import-sources"),
    ("POST", "/api/v1/import-sources/profile"),
    ("POST", "/api/v1/mappings/validate"),
    ("POST", "/api/v1/import-jobs"),
    ("GET", "/api/v1/import-jobs/{resource_id}"),
    ("GET", "/api/v1/datasets/{resource_id}"),
    ("POST", "/api/v1/edge-gateways/register"),
    ("POST", "/api/v1/edge-gateways/rotate"),
    ("POST", "/api/v1/edge-gateways/event-batches"),
    ("POST", "/api/v1/edge-gateways/heartbeats"),
    ("GET", "/api/v1/edge-gateways/{gateway_id}/health"),
    ("GET", "/api/v1/admin/system-health"),
    ("GET", "/api/v1/admin/quotas"),
    ("GET", "/api/v1/admin/version-registry"),
    ("GET", "/api/v1/audit-records"),
)


def _etag(value: str | None) -> int:
    if value is None:
        raise DomainError("PRECONDITION_REQUIRED", "If-Match is required", status=428)
    try:
        return int(value.strip('W/"'))
    except ValueError as exc:
        raise DomainError(
            "PRECONDITION_INVALID", "If-Match must contain a resource version"
        ) from exc


def create_api_router(
    application: ApplicationService,
    *,
    public_auth_config: dict[str, object] | None = None,
) -> Any:
    """Build the complete `/api/v1` adapter while keeping FastAPI optional."""
    try:
        from fastapi import APIRouter, Header, Query
        from fastapi.responses import Response
    except ImportError as exc:
        raise DomainError(
            "FASTAPI_DEPENDENCY_UNAVAILABLE", "FastAPI is required for HTTP serving", status=503
        ) from exc

    router = APIRouter(prefix="/api/v1")

    def context(
        actor_id: str,
        tenant_id: str,
        workspace_id: str,
        roles: str,
        service: str = "false",
    ) -> ActorContext:
        return ActorContext(
            actor_id,
            tenant_id,
            workspace_id,
            frozenset(item.strip() for item in roles.split(",") if item.strip()),
            service.lower() == "true",
        )

    def actor_from_headers(
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
        x_service_identity: str = Header(default="false"),
    ) -> ActorContext:
        return context(x_actor_id, x_tenant_id, x_workspace_id, x_roles, x_service_identity)

    def register(method: str, path: str, endpoint: Callable[..., Any], **kwargs: Any) -> None:
        router.add_api_route(path, endpoint, methods=[method], **kwargs)

    # Foundation and identity
    register("GET", "/health/live", lambda: {"status": "live"}, tags=["health"])

    def ready() -> Any:
        from shadow_sandbox.admin import database_probe

        result = database_probe(application.store)
        if result["status"] != "ready":
            return Response(
                json.dumps(
                    DomainError(
                        "MIGRATION_DRIFT", "database is not at expected head", result, 503
                    ).problem()
                ),
                status_code=503,
                media_type="application/problem+json",
            )
        return result

    register("GET", "/health/ready", ready, tags=["health"])
    register("GET", "/version", application.version, tags=["health"])
    register(
        "GET",
        "/auth/config",
        lambda: public_auth_config or {"mode": "development"},
        tags=["identity"],
    )

    def me(
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
        x_service_identity: str = Header(default="false"),
    ) -> dict[str, Any]:
        return application.me(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles, x_service_identity)
        )

    register("GET", "/me", me, tags=["identity"])
    register("GET", "/permissions", me, tags=["identity"])

    authorization_probe_permissions = {
        "viewer": "run:view",
        "engineer": "run:create",
        "approver": "approval:decide",
        "pack-author": "pack:edit",
        "admin": "admin:manage",
        "auditor": "audit:view",
        "evaluator-service": "evaluation:execute",
    }

    def authorization_probe(
        capability: str,
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
        x_service_identity: str = Header(default="false"),
    ) -> dict[str, object]:
        permission = authorization_probe_permissions.get(capability)
        if permission is None:
            raise DomainError("AUTHORIZATION_PROBE_UNKNOWN", "unknown capability", status=404)
        actor = context(
            x_actor_id,
            x_tenant_id,
            x_workspace_id,
            x_roles,
            x_service_identity,
        )
        authorize(actor, permission)
        return {
            "authorized": True,
            "capability": capability,
            "service_identity": actor.service,
        }

    register(
        "GET",
        "/authorization-probe/{capability}",
        authorization_probe,
        tags=["identity"],
    )

    # Asset models
    def create_asset(
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.create_asset_model(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), body
        )

    def get_asset(
        model_id: str,
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> dict[str, Any]:
        return application.resources.get(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), "asset_model_draft", model_id
        ).as_dict()

    def patch_asset(
        model_id: str,
        body: dict[str, Any],
        if_match: str | None = Header(default=None, alias="If-Match"),
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.update_asset_model(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
            model_id,
            body,
            _etag(if_match),
        )

    def validate_asset_route(
        model_id: str,
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.validate_asset_model(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), model_id
        )

    def publish_asset_route(
        model_id: str,
        x_actor_id: str = Header(default="dev-author"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="PackAuthor"),
    ) -> dict[str, Any]:
        return application.publish_asset_model(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), model_id
        )

    def get_asset_version(
        version_id: str,
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> dict[str, Any]:
        return application.resources.get(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
            "asset_model_version",
            version_id,
        ).as_dict()

    def get_topology(
        version_id: str,
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> dict[str, Any]:
        return application.asset_topology(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), version_id
        )

    register("POST", "/asset-models", create_asset, status_code=201, tags=["assets"])
    register("GET", "/asset-models/{model_id}", get_asset, tags=["assets"])
    register("PATCH", "/asset-models/{model_id}", patch_asset, tags=["assets"])
    register("POST", "/asset-models/{model_id}/validate", validate_asset_route, tags=["assets"])
    register("POST", "/asset-models/{model_id}/publish", publish_asset_route, tags=["assets"])
    register("GET", "/asset-model-versions/{version_id}", get_asset_version, tags=["assets"])
    register("GET", "/asset-model-versions/{version_id}/topology", get_topology, tags=["assets"])

    # Scenarios and suites
    def create_scenario_route(
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.create_scenario(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), body
        )

    def get_scenario(
        scenario_id: str,
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> dict[str, Any]:
        return application.resources.get(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), "scenario_draft", scenario_id
        ).as_dict()

    def patch_scenario(
        scenario_id: str,
        body: dict[str, Any],
        if_match: str | None = Header(default=None, alias="If-Match"),
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.update_scenario(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
            scenario_id,
            body,
            _etag(if_match),
        )

    def validate_scenario_route(
        scenario_id: str,
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.validate_scenario(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
            scenario_id,
            body.get("signal_keys", ()),
        )

    def preview_scenario_route(
        scenario_id: str,
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.preview_scenario(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), scenario_id
        )

    def publish_scenario_route(
        scenario_id: str,
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-author"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="PackAuthor"),
    ) -> dict[str, Any]:
        return application.publish_scenario(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
            scenario_id,
            body.get("signal_keys", ()),
        )

    def get_scenario_version(
        version_id: str,
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> dict[str, Any]:
        return application.resources.get(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
            "scenario_version",
            version_id,
        ).as_dict()

    def validate_suite(
        suite_id: str,
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        expected = int(body.get("expected_episode_count", 0))
        return {
            "valid": expected > 0,
            "errors": [] if expected > 0 else [{"code": "EXPECTED_COUNT_REQUIRED"}],
        }

    def publish_suite(
        suite_id: str,
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-author"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="PackAuthor"),
    ) -> dict[str, Any]:
        return application.put_scenario_suite(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), suite_id, body, publish=True
        )

    def expand_suite(
        suite_id: str,
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.expand_scenario_suite(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), suite_id
        )

    register("POST", "/scenarios", create_scenario_route, status_code=201, tags=["scenarios"])
    register("GET", "/scenarios/{scenario_id}", get_scenario, tags=["scenarios"])
    register("PATCH", "/scenarios/{scenario_id}", patch_scenario, tags=["scenarios"])
    register(
        "POST", "/scenarios/{scenario_id}/validate", validate_scenario_route, tags=["scenarios"]
    )
    register("POST", "/scenarios/{scenario_id}/preview", preview_scenario_route, tags=["scenarios"])
    register("POST", "/scenarios/{scenario_id}/publish", publish_scenario_route, tags=["scenarios"])
    register("GET", "/scenario-versions/{version_id}", get_scenario_version, tags=["scenarios"])
    register("POST", "/scenario-suites/{suite_id}/validate", validate_suite, tags=["suites"])
    register("POST", "/scenario-suites/{suite_id}/publish", publish_suite, tags=["suites"])
    register("POST", "/scenario-suites/{suite_id}/expand", expand_suite, tags=["suites"])

    # Runs
    def create_run_route(
        body: dict[str, Any],
        idempotency_key: str = Header(alias="Idempotency-Key"),
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.create_run(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), body, idempotency_key
        )

    def get_run(
        run_id: str,
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> dict[str, Any]:
        return application.runs.get(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), run_id
        )

    def timeline(
        run_id: str,
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> list[dict[str, Any]]:
        return application.runs.timeline(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), run_id
        )

    def tasks(
        run_id: str,
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> list[dict[str, Any]]:
        return application.run_tasks(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), run_id
        )

    def command_handler(command: str) -> Callable[..., Any]:
        def handler(
            run_id: str,
            body: dict[str, Any],
            x_actor_id: str = Header(default="dev-engineer"),
            x_tenant_id: str = Header(default="dev-tenant"),
            x_workspace_id: str = Header(default="dev-workspace"),
            x_roles: str = Header(default="Engineer"),
        ) -> dict[str, Any]:
            return application.command_run(
                context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
                run_id,
                command,
                str(body.get("reason", command)),
            )

        handler.__name__ = f"{command}_run"
        return handler

    register("POST", "/runs", create_run_route, status_code=201, tags=["runs"])
    register("GET", "/runs/{run_id}", get_run, tags=["runs"])
    register("GET", "/runs/{run_id}/timeline", timeline, tags=["runs"])
    register("GET", "/runs/{run_id}/tasks", tasks, tags=["runs"])
    for run_command in ("pause", "resume", "cancel", "retry"):
        register(
            "POST", f"/runs/{{run_id}}/{run_command}", command_handler(run_command), tags=["runs"]
        )

    def signal_events(
        run_id: str,
        signal_key: str,
        start: str | None = Query(default=None, alias="from"),
        end: str | None = Query(default=None, alias="to"),
        limit: int = Query(default=1000, ge=1, le=10000),
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> list[dict[str, Any]]:
        return application.signal_events(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
            run_id,
            signal_key,
            start,
            end,
            limit,
        )

    def export_run(
        run_id: str,
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.export_events(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), run_id
        )

    def connector_health(
        connector_id: str,
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> dict[str, Any]:
        return application.connector_health(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), connector_id
        )

    register("GET", "/runs/{run_id}/signals/{signal_key}/events", signal_events, tags=["ingestion"])
    register("POST", "/runs/{run_id}/exports/parquet", export_run, tags=["ingestion"])
    register("GET", "/connectors/{connector_id}/health", connector_health, tags=["ingestion"])

    # Diagnosis stage command/query endpoints
    def stage_command(
        kind: str, method: Callable[[ActorContext, str, dict[str, Any]], dict[str, Any]]
    ) -> Callable[..., Any]:
        def handler(
            run_id: str,
            body: dict[str, Any],
            x_actor_id: str = Header(default="dev-engineer"),
            x_tenant_id: str = Header(default="dev-tenant"),
            x_workspace_id: str = Header(default="dev-workspace"),
            x_roles: str = Header(default="Engineer"),
        ) -> dict[str, Any]:
            return method(context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), run_id, body)

        handler.__name__ = f"run_{kind.replace('-', '_')}"
        return handler

    register(
        "POST",
        "/runs/{run_id}/quality-and-detect",
        stage_command("quality_and_detect", application.quality_and_detect),
        tags=["diagnosis"],
    )
    register(
        "POST",
        "/runs/{run_id}/residuals-and-consistency",
        stage_command("residuals", application.residuals_and_consistency),
        tags=["diagnosis"],
    )
    register(
        "POST",
        "/runs/{run_id}/materialize-evidence",
        stage_command("evidence", application.materialize_evidence),
        tags=["diagnosis"],
    )
    register(
        "POST",
        "/runs/{run_id}/hypotheses",
        stage_command("hypotheses", application.generate_hypotheses),
        tags=["diagnosis"],
    )
    register(
        "POST",
        "/runs/{run_id}/check-plans",
        stage_command("check_plans", application.create_check_plan),
        tags=["diagnosis"],
    )

    def product_query(
        resource_type: str, resource_id: Callable[[str], str], field: str | None = None
    ) -> Callable[..., Any]:
        def handler(
            run_id: str,
            x_actor_id: str = Header(default="dev-viewer"),
            x_tenant_id: str = Header(default="dev-tenant"),
            x_workspace_id: str = Header(default="dev-workspace"),
            x_roles: str = Header(default="Viewer"),
        ) -> Any:
            resource = application.resources.get(
                context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
                resource_type,
                resource_id(run_id),
            )
            return resource.payload.get(field) if field else resource.as_dict()

        handler.__name__ = f"get_{resource_type}_{field or 'resource'}"
        return handler

    register(
        "GET",
        "/runs/{run_id}/quality",
        product_query("quality_detection", lambda value: f"quality:{value}", "quality"),
        tags=["diagnosis"],
    )
    register(
        "GET",
        "/runs/{run_id}/anomalies",
        product_query("quality_detection", lambda value: f"quality:{value}", "anomalies"),
        tags=["diagnosis"],
    )
    register(
        "GET",
        "/runs/{run_id}/residuals",
        product_query("residual_set", lambda value: f"residuals:{value}", "residuals"),
        tags=["diagnosis"],
    )
    register(
        "GET",
        "/runs/{run_id}/consistency-observations",
        product_query(
            "residual_set", lambda value: f"residuals:{value}", "consistency_observations"
        ),
        tags=["diagnosis"],
    )
    register(
        "GET",
        "/runs/{run_id}/evidence",
        product_query("evidence_set", lambda value: f"evidence:{value}", "evidence"),
        tags=["diagnosis"],
    )
    register(
        "GET",
        "/runs/{run_id}/symptoms",
        product_query("evidence_set", lambda value: f"evidence:{value}", "symptoms"),
        tags=["diagnosis"],
    )
    register(
        "GET",
        "/runs/{run_id}/evidence-timeline",
        product_query("evidence_set", lambda value: f"evidence:{value}", "evidence"),
        tags=["diagnosis"],
    )
    register(
        "GET",
        "/runs/{run_id}/hypotheses",
        product_query("diagnosis_result", lambda value: f"diagnosis:{value}"),
        tags=["diagnosis"],
    )
    register(
        "GET",
        "/runs/{run_id}/causal-subgraph",
        product_query("diagnosis_result", lambda value: f"diagnosis:{value}", "hypotheses"),
        tags=["diagnosis"],
    )

    def get_evidence_item(
        evidence_id: str,
        run_id: str = Query(),
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> dict[str, Any]:
        resource = application.resources.get(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
            "evidence_set",
            f"evidence:{run_id}",
        )
        for item in resource.payload.get("evidence", ()):
            if item["evidence_id"] == evidence_id:
                return item
        raise DomainError("EVIDENCE_NOT_FOUND", "evidence not found", status=404)

    def get_check_plan(
        run_id: str,
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> dict[str, Any]:
        rows = application.resources.list(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), "check_plan", limit=500
        )["items"]
        matches = [item for item in rows if item["payload"].get("run_id") == run_id]
        if not matches:
            raise DomainError("CHECK_PLAN_NOT_FOUND", "check plan not found", status=404)
        return matches[-1]

    def reorder_plan(
        plan_id: str,
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.reorder_check_plan(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
            plan_id,
            body.get("ordered_step_ids", ()),
        )

    register("GET", "/evidence/{evidence_id}", get_evidence_item, tags=["diagnosis"])
    register("GET", "/runs/{run_id}/check-plan", get_check_plan, tags=["diagnosis"])
    register("POST", "/check-plans/{plan_id}/reorder-preview", reorder_plan, tags=["diagnosis"])

    # Approvals and actions
    def request_approval(
        body: dict[str, Any],
        idempotency_key: str = Header(alias="Idempotency-Key"),
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.request_approval(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
            {**body, "idempotency_key": idempotency_key},
        )

    def inbox(
        x_actor_id: str = Header(default="dev-approver"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Approver"),
    ) -> list[dict[str, Any]]:
        return application.approval_inbox(context(x_actor_id, x_tenant_id, x_workspace_id, x_roles))

    def get_approval(
        approval_id: str,
        x_actor_id: str = Header(default="dev-approver"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Approver"),
    ) -> dict[str, Any]:
        return application.approval(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), approval_id
        )

    def decide(
        approval_id: str,
        body: dict[str, Any],
        if_match: str | None = Header(default=None, alias="If-Match"),
        idempotency_key: str = Header(alias="Idempotency-Key"),
        x_actor_id: str = Header(default="dev-approver"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Approver"),
    ) -> dict[str, Any]:
        return application.decide_approval(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
            approval_id,
            {**body, "idempotency_key": idempotency_key},
            _etag(if_match),
        )

    def transfer(
        approval_id: str,
        body: dict[str, Any],
        if_match: str | None = Header(default=None, alias="If-Match"),
        idempotency_key: str = Header(alias="Idempotency-Key"),
        x_actor_id: str = Header(default="dev-approver"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Approver"),
    ) -> dict[str, Any]:
        actor = context(x_actor_id, x_tenant_id, x_workspace_id, x_roles)
        return asdict(
            application.approvals.transfer(
                actor, approval_id, str(body["target_actor_id"]), _etag(if_match)
            )
        )

    def revoke(
        approval_id: str,
        body: dict[str, Any],
        idempotency_key: str = Header(alias="Idempotency-Key"),
        x_actor_id: str = Header(default="dev-approver"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Approver"),
    ) -> dict[str, Any]:
        application.approvals.revoke(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
            approval_id,
            str(body.get("reason", "revoked")),
        )
        return {"approval_id": approval_id, "state": "REVOKED", "idempotency_key": idempotency_key}

    def execute_action_route(
        body: dict[str, Any],
        idempotency_key: str = Header(alias="Idempotency-Key"),
        x_actor_id: str = Header(default="action-service"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="ActionExecutorService"),
    ) -> dict[str, Any]:
        return application.execute_action(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles, "true"),
            {**body, "idempotency_key": idempotency_key},
        )

    def get_action(
        action_id: str,
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> dict[str, Any]:
        return application.action(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), action_id
        )

    def run_actions(
        run_id: str,
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> list[dict[str, Any]]:
        actor = context(x_actor_id, x_tenant_id, x_workspace_id, x_roles)
        application.runs.get(actor, run_id)
        return [
            application.action(actor, row["action_id"])
            for row in application.store.query(
                "SELECT action_id FROM action_executions WHERE run_id=? ORDER BY created_at",
                (run_id,),
            )
        ]

    register("POST", "/approval-requests", request_approval, tags=["approvals"])
    register("GET", "/approvals/inbox", inbox, tags=["approvals"])
    register("GET", "/approvals/{approval_id}", get_approval, tags=["approvals"])
    register("POST", "/approvals/{approval_id}/decide", decide, tags=["approvals"])
    register("POST", "/approvals/{approval_id}/transfer", transfer, tags=["approvals"])
    register("POST", "/approvals/{approval_id}/revoke", revoke, tags=["approvals"])
    register("POST", "/actions", execute_action_route, tags=["actions"])
    register("GET", "/actions/{action_id}", get_action, tags=["actions"])
    register("GET", "/runs/{run_id}/actions", run_actions, tags=["actions"])

    # Replay, experiments, evaluation, reports
    def replay(
        run_id: str,
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.create_replay(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), run_id, body
        )

    def create_experiment(
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.create_experiment(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), body
        )

    def get_resource(resource_type: str) -> Callable[..., Any]:
        def handler(
            resource_id: str,
            x_actor_id: str = Header(default="dev-viewer"),
            x_tenant_id: str = Header(default="dev-tenant"),
            x_workspace_id: str = Header(default="dev-workspace"),
            x_roles: str = Header(default="Viewer"),
        ) -> dict[str, Any]:
            return application.resources.get(
                context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
                resource_type,
                resource_id,
            ).as_dict()

        handler.__name__ = f"get_{resource_type}"
        return handler

    def evaluation(
        body: dict[str, Any],
        x_actor_id: str = Header(default="evaluator"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="EvaluatorService"),
    ) -> dict[str, Any]:
        return application.create_evaluation(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles, "true"), body
        )

    def gate(
        body: dict[str, Any],
        x_actor_id: str = Header(default="evaluator"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="EvaluatorService"),
    ) -> dict[str, Any]:
        return application.evaluate_release_gate(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles, "true"), body
        )

    def promote(
        gate_id: str,
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-admin"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Admin"),
    ) -> dict[str, Any]:
        return application.promote_release_gate(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), gate_id, body
        )

    def create_report(
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.generate_report(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), body
        )

    def report(
        report_id: str,
        accept: str = Header(default="application/json", alias="Accept"),
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> Any:
        content, media_type = application.render_report(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles),
            report_id,
            accept,
        )
        return Response(content, media_type=media_type)

    register("POST", "/runs/{run_id}/replays", replay, tags=["replay"])
    register("GET", "/replays/{resource_id}", get_resource("replay"), tags=["replay"])
    register("POST", "/experiments", create_experiment, tags=["experiments"])
    register("GET", "/experiments/{resource_id}", get_resource("experiment"), tags=["experiments"])
    register(
        "GET",
        "/experiments/{resource_id}/comparison",
        get_resource("experiment"),
        tags=["experiments"],
    )
    register(
        "GET",
        "/experiments/{resource_id}/episodes",
        get_resource("experiment"),
        tags=["experiments"],
    )
    register("POST", "/evaluations", evaluation, tags=["evaluation"])
    register("GET", "/evaluations/{resource_id}", get_resource("evaluation"), tags=["evaluation"])
    register(
        "GET", "/evaluations/{resource_id}/slices", get_resource("evaluation"), tags=["evaluation"]
    )
    register(
        "GET",
        "/evaluations/{resource_id}/episodes",
        get_resource("evaluation"),
        tags=["evaluation"],
    )
    register("POST", "/release-gates/evaluate", gate, tags=["evaluation"])
    register("POST", "/release-gates/{gate_id}/promote", promote, tags=["evaluation"])
    register("POST", "/reports", create_report, tags=["reports"])
    register("GET", "/reports/{report_id}", report, tags=["reports"])

    # Historical imports
    def import_source(
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.register_import_source(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), body
        )

    def profile_source(
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.profile_import_source(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), str(body["source_id"])
        )

    def validate_mapping(body: dict[str, Any]) -> dict[str, Any]:
        return application.validate_mappings(body.get("mappings", ()))

    def import_job(
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-engineer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Engineer"),
    ) -> dict[str, Any]:
        return application.create_import_job(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), body
        )

    register("POST", "/import-sources", import_source, tags=["imports"])
    register("POST", "/import-sources/profile", profile_source, tags=["imports"])
    register("POST", "/mappings/validate", validate_mapping, tags=["imports"])
    register("POST", "/import-jobs", import_job, tags=["imports"])
    register("GET", "/import-jobs/{resource_id}", get_resource("import_job"), tags=["imports"])
    register("GET", "/datasets/{resource_id}", get_resource("dataset"), tags=["imports"])

    # Edge gateway
    def edge_register(
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-admin"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Admin"),
    ) -> dict[str, Any]:
        return application.register_edge_gateway(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), body
        )

    def edge_rotate(
        body: dict[str, Any],
        x_actor_id: str = Header(default="dev-admin"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Admin"),
    ) -> dict[str, Any]:
        return application.rotate_edge_identity(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), str(body["gateway_id"]), body
        )

    def edge_batch(
        body: dict[str, Any],
        x_actor_id: str = Header(default="edge-service"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="CollectorService"),
    ) -> dict[str, Any]:
        return application.ingest_edge_batch(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles, "true"), body
        )

    def edge_heartbeat(
        body: dict[str, Any],
        x_actor_id: str = Header(default="edge-service"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="CollectorService"),
    ) -> dict[str, Any]:
        return application.edge_heartbeat(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles, "true"), body
        )

    def edge_health(
        gateway_id: str,
        x_actor_id: str = Header(default="dev-viewer"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Viewer"),
    ) -> dict[str, Any]:
        return application.edge_health(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), gateway_id
        )

    register("POST", "/edge-gateways/register", edge_register, tags=["edge"])
    register("POST", "/edge-gateways/rotate", edge_rotate, tags=["edge"])
    register("POST", "/edge-gateways/event-batches", edge_batch, tags=["edge"])
    register("POST", "/edge-gateways/heartbeats", edge_heartbeat, tags=["edge"])
    register("GET", "/edge-gateways/{gateway_id}/health", edge_health, tags=["edge"])

    # Admin and audit
    def system_health(
        x_actor_id: str = Header(default="dev-admin"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Admin"),
    ) -> dict[str, Any]:
        return application.system_health(context(x_actor_id, x_tenant_id, x_workspace_id, x_roles))

    def audit(
        limit: int = Query(default=100, ge=1, le=500),
        x_actor_id: str = Header(default="dev-auditor"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Auditor"),
    ) -> list[dict[str, Any]]:
        return application.audit_records(
            context(x_actor_id, x_tenant_id, x_workspace_id, x_roles), limit
        )

    def admin_quotas(
        x_actor_id: str = Header(default="dev-admin"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Admin"),
    ) -> dict[str, int]:
        actor = context(x_actor_id, x_tenant_id, x_workspace_id, x_roles)
        actor.require_role("Admin", "Auditor")
        return {
            "imports_max_rows": 5_000_000,
            "query_max_rows": 10_000,
            "tool_budget_ms": 10_000,
        }

    def version_registry(
        x_actor_id: str = Header(default="dev-admin"),
        x_tenant_id: str = Header(default="dev-tenant"),
        x_workspace_id: str = Header(default="dev-workspace"),
        x_roles: str = Header(default="Admin"),
    ) -> dict[str, Any]:
        actor = context(x_actor_id, x_tenant_id, x_workspace_id, x_roles)
        actor.require_role("Admin", "Auditor")
        return application.version()

    register("GET", "/admin/system-health", system_health, tags=["admin"])
    register("GET", "/admin/quotas", admin_quotas, tags=["admin"])
    register("GET", "/admin/version-registry", version_registry, tags=["admin"])
    register("GET", "/audit-records", audit, tags=["audit"])
    return router
