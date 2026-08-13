from __future__ import annotations

import asyncio
import copy
import hmac
import os
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from shadow_sandbox.actions import SimulatorActionAdapter
from shadow_sandbox.asset_registry import pump_tank_model
from shadow_sandbox.common import DomainError, SqliteStore
from shadow_sandbox.common.models import canonical_digest, new_id
from shadow_sandbox.common.object_storage import create_object_storage

from .faults import FaultRuntime, FaultSpec
from .model import OperatingMode, ProcessCommand, ProcessParameters, SimulatorEngine
from .opcua import AsyncUaSimulatorServer, OpcUaServerConfig
from .snapshot import SnapshotService


def _trusted_client_fingerprints(raw: str) -> frozenset[str]:
    values = frozenset(item.strip().lower() for item in raw.split(",") if item.strip())
    if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in values):
        raise DomainError(
            "OPCUA_CLIENT_TRUST_INVALID",
            "trusted client fingerprints must be comma-separated SHA-256 hex values",
            status=503,
        )
    return values


def create_app(database_path: str | None = None) -> Any:
    try:
        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse
    except ImportError as exc:
        raise DomainError(
            "FASTAPI_DEPENDENCY_UNAVAILABLE", "FastAPI is required", status=503
        ) from exc

    database_path = database_path or os.environ.get(
        "SHADOW_DATABASE_PATH", ".runtime/simulator.db"
    )
    environment = os.environ.get("SHADOW_ENVIRONMENT", "development")
    build_digest = os.environ.get("SHADOW_SIMULATOR_BUILD_DIGEST", "dev-build")
    if environment == "production" and (
        not re.fullmatch(r"[a-f0-9]{64}", build_digest) or build_digest == "0" * 64
    ):
        raise DomainError(
            "SIMULATOR_BUILD_DIGEST_INVALID",
            "production simulator requires a non-placeholder SHA-256 build digest",
            status=503,
        )
    storage_backend = os.environ.get("SHADOW_OBJECT_STORAGE_BACKEND", "local")
    if environment == "production" and storage_backend != "s3":
        raise DomainError(
            "PRODUCTION_OBJECT_STORAGE_REQUIRED",
            "production simulator snapshots require S3-compatible object storage",
            status=503,
        )
    if environment == "production" and not os.environ.get(
        "SHADOW_OBJECT_STORAGE_KMS_KEY_ID", ""
    ).startswith("arn:"):
        raise DomainError(
            "PRODUCTION_KMS_KEY_REQUIRED",
            "production simulator snapshots require an explicit KMS key",
            status=503,
        )
    internal_token = os.environ.get("SHADOW_INTERNAL_SERVICE_TOKEN")
    if environment == "production" and (not internal_token or len(internal_token) < 32):
        raise DomainError(
            "INTERNAL_TOKEN_REQUIRED",
            "production simulator requires a strong internal service token",
            status=503,
        )
    storage_root = Path(
        os.environ.get(
            "SHADOW_OBJECT_STORAGE_ROOT", str(Path(database_path).parent / "objects")
        )
    )
    object_storage = create_object_storage(
        storage_backend,
        local_root=storage_root,
        bucket=os.environ.get("SHADOW_OBJECT_STORAGE_BUCKET"),
        region=os.environ.get("SHADOW_OBJECT_STORAGE_REGION"),
        endpoint_url=os.environ.get("SHADOW_OBJECT_STORAGE_ENDPOINT"),
        prefix=os.environ.get(
            "SHADOW_OBJECT_STORAGE_PREFIX", "industrial-shadow/simulator"
        ),
        kms_key_id=os.environ.get("SHADOW_OBJECT_STORAGE_KMS_KEY_ID"),
        kms_encryption_context={
            "application": "industrial-shadow",
            "purpose": "snapshot",
        },
    )
    model = pump_tank_model()
    store = SqliteStore(database_path)
    store.migrate_all(Path(__file__).resolve().parents[4] / "migrations")
    snapshots = SnapshotService(
        store,
        Path(database_path).parent / "snapshots",
        object_storage=object_storage,
    )
    engines: dict[str, SimulatorEngine] = {
        "default": SimulatorEngine(
            asset_model_digest=model.digest,
            simulator_build_digest=build_digest,
            fault_runtime=FaultRuntime(),
        )
    }
    app = FastAPI(title="Industrial Shadow Simulator", version="0.1.0")

    @app.middleware("http")
    async def internal_authentication(request: Request, call_next: Any) -> Any:
        if request.url.path != "/internal/v1/health" and internal_token:
            provided = request.headers.get("x-internal-token", "")
            if not hmac.compare_digest(provided, internal_token):
                return JSONResponse(
                    DomainError(
                        "INTERNAL_AUTH_FAILED",
                        "internal authentication failed",
                        status=401,
                    ).problem(str(request.url.path)),
                    status_code=401,
                    media_type="application/problem+json",
                )
        return await call_next(request)

    @app.exception_handler(DomainError)
    async def error_handler(_request: Any, error: DomainError) -> JSONResponse:
        return JSONResponse(
            error.problem(),
            status_code=error.status,
            media_type="application/problem+json",
        )

    def engine(simulator_id: str) -> SimulatorEngine:
        result = engines.get(simulator_id)
        if not result:
            raise DomainError("SIMULATOR_NOT_FOUND", "simulator not found", status=404)
        return result

    def identity_for(simulator_id: str) -> dict[str, Any]:
        item = engine(simulator_id)
        payload = {
            "environment_type": "simulator",
            "simulator_id": simulator_id,
            "model_digest": item.model_digest,
            "asset_model_digest": item.asset_model_digest,
            "simulator_build_digest": item.simulator_build_digest,
        }
        return {**payload, "identity_digest": canonical_digest(payload)}

    @app.get("/internal/v1/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ready",
            "environment_type": "simulator",
            "instances": len(engines),
            "model_digest": model.digest,
        }

    @app.get("/internal/v1/simulators/{simulator_id}/identity")
    def identity(simulator_id: str) -> dict[str, Any]:
        return identity_for(simulator_id)

    @app.post("/internal/v1/simulators", status_code=201)
    def create_simulator(body: dict[str, Any]) -> dict[str, Any]:
        simulator_id = str(body.get("simulator_id", new_id("simulator")))
        if simulator_id in engines:
            raise DomainError(
                "SIMULATOR_EXISTS", "simulator ID already exists", status=409
            )
        parameters = ProcessParameters(**body.get("parameters", {}))
        parameters.validate()
        requested_build = str(body.get("simulator_build_digest", build_digest))
        if environment == "production" and requested_build != build_digest:
            raise DomainError(
                "SIMULATOR_BUILD_OVERRIDE_FORBIDDEN",
                "production simulator build identity is immutable process configuration",
                status=403,
            )
        engines[simulator_id] = SimulatorEngine(
            asset_model_digest=str(body.get("asset_model_digest", model.digest)),
            parameters=parameters,
            seed=int(body.get("seed", 42)),
            step_ms=int(body.get("step_ms", 100)),
            simulator_build_digest=requested_build,
            fault_runtime=FaultRuntime(),
        )
        return {
            "simulator_id": simulator_id,
            "state": "initialized",
            "model_digest": engines[simulator_id].model_digest,
        }

    @app.get("/internal/v1/simulators/{simulator_id}/state")
    def state(simulator_id: str) -> dict[str, Any]:
        item = engine(simulator_id)
        with item.synchronized():
            return {
                "simulation_time": item.simulation_time,
                "state": asdict(item.state),
                "paused": item.paused,
                "stopped": item.stopped,
                "sequence": item.sequence,
            }

    @app.post("/internal/v1/simulators/{simulator_id}/start")
    def start(simulator_id: str) -> dict[str, str]:
        engine(simulator_id).resume()
        return {"status": "running"}

    @app.post("/internal/v1/simulators/{simulator_id}/step")
    def step(simulator_id: str, body: dict[str, Any]) -> dict[str, Any]:
        item = engine(simulator_id)
        command = ProcessCommand(**body.get("command", body))
        frame = item.step_paused(command) if item.paused else item.step(command)
        return asdict(frame)

    @app.post("/internal/v1/simulators/{simulator_id}/pause")
    def pause(simulator_id: str) -> dict[str, str]:
        engine(simulator_id).pause()
        return {"status": "paused"}

    @app.post("/internal/v1/simulators/{simulator_id}/stop")
    def stop(simulator_id: str) -> dict[str, str]:
        engine(simulator_id).stop()
        return {"status": "stopped"}

    @app.post("/internal/v1/simulators/{simulator_id}/mode/{mode}")
    def mode(simulator_id: str, mode: OperatingMode) -> dict[str, str]:
        item = engine(simulator_id)
        item.transition_mode(mode)
        return {"mode": item.state.mode}

    @app.get("/internal/v1/simulators/{simulator_id}/faults")
    def faults(simulator_id: str) -> dict[str, Any]:
        runtime = engine(simulator_id).fault_runtime
        return {
            "active_faults": runtime.snapshot_state() if runtime else {},
            "gold_labels_exposed": False,
        }

    @app.post("/internal/v1/simulators/{simulator_id}/faults", status_code=201)
    def configure_faults(simulator_id: str, body: dict[str, Any]) -> dict[str, Any]:
        item = engine(simulator_id)
        with item.synchronized():
            if item.sequence and not item.paused:
                raise DomainError(
                    "FAULT_CONFIGURATION_REQUIRES_PAUSE",
                    "pause a running simulator before changing the fault schedule",
                    status=409,
                )
            raw_specs = body.get("faults")
            if not isinstance(raw_specs, list):
                raise DomainError(
                    "FAULT_CONFIGURATION_INVALID", "faults must be a list"
                )
            runtime = FaultRuntime([FaultSpec(**raw) for raw in raw_specs])
            item.fault_runtime = runtime
        return {
            "simulator_id": simulator_id,
            "fault_count": len(runtime.specs),
            "schedule_digest": canonical_digest(
                [asdict(spec) for spec in runtime.specs]
            ),
        }

    @app.post("/internal/v1/simulators/{simulator_id}/actions/{action_name}")
    def execute_action(
        simulator_id: str, action_name: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        item = engine(simulator_id)
        before = item.fault_runtime.snapshot_state() if item.fault_runtime else {}
        SimulatorActionAdapter(
            item,
            simulator_id,
            identity_for(simulator_id)["identity_digest"],
        ).execute(action_name, body.get("parameters", {}))
        after = item.fault_runtime.snapshot_state() if item.fault_runtime else {}
        before_ids = {spec["fault_id"] for spec in before.get("specs", ())}
        after_ids = {spec["fault_id"] for spec in after.get("specs", ())}
        outcome = "RECOVERED" if after_ids < before_ids else "UNCHANGED"
        evidence = {
            "action_name": action_name,
            "before_fault_ids": sorted(before_ids),
            "after_fault_ids": sorted(after_ids),
            "sequence": item.sequence,
        }
        return {
            "outcome": outcome,
            "evidence_refs": [f"simulator-state:{canonical_digest(evidence)}"],
            "state_digest": canonical_digest(evidence),
        }

    @app.post("/internal/v1/simulators/{simulator_id}/snapshots", status_code=201)
    def create_snapshot(simulator_id: str, body: dict[str, Any]) -> dict[str, Any]:
        envelope = snapshots.create(
            simulator_id,
            engine(simulator_id),
            str(body.get("reason", "manual")),
            body.get("run_id"),
            protected=bool(body.get("protected", False)),
        )
        return {
            "snapshot_id": envelope.snapshot_id,
            "content_hash": envelope.content_hash,
            "simulation_time": envelope.simulation_time,
        }

    @app.post("/internal/v1/simulators/{simulator_id}/restore")
    def restore(simulator_id: str, body: dict[str, Any]) -> dict[str, Any]:
        envelope = snapshots.restore(engine(simulator_id), str(body["snapshot_id"]))
        return {
            "snapshot_id": envelope.snapshot_id,
            "simulator_id": simulator_id,
            "simulation_time": envelope.simulation_time,
        }

    @app.post("/internal/v1/simulators/{simulator_id}/branches", status_code=201)
    def branch(simulator_id: str, body: dict[str, Any]) -> dict[str, Any]:
        source = engine(simulator_id)
        branch_id = str(body.get("branch_id", new_id("simulator")))
        if branch_id in engines:
            raise DomainError(
                "SIMULATOR_EXISTS", "branch ID already exists", status=409
            )
        engines[branch_id] = SimulatorEngine(
            asset_model_digest=source.asset_model_digest,
            parameters=source.parameters,
            seed=0,
            step_ms=source.step_ms,
            simulator_build_digest=source.simulator_build_digest,
            fault_runtime=copy.deepcopy(source.fault_runtime),
        )
        envelope = snapshots.restore(engines[branch_id], str(body["snapshot_id"]))
        return {
            "simulator_id": branch_id,
            "parent_simulator_id": simulator_id,
            "snapshot_id": envelope.snapshot_id,
        }

    app.state.engines = engines
    app.state.snapshots = snapshots
    app.state.store = store

    opcua_server: AsyncUaSimulatorServer | None = None
    publisher_task: asyncio.Task[None] | None = None

    async def publish_frames(server: AsyncUaSimulatorServer) -> None:
        item = engine("default")
        speed = int(os.environ.get("SHADOW_SIMULATOR_SPEED", "1"))
        if speed not in {1, 2, 10, 50}:
            raise DomainError(
                "SIMULATOR_SPEED_INVALID", "speed must be 1, 2, 10, or 50"
            )
        publish_every = max(1, int(500 / item.step_ms))
        while True:
            if not item.paused and not item.stopped:
                frame = item.step()
                if frame.source_sequence % publish_every == 0:
                    await server.publish(frame)
            await asyncio.sleep((item.step_ms / 1000.0) / speed)

    async def start_opcua() -> None:
        nonlocal opcua_server, publisher_task
        if os.environ.get("SHADOW_OPCUA_ENABLED", "false").lower() != "true":
            return
        certificate = os.environ.get("SHADOW_OPCUA_CERTIFICATE_PATH")
        private_key = os.environ.get("SHADOW_OPCUA_PRIVATE_KEY_PATH")
        opcua_server = AsyncUaSimulatorServer(
            model,
            engine("default"),
            OpcUaServerConfig(
                endpoint=os.environ.get(
                    "SHADOW_OPCUA_ENDPOINT", "opc.tcp://0.0.0.0:4840/shadow"
                ),
                application_uri=os.environ.get(
                    "SHADOW_OPCUA_APPLICATION_URI", "urn:industrial-shadow:simulator"
                ),
                namespace_uri=os.environ.get(
                    "SHADOW_OPCUA_NAMESPACE_URI", "urn:industrial-shadow:pump-tank"
                ),
                certificate_path=Path(certificate) if certificate else None,
                private_key_path=Path(private_key) if private_key else None,
                trusted_client_fingerprints=_trusted_client_fingerprints(
                    os.environ.get("SHADOW_OPCUA_TRUSTED_CLIENT_FINGERPRINTS", "")
                ),
                allow_insecure_development=(
                    environment != "production"
                    and os.environ.get("SHADOW_OPCUA_ALLOW_INSECURE", "false").lower()
                    == "true"
                ),
            ),
        )
        await opcua_server.start()
        publisher_task = asyncio.create_task(publish_frames(opcua_server))
        app.state.opcua_server = opcua_server

    @app.get("/internal/v1/opcua-endpoint")
    def opcua_endpoint() -> dict[str, Any]:
        if not opcua_server:
            raise DomainError(
                "OPCUA_SERVER_NOT_STARTED", "OPC UA server is disabled", status=503
            )
        return {
            "endpoint": opcua_server.config.endpoint,
            "application_uri": opcua_server.config.application_uri,
            "namespace_uri": opcua_server.config.namespace_uri,
            "certificate_fingerprint": opcua_server.certificate_fingerprint,
            "security_mode": (
                "SignAndEncrypt"
                if opcua_server.certificate_fingerprint
                else "None-development-only"
            ),
            "simulator_identity_digest": opcua_server.identity_digest,
        }

    async def shutdown() -> None:
        if publisher_task:
            publisher_task.cancel()
            try:
                await publisher_task
            except asyncio.CancelledError:
                pass
        if opcua_server:
            await opcua_server.stop()
        store.close()

    @asynccontextmanager
    async def lifespan(_app: Any) -> AsyncIterator[None]:
        await start_opcua()
        try:
            yield
        finally:
            await shutdown()

    app.router.lifespan_context = lifespan
    return app
