from __future__ import annotations

import argparse
import json
import os
import sqlite3
from dataclasses import asdict
from pathlib import Path

from shadow_simulator import ProcessCommand, SimulatorEngine

from shadow_sandbox.api.router import API_ROUTE_CONTRACT
from shadow_sandbox.asset_registry import AssetRegistryService, pump_tank_model
from shadow_sandbox.common import ActorContext, Store
from shadow_sandbox.common.db import open_store
from shadow_sandbox.common.models import canonical_digest
from shadow_sandbox.evaluation.metrics import (
    EpisodeEvaluationInput,
    Evaluator,
    ReleaseGate,
)
from shadow_sandbox.reports import Report, ReportRenderer
from shadow_sandbox.scenarios import expand_mvp_benchmark

ROOT = Path(__file__).resolve().parents[3]


def migrate(database: str) -> Store:
    return open_store(database, ROOT / "migrations")


def generate_schemas(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    schemas = {
        "events/raw-signal-event-v1.json": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "RawSignalEventV1",
            "type": "object",
            "required": [
                "tenant_id",
                "workspace_id",
                "run_id",
                "scenario_id",
                "endpoint_id",
                "node_id",
                "signal_key",
                "data_type",
                "value",
                "source_timestamp",
                "server_timestamp",
                "received_timestamp",
                "status_code",
                "sequence",
            ],
            "properties": {
                "tenant_id": {"type": "string"},
                "workspace_id": {"type": "string"},
                "run_id": {"type": "string"},
                "scenario_id": {"type": "string"},
                "endpoint_id": {"type": "string"},
                "node_id": {"type": "string"},
                "signal_key": {"type": "string"},
                "data_type": {"type": "string"},
                "value": {},
                "source_timestamp": {"type": "string", "format": "date-time"},
                "server_timestamp": {"type": "string", "format": "date-time"},
                "received_timestamp": {"type": "string", "format": "date-time"},
                "status_code": {"type": "string"},
                "sequence": {"type": "integer", "minimum": 1},
                "flags": {"type": "array", "items": {"type": "string"}},
                "ingest_version": {"const": 1},
                "trace_id": {"type": ["string", "null"]},
            },
            "additionalProperties": False,
        },
        "scenarios/scenario-suite-v1.json": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "ScenarioSuiteV1",
            "type": "object",
            "required": ["suite_id", "axes", "seeds", "split"],
            "properties": {
                "suite_id": {"type": "string"},
                "axes": {"type": "object"},
                "seeds": {"type": "array", "items": {"type": "integer"}},
                "split": {"enum": ["train", "tune", "validation", "certification"]},
            },
            "additionalProperties": False,
        },
        "api/release-gate-result-v1.json": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "ReleaseGateResultV1",
            "type": "object",
            "required": ["bundle_digest", "passed", "reasons", "certification_digest"],
            "properties": {
                "bundle_digest": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                "passed": {"type": "boolean"},
                "reasons": {"type": "array", "items": {"type": "string"}},
                "certification_digest": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
            },
            "additionalProperties": True,
        },
        "api/openapi.json": {
            "openapi": "3.1.0",
            "info": {"title": "Industrial Shadow Sandbox", "version": "0.1.0"},
            "paths": _openapi_paths(),
        },
    }
    for relative, schema in schemas.items():
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _openapi_paths() -> dict[str, dict[str, object]]:
    paths: dict[str, dict[str, object]] = {}
    for method, path in API_ROUTE_CONTRACT:
        operation_id = (
            method.lower()
            + "_"
            + path.removeprefix("/api/v1/")
            .replace("/", "_")
            .replace("{", "")
            .replace("}", "")
            .replace("-", "_")
        )
        paths.setdefault(path, {})[method.lower()] = {
            "operationId": operation_id,
            "responses": {
                "200": {"description": "Successful response"},
                "4XX": {"description": "Problem Details"},
            },
        }
    return paths


def demo(database: str, output: Path) -> None:
    store = migrate(database)
    actor = ActorContext(
        "demo-engineer", "demo-tenant", "demo-workspace", frozenset({"Engineer", "Admin"})
    )
    model = pump_tank_model()
    try:
        AssetRegistryService(store).publish(actor, model)
    except sqlite3.IntegrityError:
        existing = store.get_artifact("asset_model", model.model_id, actor.workspace_id, 1)
        if existing["digest"] != model.digest:
            raise RuntimeError("existing demo asset model has a different digest")
    engine = SimulatorEngine(asset_model_digest=model.digest, seed=42)
    frames = engine.run_until(10.0, ProcessCommand())
    episodes = expand_mvp_benchmark()
    evaluations = []
    for episode in episodes:
        cause = () if episode.fault_type is None else (f"cause-{episode.fault_type}",)
        evaluations.append(
            EpisodeEvaluationInput(
                episode.episode_id,
                episode.fault_type is None,
                cause,
                cause,
                episode.fault_type is not None,
                0.95,
                False,
                0,
                0,
                0,
                0,
                True,
                True,
                True,
                {"fault": episode.fault_type or "normal", "load": episode.load},
            )
        )
    evaluation = Evaluator().evaluate("demo-evaluation", evaluations)
    gate = ReleaseGate().evaluate("demo-gate", canonical_digest([model.digest, "demo"]), evaluation)
    report = Report(
        "demo-report",
        "demo-run",
        "Industrial Shadow Sandbox Demo",
        {
            "simulator": {"frames": len(frames), "last_frame": frames[-1].frame_digest},
            "evaluation": asdict(evaluation),
            "gate": asdict(gate),
        },
        {"asset_model": model.digest, "build": "demo"},
        (),
        ("Synthetic deterministic corpus; not real-site certification.",),
    )
    output.mkdir(parents=True, exist_ok=True)
    renderer = ReportRenderer()
    (output / "report.json").write_text(renderer.render_json(report), encoding="utf-8")
    (output / "report.html").write_text(renderer.render_html(report), encoding="utf-8")
    (output / "summary.json").write_text(
        json.dumps(
            {
                "frames": len(frames),
                "episodes": len(episodes),
                "fault_episodes": sum(item.fault_type is not None for item in episodes),
                "normal_episodes": sum(item.fault_type is None for item in episodes),
                "gate_passed": gate.passed,
                "gate_reasons": gate.reasons,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Industrial Shadow Sandbox CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "migrate"):
        command = sub.add_parser(name)
        command.add_argument("--database")
    schema_command = sub.add_parser("schemas")
    schema_command.add_argument("--output", required=True, type=Path)
    demo_command = sub.add_parser("demo")
    demo_command.add_argument("--database", required=True)
    demo_command.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.command in {"init", "migrate"}:
        database = args.database or os.environ.get("SHADOW_DATABASE_URL")
        if not database:
            parser.error("--database or SHADOW_DATABASE_URL is required")
        migrate(database).close()
    elif args.command == "schemas":
        generate_schemas(args.output)
    elif args.command == "demo":
        demo(args.database, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
