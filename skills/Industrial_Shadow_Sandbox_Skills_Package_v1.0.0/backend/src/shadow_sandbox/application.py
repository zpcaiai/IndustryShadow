from __future__ import annotations

import json
import platform
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from shadow_sandbox import __version__
from shadow_sandbox.actions import ActionRequest
from shadow_sandbox.admin import database_probe
from shadow_sandbox.approvals import ApprovalService
from shadow_sandbox.asset_registry import (
    Asset,
    AssetModel,
    AssetRegistryService,
    SignalDefinition,
    TopologyEdge,
    validate_model,
)
from shadow_sandbox.common import (
    ActorContext,
    DomainError,
    EventEnvelope,
    Resource,
    ResourceRepository,
    Store,
    canonical_digest,
)
from shadow_sandbox.common.models import new_id, utc_now
from shadow_sandbox.diagnosis.evidence import Evidence, EvidenceService, Symptom
from shadow_sandbox.diagnosis.hypotheses import DiagnosisResult, Hypothesis, HypothesisRanker
from shadow_sandbox.diagnosis.residuals import ResidualEngine
from shadow_sandbox.evaluation.metrics import (
    EpisodeEvaluationInput,
    EvaluationResult,
    Evaluator,
    ReleaseGate,
    ReleaseGateResult,
)
from shadow_sandbox.ingestion import IngestionQueryService
from shadow_sandbox.integrations.imports import HistoricalImporter, SignalMapping
from shadow_sandbox.observability.metrics import SAFETY_POLICY_VIOLATIONS, VIRTUAL_ACTIONS
from shadow_sandbox.planning import CheckPlan, CheckPlanner, CheckStep
from shadow_sandbox.replay import ReplayManifest, compare_variants
from shadow_sandbox.reports import Report, ReportRenderer
from shadow_sandbox.runtime import RunManifest, RunOrchestrator, RunState
from shadow_sandbox.scenarios import (
    ClockSpec,
    FaultInjection,
    ScenarioService,
    ScenarioSpec,
    TimelineItem,
    expand_mvp_benchmark,
    scenario_from_mapping,
    validate_scenario,
)
from shadow_sandbox.security import ROLE_PERMISSIONS, authorize, redact


def _as_model(payload: Mapping[str, Any]) -> AssetModel:
    return AssetModel(
        model_id=str(payload["model_id"]),
        version=int(payload.get("version", 1)),
        assets=tuple(Asset(**item) for item in payload.get("assets", ())),
        signals=tuple(SignalDefinition(**item) for item in payload.get("signals", ())),
        topology=tuple(TopologyEdge(**item) for item in payload.get("topology", ())),
        metadata=dict(payload.get("metadata", {})),
    )


def _as_diagnosis(payload: Mapping[str, Any]) -> DiagnosisResult:
    return DiagnosisResult(
        status=str(payload["status"]),
        hypotheses=tuple(Hypothesis(**item) for item in payload.get("hypotheses", ())),
        quality_state=str(payload["quality_state"]),
        candidate_coverage=float(payload.get("candidate_coverage", 0)),
        reasons=tuple(payload.get("reasons", ())),
        additional_information=tuple(payload.get("additional_information", ())),
    )


def _as_scenario(payload: Mapping[str, Any]) -> ScenarioSpec:
    timeline = []
    for raw in payload.get("timeline", ()):
        item = dict(raw)
        fault = item.pop("fault", None)
        timeline.append(TimelineItem(fault=FaultInjection(**fault) if fault else None, **item))
    return ScenarioSpec(
        scenario_id=str(payload["scenario_id"]),
        scenario_version=int(payload["scenario_version"]),
        process_model_ref=str(payload["process_model_ref"]),
        asset_model_ref=str(payload["asset_model_ref"]),
        seed=int(payload["seed"]),
        clock=ClockSpec(**dict(payload["clock"])),
        operating_profile=dict(payload.get("operating_profile", {})),
        timeline=tuple(timeline),
        tags=tuple(payload.get("tags", ())),
        schema_version=int(payload.get("schema_version", 1)),
        metadata=dict(payload.get("metadata", {})),
    )


def _as_plan(payload: Mapping[str, Any]) -> CheckPlan:
    return CheckPlan(
        plan_id=str(payload["plan_id"]),
        run_id=str(payload["run_id"]),
        diagnosis_digest=str(payload["diagnosis_digest"]),
        environment_type=str(payload["environment_type"]),
        steps=tuple(CheckStep(**item) for item in payload.get("steps", ())),
        rejected_checks=tuple(payload.get("rejected_checks", ())),
        status=str(payload["status"]),
        policy_digest=str(payload["policy_digest"]),
        plan_hash=str(payload["plan_hash"]),
    )


class ApplicationService:
    """Executable use-case layer shared by HTTP, CLI, workers, and tests.

    It deliberately accepts plain mappings at the boundary.  Domain constructors
    perform the validation, while every returned product is persisted with a digest,
    tenant scope, optimistic version, and append-only history.
    """

    def __init__(
        self,
        store: Store,
        *,
        import_directory: str | Path = ".runtime/imports",
        action_executor: Any | None = None,
        build_digest: str = "source-tree-uncommitted",
    ) -> None:
        self.store = store
        self.resources = ResourceRepository(store)
        self.assets = AssetRegistryService(store)
        self.scenarios = ScenarioService(store)
        self.runs = RunOrchestrator(store)
        self.ingestion = IngestionQueryService(store)
        self.approvals = ApprovalService(store)
        self.action_executor = action_executor
        self.build_digest = build_digest
        self.import_directory = Path(import_directory).resolve()
        self.import_directory.mkdir(parents=True, exist_ok=True)
        self.importer = HistoricalImporter(self.import_directory)

    def _emit(
        self,
        actor: ActorContext,
        event_type: str,
        payload: Mapping[str, Any],
        run_id: str | None = None,
    ) -> None:
        self.store.append_event(
            EventEnvelope(
                event_type, payload, actor.tenant_id, actor.workspace_id, run_id, actor.trace_id
            )
        )

    def _output(
        self,
        actor: ActorContext,
        resource_type: str,
        resource_id: str,
        payload: Mapping[str, Any],
        *,
        state: str = "COMPLETED",
        sealed: bool = True,
    ) -> Resource:
        try:
            current = self.resources.get(actor, resource_type, resource_id)
        except DomainError as error:
            if error.code != "RESOURCE_NOT_FOUND":
                raise
            return self.resources.create(
                actor, resource_type, resource_id, payload, state=state, sealed=sealed
            )
        if current.digest == canonical_digest(payload):
            return current
        if current.sealed:
            resource_id = resource_id + "_" + canonical_digest(payload)[:12]
            return self.resources.create(
                actor, resource_type, resource_id, payload, state=state, sealed=sealed
            )
        return self.resources.update(
            actor,
            resource_type,
            resource_id,
            payload,
            expected_version=current.version,
            state=state,
            seal=sealed,
        )

    # Asset registry -----------------------------------------------------
    def create_asset_model(self, actor: ActorContext, body: Mapping[str, Any]) -> dict[str, Any]:
        actor.require_role("Engineer", "PackAuthor", "Admin")
        model = _as_model(body)
        errors = validate_model(model)
        payload = asdict(model)
        result = self.resources.create(actor, "asset_model_draft", model.model_id, payload)
        return {**result.as_dict(), "validation_errors": errors}

    def update_asset_model(
        self, actor: ActorContext, model_id: str, body: Mapping[str, Any], expected_version: int
    ) -> dict[str, Any]:
        actor.require_role("Engineer", "PackAuthor", "Admin")
        payload = {**dict(body), "model_id": model_id}
        model = _as_model(payload)
        result = self.resources.update(
            actor, "asset_model_draft", model_id, asdict(model), expected_version=expected_version
        )
        return {**result.as_dict(), "validation_errors": validate_model(model)}

    def validate_asset_model(self, actor: ActorContext, model_id: str) -> dict[str, Any]:
        draft = self.resources.get(actor, "asset_model_draft", model_id)
        errors = validate_model(_as_model(draft.payload))
        return {
            "valid": not errors,
            "errors": errors,
            "digest": draft.digest,
            "version": draft.version,
        }

    def publish_asset_model(self, actor: ActorContext, model_id: str) -> dict[str, Any]:
        draft = self.resources.get(actor, "asset_model_draft", model_id)
        model = _as_model(draft.payload)
        digest = self.assets.publish(actor, model)
        published = self._output(
            actor,
            "asset_model_version",
            f"{model_id}@{model.version}",
            {**asdict(model), "digest": digest},
            state="PUBLISHED",
        )
        return published.as_dict()

    def asset_topology(self, actor: ActorContext, version_id: str) -> dict[str, Any]:
        resource = self.resources.get(actor, "asset_model_version", version_id)
        return {"model": version_id, "topology": resource.payload.get("topology", ())}

    # Scenario registry and suite ---------------------------------------
    def create_scenario(self, actor: ActorContext, body: Mapping[str, Any]) -> dict[str, Any]:
        actor.require_role("Engineer", "PackAuthor", "Admin")
        spec = scenario_from_mapping(body)
        result = self.resources.create(actor, "scenario_draft", spec.scenario_id, asdict(spec))
        return result.as_dict()

    def update_scenario(
        self, actor: ActorContext, scenario_id: str, body: Mapping[str, Any], expected_version: int
    ) -> dict[str, Any]:
        actor.require_role("Engineer", "PackAuthor", "Admin")
        spec = scenario_from_mapping({**dict(body), "scenario_id": scenario_id})
        return self.resources.update(
            actor,
            "scenario_draft",
            scenario_id,
            asdict(spec),
            expected_version=expected_version,
        ).as_dict()

    def validate_scenario(
        self, actor: ActorContext, scenario_id: str, signal_keys: Sequence[str]
    ) -> dict[str, Any]:
        draft = self.resources.get(actor, "scenario_draft", scenario_id)
        spec = _as_scenario(draft.payload)
        errors = validate_scenario(spec, set(signal_keys))
        enriched = [
            {
                "severity": "error",
                "line": None,
                "column": None,
                "remediation": "correct the referenced Scenario Spec field",
                **error,
            }
            for error in errors
        ]
        return {"valid": not errors, "errors": enriched, "digest": draft.digest}

    def preview_scenario(self, actor: ActorContext, scenario_id: str) -> dict[str, Any]:
        draft = self.resources.get(actor, "scenario_draft", scenario_id)
        spec = _as_scenario(draft.payload)
        timeline = sorted((asdict(item) for item in spec.timeline), key=lambda item: item["at"])
        affected = sorted(
            {
                str(item.fault.target if item.fault else item.target)
                for item in spec.timeline
                if item.fault or item.target
            }
        )
        return {"scenario_id": scenario_id, "timeline": timeline, "affected_signals": affected}

    def publish_scenario(
        self, actor: ActorContext, scenario_id: str, signal_keys: Sequence[str]
    ) -> dict[str, Any]:
        draft = self.resources.get(actor, "scenario_draft", scenario_id)
        spec = _as_scenario(draft.payload)
        digest = self.scenarios.publish(actor, spec, set(signal_keys))
        return self._output(
            actor,
            "scenario_version",
            f"{scenario_id}@{spec.scenario_version}",
            {**asdict(spec), "digest": digest},
            state="PUBLISHED",
        ).as_dict()

    def put_scenario_suite(
        self, actor: ActorContext, suite_id: str, body: Mapping[str, Any], *, publish: bool = False
    ) -> dict[str, Any]:
        actor.require_role("Engineer", "PackAuthor", "Admin")
        expected = int(body.get("expected_episode_count", 0))
        if expected < 1:
            raise DomainError("SUITE_INVALID", "expected_episode_count must be positive")
        state = "PUBLISHED" if publish else "DRAFT"
        return self._output(
            actor, "scenario_suite", suite_id, dict(body), state=state, sealed=publish
        ).as_dict()

    def expand_scenario_suite(self, actor: ActorContext, suite_id: str) -> dict[str, Any]:
        suite = self.resources.get(actor, "scenario_suite", suite_id)
        if suite_id == "mvp-benchmark" or suite.payload.get("builtin") == "mvp-benchmark":
            episodes = [asdict(item) for item in expand_mvp_benchmark()]
        else:
            scenarios = list(suite.payload.get("scenario_refs", ()))
            seeds = list(suite.payload.get("seeds", (1,)))
            loads = list(suite.payload.get("loads", ("nominal",)))
            episodes = []
            for scenario in scenarios:
                for seed in seeds:
                    for load in loads:
                        item = {
                            "scenario_ref": scenario,
                            "seed": seed,
                            "load": load,
                            "split": suite.payload.get("split", "development"),
                        }
                        episodes.append({"episode_id": "ep_" + canonical_digest(item)[:24], **item})
        expected = int(suite.payload.get("expected_episode_count", len(episodes)))
        if len(episodes) != expected:
            raise DomainError(
                "SUITE_COUNT_MISMATCH",
                "expanded Episode count differs from contract",
                {"expected": expected, "actual": len(episodes)},
            )
        return {
            "suite_id": suite_id,
            "episodes": episodes,
            "count": len(episodes),
            "gold_included": False,
        }

    # Runs and acquired events ------------------------------------------
    def create_run(
        self, actor: ActorContext, body: Mapping[str, Any], idempotency_key: str
    ) -> dict[str, Any]:
        return self.runs.create(actor, RunManifest(**body), idempotency_key)

    def command_run(
        self, actor: ActorContext, run_id: str, command: str, reason: str
    ) -> dict[str, Any]:
        actor.require_role("Engineer", "Admin")
        row = self.runs.get(actor, run_id)
        state = RunState(row["state"])
        targets = {
            "pause": RunState.PAUSED,
            "resume": RunState.RUNNING,
            "cancel": RunState.CANCELLED if state == RunState.REQUESTED else RunState.CANCELLING,
            "retry": RunState.QUEUED,
        }
        if command not in targets:
            raise DomainError("RUN_COMMAND_INVALID", "unknown Run command")
        return self.runs.transition(actor, run_id, targets[command], reason, int(row["version"]))

    def run_tasks(self, actor: ActorContext, run_id: str) -> list[dict[str, Any]]:
        self.runs.get(actor, run_id)
        return self.store.query(
            "SELECT * FROM processing_tasks WHERE run_id=? AND workspace_id=? ORDER BY created_at",
            (run_id, actor.workspace_id),
        )

    def signal_events(
        self,
        actor: ActorContext,
        run_id: str,
        signal_key: str,
        start: str | None,
        end: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        return self.ingestion.events(actor, run_id, signal_key, start, end, limit)

    def connector_health(self, actor: ActorContext, endpoint_id: str) -> dict[str, Any]:
        rows = self.store.query(
            "SELECT * FROM endpoint_registry WHERE endpoint_id=? AND workspace_id=?",
            (endpoint_id, actor.workspace_id),
        )
        if not rows:
            raise DomainError("CONNECTOR_NOT_FOUND", "connector not found", status=404)
        row = rows[0]
        counts = self.store.query(
            """SELECT COUNT(*) AS event_count, MAX(received_timestamp) AS last_received
                 FROM raw_signal_events WHERE endpoint_id=? AND workspace_id=?""",
            (endpoint_id, actor.workspace_id),
        )[0]
        return {
            "endpoint_id": endpoint_id,
            "state": row["state"],
            **counts,
            "last_error": None,
            "backlog": 0,
        }

    def export_events(self, actor: ActorContext, run_id: str) -> dict[str, Any]:
        run = self.runs.get(actor, run_id)
        rows = self.store.query(
            """SELECT logical_id, event_digest, signal_key, source_timestamp
                 FROM raw_signal_events WHERE run_id=? AND workspace_id=?
                 ORDER BY signal_key, source_timestamp, sequence""",
            (run_id, actor.workspace_id),
        )
        payload = {
            "run_id": run_id,
            "run_manifest_digest": run["manifest_digest"],
            "format": "parquet",
            "event_count": len(rows),
            "event_set_digest": canonical_digest(rows),
            "status": "MANIFEST_CREATED",
            "limitation": "binary parquet materialization requires the worker pyarrow profile",
        }
        return self._output(
            actor, "export_manifest", "export_" + canonical_digest(payload)[:24], payload
        ).as_dict()

    def _run_events(self, actor: ActorContext, run_id: str) -> dict[str, list[SimpleNamespace]]:
        self.runs.get(actor, run_id)
        rows = self.store.query(
            """SELECT * FROM raw_signal_events WHERE run_id=? AND workspace_id=?
               ORDER BY signal_key, source_timestamp, sequence""",
            (run_id, actor.workspace_id),
        )
        grouped: dict[str, list[SimpleNamespace]] = {}
        for row in rows:
            item = dict(row)
            item["value"] = json.loads(item.pop("value_json"))
            item["flags"] = tuple(json.loads(item.pop("flags_json")))
            grouped.setdefault(str(item["signal_key"]), []).append(SimpleNamespace(**item))
        return grouped

    def quality_and_detect(
        self, actor: ActorContext, run_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        from shadow_sandbox.quality import QualityService, UnivariateDetector

        grouped = self._run_events(actor, run_id)
        service = QualityService()
        detector = UnivariateDetector(str(body.get("detector_ref", "robust-univariate@1")))
        quality: list[dict[str, Any]] = []
        anomalies: list[dict[str, Any]] = []
        expected_by_signal = dict(body.get("expected_counts", {}))
        baselines = dict(body.get("baselines", {}))
        mode = str(body.get("mode", "steady"))
        for signal, events in grouped.items():
            window = service.assess(events, int(expected_by_signal.get(signal, len(events))))
            quality.append({**asdict(window), "digest": window.digest})
            values = [float(item.value) for item in events if isinstance(item.value, (int, float))]
            baseline = [
                float(value) for value in baselines.get(signal, values[: max(3, len(values) // 2)])
            ]
            anomalies.extend(
                {**asdict(item), "digest": item.digest}
                for item in detector.detect(window, values, baseline, mode)
            )
        payload = {
            "run_id": run_id,
            "quality": quality,
            "anomalies": anomalies,
            "policy_digest": service.policy_digest,
        }
        result = self._output(
            actor, "quality_detection", f"quality:{run_id}", payload, sealed=False
        )
        self._emit(actor, "data_quality.assessed.v1", {"resource_id": result.resource_id}, run_id)
        return result.as_dict()

    def residuals_and_consistency(
        self, actor: ActorContext, run_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        self.runs.get(actor, run_id)
        engine = ResidualEngine(body.get("tolerances"))
        series = dict(body.get("series", {}))
        quality = str(body.get("quality_state", "TRUSTED"))
        observations = []
        if all(key in series for key in ("level", "qin", "qout")):
            observations.append(
                engine.mass_balance(
                    run_id,
                    series["level"],
                    series["qin"],
                    series["qout"],
                    float(body.get("step_s", 1)),
                    float(body.get("area_m2", 1)),
                    quality,
                )
            )
        if all(key in series for key in ("temperature", "heater_kw")):
            observations.append(
                engine.thermal_balance(
                    run_id,
                    series["temperature"],
                    series["heater_kw"],
                    float(body.get("step_s", 1)),
                    float(body.get("capacity", 10000)),
                    float(body.get("heat_loss", 20)),
                    float(body.get("ambient", 20)),
                    quality,
                )
            )
        if all(key in body for key in ("inlet_flow", "speed_rpm", "valve_percent", "max_flow")):
            observations.append(
                engine.pump_performance(
                    run_id,
                    float(body["inlet_flow"]),
                    float(body["speed_rpm"]),
                    float(body["valve_percent"]),
                    float(body["max_flow"]),
                    quality,
                )
            )
        if all(key in body for key in ("actual", "command")):
            observations.append(
                engine.command_response(
                    run_id, float(body["actual"]), float(body["command"]), quality
                )
            )
        if not observations:
            raise DomainError(
                "RESIDUAL_INPUT_MISSING", "no registered residual has complete typed inputs"
            )
        data = [{**asdict(item), "digest": item.digest} for item in observations]
        consistency = [
            {
                "code": f"{item['residual_ref']}:exceeded",
                "residual_digest": item["digest"],
                "direction": item["direction"],
            }
            for item in data
            if (item["normalized_magnitude"] or 0) > 1
        ]
        result = self._output(
            actor,
            "residual_set",
            f"residuals:{run_id}",
            {"run_id": run_id, "residuals": data, "consistency_observations": consistency},
            sealed=False,
        )
        self._emit(actor, "residual.observed.v1", {"resource_id": result.resource_id}, run_id)
        return result.as_dict()

    def materialize_evidence(
        self, actor: ActorContext, run_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        self.runs.get(actor, run_id)
        service = EvidenceService()
        evidence: list[dict[str, Any]] = []
        symptoms: list[dict[str, Any]] = []
        for raw in body.get("observations", ()):
            item, symptom = service.materialize(
                run_id=run_id,
                workspace_id=actor.workspace_id,
                observation_type=str(raw["observation_type"]),
                observation=raw.get("observation"),
                baseline=raw.get("baseline"),
                threshold=raw.get("threshold"),
                quality_state=str(raw.get("quality_state", "TRUSTED")),
                source_refs=tuple(raw.get("source_refs", ())),
                source_hashes=tuple(raw.get("source_hashes", ())),
                related_signals=tuple(raw.get("related_signals", ())),
                transformation_ref=str(raw.get("transformation_ref", "registered@1")),
                units=raw.get("units"),
                role=str(raw.get("role", "support")),
                window=raw.get("window", {}),
            )
            evidence.append({**asdict(item), "digest": item.digest})
            if symptom:
                symptoms.append(asdict(symptom))
        if not evidence:
            raise DomainError(
                "EVIDENCE_INPUT_MISSING", "at least one typed observation is required"
            )
        result = self._output(
            actor,
            "evidence_set",
            f"evidence:{run_id}",
            {"run_id": run_id, "evidence": evidence, "symptoms": symptoms},
            sealed=False,
        )
        self._emit(actor, "evidence.created.v1", {"resource_id": result.resource_id}, run_id)
        return result.as_dict()

    def generate_hypotheses(
        self, actor: ActorContext, run_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        source_id = str(body.get("evidence_resource_id", f"evidence:{run_id}"))
        source = self.resources.get(actor, "evidence_set", source_id)
        evidence = {
            item["evidence_id"]: Evidence(
                **{key: value for key, value in item.items() if key != "digest"}
            )
            for item in source.payload.get("evidence", ())
        }
        symptoms = tuple(Symptom(**item) for item in source.payload.get("symptoms", ()))
        diagnosis = HypothesisRanker(body.get("catalog")).rank(
            symptoms, evidence, str(body.get("quality_state", "TRUSTED"))
        )
        payload = asdict(diagnosis)
        result = self._output(
            actor, "diagnosis_result", f"diagnosis:{run_id}", payload, sealed=False
        )
        event = (
            "hypotheses.ready.v1" if diagnosis.status == "RANKED" else "diagnosis.inconclusive.v1"
        )
        self._emit(actor, event, {"resource_id": result.resource_id}, run_id)
        return result.as_dict()

    def create_check_plan(
        self, actor: ActorContext, run_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        run = self.runs.get(actor, run_id)
        source = self.resources.get(
            actor, "diagnosis_result", str(body.get("diagnosis_resource_id", f"diagnosis:{run_id}"))
        )
        diagnosis = _as_diagnosis(source.payload)
        plan = CheckPlanner().plan(run_id, diagnosis, str(run["manifest"]["environment_type"]))
        result = self._output(actor, "check_plan", plan.plan_id, asdict(plan), state=plan.status)
        self._emit(
            actor,
            "check_plan.ready.v1",
            {"plan_id": plan.plan_id, "plan_hash": plan.plan_hash},
            run_id,
        )
        return result.as_dict()

    def reorder_check_plan(
        self, actor: ActorContext, plan_id: str, ordered_step_ids: Sequence[str]
    ) -> dict[str, Any]:
        source = self.resources.get(actor, "check_plan", plan_id)
        plan = _as_plan(source.payload)
        by_id = {step.step_id: step for step in plan.steps}
        if set(ordered_step_ids) != set(by_id):
            raise DomainError("PLAN_REORDER_INVALID", "order must contain every step exactly once")
        position = {step_id: index for index, step_id in enumerate(ordered_step_ids)}
        for step in plan.steps:
            for dependency in step.prerequisites:
                dep_steps = [item.step_id for item in plan.steps if item.check_id == dependency]
                if dep_steps and position[dep_steps[0]] > position[step.step_id]:
                    raise DomainError(
                        "PLAN_DEPENDENCY_VIOLATION", "reorder moves a dependency after its consumer"
                    )
        return {
            "valid": True,
            "plan_id": plan_id,
            "ordered_step_ids": list(ordered_step_ids),
            "preview_hash": canonical_digest([plan.plan_hash, ordered_step_ids]),
        }

    # Approval and simulation-only action -------------------------------
    def request_approval(self, actor: ActorContext, body: Mapping[str, Any]) -> dict[str, Any]:
        plan = _as_plan(self.resources.get(actor, "check_plan", str(body["plan_id"])).payload)
        request = self.approvals.request(
            actor,
            plan,
            str(body["simulator_digest"]),
            str(body["expires_at"]),
            body.get("parameter_bounds"),
        )
        self._emit(
            actor, "approval.requested.v1", {"approval_id": request.approval_id}, request.run_id
        )
        return asdict(request)

    def approval(self, actor: ActorContext, approval_id: str) -> dict[str, Any]:
        rows = self.store.query(
            "SELECT * FROM approvals WHERE approval_id=? AND workspace_id=?",
            (approval_id, actor.workspace_id),
        )
        if not rows:
            raise DomainError("APPROVAL_NOT_FOUND", "approval not found", status=404)
        row = rows[0]
        row["request"] = json.loads(row.pop("request_json"))
        row["decision"] = json.loads(row.pop("decision_json")) if row.get("decision_json") else None
        return row

    def approval_inbox(self, actor: ActorContext) -> list[dict[str, Any]]:
        actor.require_role("Approver", "Admin")
        self.approvals.expire_due()
        return [
            self.approval(actor, row["approval_id"])
            for row in self.store.query(
                "SELECT approval_id FROM approvals WHERE workspace_id=? AND state='PENDING' ORDER BY created_at",
                (actor.workspace_id,),
            )
        ]

    def decide_approval(
        self, actor: ActorContext, approval_id: str, body: Mapping[str, Any], expected_version: int
    ) -> dict[str, Any]:
        decision = self.approvals.decide(
            actor,
            approval_id,
            str(body["kind"]),
            tuple(body.get("allowed_steps", ())),
            str(body.get("reason_code", "reviewed")),
            str(body.get("reason_text", "")),
            expected_version,
            body.get("parameter_bounds"),
        )
        self._emit(
            actor, "approval.decided.v1", {"approval_id": approval_id, "kind": decision.kind}
        )
        return asdict(decision)

    def execute_action(
        self,
        actor: ActorContext,
        body: Mapping[str, Any],
        verifier: Callable[[Any], tuple[str, tuple[str, ...]]] | None = None,
    ) -> dict[str, Any]:
        authorize(actor, "action:execute")
        if str(body.get("environment_type", "simulator")) != "simulator":
            SAFETY_POLICY_VIOLATIONS.labels("REAL_ACTION_DENIED").inc()
            raise DomainError(
                "REAL_ACTION_DENIED", "actions can target simulator environments only", status=403
            )
        if not self.action_executor:
            raise DomainError(
                "SIMULATOR_DEPENDENCY_UNAVAILABLE",
                "no attested simulator executor is attached",
                status=503,
            )
        result = self.action_executor.execute(
            ActionRequest(**{key: body[key] for key in ActionRequest.__dataclass_fields__}),
            actor.workspace_id,
            verifier or (lambda _engine: ("UNCHANGED", ())),
        )
        VIRTUAL_ACTIONS.labels(result.state, result.outcome).inc()
        self._emit(
            actor,
            f"virtual_action.{result.state.lower()}.v1",
            {"action_id": result.action_id},
            body.get("run_id"),
        )
        return asdict(result)

    def action(self, actor: ActorContext, action_id: str) -> dict[str, Any]:
        rows = self.store.query(
            """SELECT a.* FROM action_executions a JOIN runs r ON r.run_id=a.run_id
               WHERE a.action_id=? AND r.workspace_id=?""",
            (action_id, actor.workspace_id),
        )
        if not rows:
            raise DomainError("ACTION_NOT_FOUND", "action not found", status=404)
        row = rows[0]
        row["request"] = json.loads(row.pop("request_json"))
        row["result"] = json.loads(row.pop("result_json")) if row.get("result_json") else None
        return row

    # Replay, experiment, evaluation, Gate and reports ------------------
    def create_replay(
        self, actor: ActorContext, run_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        self.runs.get(actor, run_id)
        stages = tuple(body.get("selected_stages", ()))
        allowed = {
            "quality",
            "detect",
            "residual",
            "evidence",
            "hypotheses",
            "check_plan",
            "narrative",
        }
        if not stages or not set(stages).issubset(allowed):
            raise DomainError("REPLAY_STAGE_INVALID", "replay stages must be registered")
        manifest = ReplayManifest(
            new_id("replay"),
            run_id,
            str(body["dataset_digest"]),
            stages,
            str(body.get("speed", "max")),
            dict(body.get("source_versions", {})),
            dict(body.get("override_versions", {})),
            str(body.get("output_namespace", new_id("replay-output"))),
        )
        result = self._output(
            actor,
            "replay",
            manifest.replay_id,
            {
                **asdict(manifest),
                "state": "COMPLETED",
                "output_digest": canonical_digest(asdict(manifest)),
            },
        )
        self._emit(actor, "replay.completed.v1", {"replay_id": manifest.replay_id}, run_id)
        return result.as_dict()

    def create_experiment(self, actor: ActorContext, body: Mapping[str, Any]) -> dict[str, Any]:
        variants = body.get("variants", {})
        if not isinstance(variants, Mapping) or len(variants) < 2:
            raise DomainError("EXPERIMENT_INVALID", "at least two named variants are required")
        experiment_id = str(body.get("experiment_id", new_id("experiment")))
        names = sorted(variants)
        comparison = [
            asdict(item) for item in compare_variants(variants[names[0]], variants[names[1]])
        ]
        payload = {
            **dict(body),
            "experiment_id": experiment_id,
            "state": "COMPLETED",
            "comparison": comparison,
            "variant_digests": {name: canonical_digest(variants[name]) for name in names},
        }
        result = self._output(actor, "experiment", experiment_id, payload)
        self._emit(actor, "experiment.completed.v1", {"experiment_id": experiment_id})
        return result.as_dict()

    def create_evaluation(self, actor: ActorContext, body: Mapping[str, Any]) -> dict[str, Any]:
        authorize(actor, "evaluation:execute")
        episodes = tuple(
            EpisodeEvaluationInput(
                episode_id=str(item["episode_id"]),
                is_normal=bool(item["is_normal"]),
                gold_causes=tuple(item.get("gold_causes", ())),
                ranked_causes=tuple(item.get("ranked_causes", ())),
                detected=bool(item.get("detected", False)),
                plan_score=float(item.get("plan_score", 0)),
                critical_step_omitted=bool(item.get("critical_step_omitted", False)),
                unsupported_claims=int(item.get("unsupported_claims", 0)),
                unapproved_actions=int(item.get("unapproved_actions", 0)),
                real_write_attempts=int(item.get("real_write_attempts", 0)),
                gold_leaks=int(item.get("gold_leaks", 0)),
                replay_match=bool(item.get("replay_match", False)),
                report_success=bool(item.get("report_success", False)),
                trace_success=bool(item.get("trace_success", False)),
                slice_labels=dict(item.get("slice_labels", {})),
            )
            for item in body.get("episodes", ())
        )
        if not episodes:
            raise DomainError("EVALUATION_EMPTY", "evaluation requires Episode results")
        evaluation_id = str(body.get("evaluation_id", new_id("evaluation")))
        evaluation = Evaluator().evaluate(evaluation_id, episodes)
        result = self._output(
            actor,
            "evaluation",
            evaluation_id,
            {
                **asdict(evaluation),
                "digest": evaluation.digest,
                "episodes": [asdict(item) for item in episodes],
            },
        )
        self._emit(actor, "evaluation.completed.v1", {"evaluation_id": evaluation_id})
        return result.as_dict()

    def evaluate_release_gate(self, actor: ActorContext, body: Mapping[str, Any]) -> dict[str, Any]:
        source = self.resources.get(actor, "evaluation", str(body["evaluation_id"]))
        payload = source.payload
        evaluation = EvaluationResult(
            str(payload["evaluation_id"]),
            str(payload["corpus_digest"]),
            dict(payload["metrics"]),
            dict(payload["slices"]),
            dict(payload["red_lines"]),
            tuple(payload["limitations"]),
            str(payload["evaluator_digest"]),
        )
        gate = ReleaseGate().evaluate(
            str(body.get("gate_id", new_id("gate"))), str(body["bundle_digest"]), evaluation
        )
        result = self._output(
            actor,
            "release_gate",
            gate.gate_id,
            asdict(gate),
            state="PASSED" if gate.passed else "FAILED",
        )
        self._emit(
            actor,
            f"release_gate.{'passed' if gate.passed else 'failed'}.v1",
            {"gate_id": gate.gate_id},
        )
        return result.as_dict()

    def promote_release_gate(
        self, actor: ActorContext, gate_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        actor.require_role("Admin")
        source = self.resources.get(actor, "release_gate", gate_id)
        gate = ReleaseGateResult(**source.payload)
        certification = ReleaseGate().promote(gate, str(body["bundle_digest"]))
        promotion_id = new_id("promotion")
        self.store.execute(
            """INSERT INTO release_promotions
               (promotion_id, workspace_id, gate_id, certification_digest, bundle_digest,
                actor_id, reason, promoted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                promotion_id,
                actor.workspace_id,
                gate_id,
                certification,
                body["bundle_digest"],
                actor.actor_id,
                str(body.get("reason", "release gate passed")),
                utc_now(),
            ),
        )
        return {
            "promotion_id": promotion_id,
            "gate_id": gate_id,
            "certification_digest": certification,
        }

    def generate_report(self, actor: ActorContext, body: Mapping[str, Any]) -> dict[str, Any]:
        report = Report(
            str(body.get("report_id", new_id("report"))),
            str(body["run_id"]),
            str(body.get("title", "Industrial Shadow Diagnosis Report")),
            dict(body.get("sections", {})),
            dict(body.get("version_manifest", {})),
            tuple(body.get("evidence_refs", ())),
            tuple(body.get("limitations", ())),
        )
        result = self._output(
            actor, "report", report.report_id, {**asdict(report), "digest": report.digest}
        )
        self._emit(actor, "report.generated.v1", {"report_id": report.report_id}, report.run_id)
        return result.as_dict()

    def render_report(
        self, actor: ActorContext, report_id: str, media_type: str
    ) -> tuple[str, str]:
        payload = self.resources.get(actor, "report", report_id).payload
        report = Report(**{key: payload[key] for key in Report.__dataclass_fields__})
        renderer = ReportRenderer()
        if "text/html" in media_type:
            return renderer.render_html(report), "text/html"
        if "application/pdf" in media_type:
            raise DomainError(
                "PDF_RENDERER_UNAVAILABLE", "PDF rendering worker is not configured", status=503
            )
        return renderer.render_json(report), "application/json"

    # Historical import -------------------------------------------------
    def register_import_source(
        self, actor: ActorContext, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        actor.require_role("Engineer", "Admin")
        path = Path(str(body["path"])).resolve()
        self.importer._safe_path(path)
        source_id = str(body.get("source_id", new_id("source")))
        return self.resources.create(
            actor,
            "import_source",
            source_id,
            {"source_id": source_id, "path": str(path), "read_only": True},
        ).as_dict()

    def profile_import_source(self, actor: ActorContext, source_id: str) -> dict[str, Any]:
        source = self.resources.get(actor, "import_source", source_id)
        profile = self.importer.profile(str(source.payload["path"]))
        return self._output(
            actor, "source_profile", f"profile:{source_id}", asdict(profile)
        ).as_dict()

    def validate_mappings(self, mappings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        errors = []
        for index, raw in enumerate(mappings):
            try:
                SignalMapping(**raw).validate()
            except DomainError as error:
                errors.append({"index": index, **error.problem()})
        return {"valid": not errors, "errors": errors, "mapping_digest": canonical_digest(mappings)}

    def create_import_job(self, actor: ActorContext, body: Mapping[str, Any]) -> dict[str, Any]:
        source = self.resources.get(actor, "import_source", str(body["source_id"]))
        mappings = tuple(SignalMapping(**item) for item in body.get("mappings", ()))
        normalized = list(self.importer.normalize(str(source.payload["path"]), mappings))
        job_id = str(body.get("job_id", new_id("import")))
        rows = [asdict(item) for item in normalized]
        dataset = {
            "dataset_id": "dataset_" + canonical_digest(rows)[:24],
            "source_id": body["source_id"],
            "source_hash": self.importer.profile(str(source.payload["path"])).source_hash,
            "mapping_digest": canonical_digest([asdict(item) for item in mappings]),
            "row_count": len(rows),
            "content_digest": canonical_digest(rows),
            "time_range": [rows[0]["source_timestamp"], rows[-1]["source_timestamp"]]
            if rows
            else [None, None],
            "split": body.get("split", "development"),
            "lineage": {"import_job_id": job_id},
        }
        dataset_resource = self._output(actor, "dataset", dataset["dataset_id"], dataset)
        job = {
            "job_id": job_id,
            "state": "COMPLETED",
            "accepted_rows": len(rows),
            "rejected_rows": 0,
            "dataset_id": dataset_resource.resource_id,
            "dataset_digest": dataset_resource.digest,
        }
        return self._output(actor, "import_job", job_id, job).as_dict()

    # Edge read-only gateway --------------------------------------------
    def register_edge_gateway(self, actor: ActorContext, body: Mapping[str, Any]) -> dict[str, Any]:
        actor.require_role("Admin")
        if body.get("environment_type") != "real_readonly":
            raise DomainError("EDGE_MODE_INVALID", "edge gateway must be real_readonly")
        gateway_id = str(body.get("gateway_id", new_id("gateway")))
        now = utc_now()
        identity_digest = canonical_digest(
            [body.get("site_id"), body.get("public_key"), body.get("endpoint")]
        )
        config_digest = canonical_digest(body)
        self.store.execute(
            """INSERT INTO edge_gateways
               (gateway_id, tenant_id, workspace_id, site_id, identity_digest,
                certificate_fingerprint, config_digest, state, health_json, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'REGISTERED', '{}', ?, ?)""",
            (
                gateway_id,
                actor.tenant_id,
                actor.workspace_id,
                body["site_id"],
                identity_digest,
                body["certificate_fingerprint"],
                config_digest,
                now,
                now,
            ),
        )
        return {
            "gateway_id": gateway_id,
            "identity_digest": identity_digest,
            "config_digest": config_digest,
            "state": "REGISTERED",
            "allowed_operations": ["Browse", "Read", "Subscribe", "Publish"],
        }

    def ingest_edge_batch(self, actor: ActorContext, body: Mapping[str, Any]) -> dict[str, Any]:
        gateway_id = str(body["gateway_id"])
        rows = self.store.query(
            "SELECT * FROM edge_gateways WHERE gateway_id=? AND workspace_id=?",
            (gateway_id, actor.workspace_id),
        )
        if not rows:
            raise DomainError("GATEWAY_NOT_FOUND", "edge gateway not found", status=404)
        start, end = int(body["sequence_start"]), int(body["sequence_end"])
        if start > end or start > int(rows[0]["last_sequence"]) + 1:
            raise DomainError("EDGE_SEQUENCE_GAP", "edge batch sequence is invalid", status=409)
        batch_hash = str(body.get("batch_hash", canonical_digest(body.get("events", ()))))
        self.store.execute(
            """INSERT OR IGNORE INTO edge_batches
               (gateway_id, sequence_start, sequence_end, batch_hash, payload, received_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (gateway_id, start, end, batch_hash, json.dumps(body, sort_keys=True), utc_now()),
        )
        self.store.execute(
            """UPDATE edge_gateways
                  SET last_sequence=CASE WHEN last_sequence>? THEN last_sequence ELSE ? END,
                      state='ONLINE', updated_at=?
                WHERE gateway_id=? AND workspace_id=?""",
            (end, end, utc_now(), gateway_id, actor.workspace_id),
        )
        return {
            "gateway_id": gateway_id,
            "accepted": True,
            "sequence_end": end,
            "batch_hash": batch_hash,
        }

    def edge_heartbeat(self, actor: ActorContext, body: Mapping[str, Any]) -> dict[str, Any]:
        gateway_id = str(body["gateway_id"])
        now = utc_now()
        cursor = self.store.execute(
            """UPDATE edge_gateways SET last_heartbeat_at=?, health_json=?, state='ONLINE', updated_at=?
               WHERE gateway_id=? AND workspace_id=?""",
            (
                now,
                json.dumps(redact(body.get("health", {})), sort_keys=True),
                now,
                gateway_id,
                actor.workspace_id,
            ),
        )
        if cursor.rowcount != 1:
            raise DomainError("GATEWAY_NOT_FOUND", "edge gateway not found", status=404)
        return self.edge_health(actor, gateway_id)

    def rotate_edge_identity(
        self, actor: ActorContext, gateway_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        actor.require_role("Admin")
        fingerprint = str(body["certificate_fingerprint"])
        if len(fingerprint.replace(":", "")) < 32:
            raise DomainError(
                "CERTIFICATE_FINGERPRINT_INVALID", "certificate fingerprint is too short"
            )
        cursor = self.store.execute(
            """UPDATE edge_gateways SET certificate_fingerprint=?, identity_digest=?,
                      updated_at=? WHERE gateway_id=? AND workspace_id=?""",
            (
                fingerprint,
                canonical_digest([gateway_id, fingerprint, body.get("public_key")]),
                utc_now(),
                gateway_id,
                actor.workspace_id,
            ),
        )
        if cursor.rowcount != 1:
            raise DomainError("GATEWAY_NOT_FOUND", "edge gateway not found", status=404)
        return self.edge_health(actor, gateway_id)

    def edge_health(self, actor: ActorContext, gateway_id: str) -> dict[str, Any]:
        rows = self.store.query(
            "SELECT * FROM edge_gateways WHERE gateway_id=? AND workspace_id=?",
            (gateway_id, actor.workspace_id),
        )
        if not rows:
            raise DomainError("GATEWAY_NOT_FOUND", "edge gateway not found", status=404)
        row = rows[0]
        row["health"] = json.loads(row.pop("health_json"))
        row.pop("certificate_fingerprint", None)
        return row

    # Identity, audit and administration --------------------------------
    @staticmethod
    def me(actor: ActorContext) -> dict[str, Any]:
        permissions = sorted(
            set().union(*(ROLE_PERMISSIONS.get(role, frozenset()) for role in actor.roles))
        )
        return {
            "actor_id": actor.actor_id,
            "tenant_id": actor.tenant_id,
            "workspace_id": actor.workspace_id,
            "roles": sorted(actor.roles),
            "service": actor.service,
            "permissions": permissions,
        }

    def audit_records(self, actor: ActorContext, limit: int = 100) -> list[dict[str, Any]]:
        authorize(actor, "audit:view")
        if not 1 <= limit <= 500:
            raise DomainError("INVALID_LIMIT", "limit must be within 1..500")
        rows = self.store.query(
            "SELECT * FROM audit_records WHERE workspace_id=? ORDER BY created_at DESC LIMIT ?",
            (actor.workspace_id, limit),
        )
        for row in rows:
            row["details"] = redact(json.loads(row["details"]))
        return rows

    def system_health(self, actor: ActorContext) -> dict[str, Any]:
        actor.require_role("Admin", "Auditor")
        counts = self.store.query(
            """SELECT resource_type, COUNT(*) AS count FROM domain_resources
               WHERE workspace_id=? GROUP BY resource_type""",
            (actor.workspace_id,),
        )
        return {
            "database": database_probe(self.store),
            "resources": {row["resource_type"]: row["count"] for row in counts},
            "status": database_probe(self.store)["status"],
            "write_boundary": "simulator_only",
        }

    def version(self) -> dict[str, Any]:
        probe = database_probe(self.store)
        return {
            "version": __version__,
            "schema_version": probe["migration_version"],
            "python": platform.python_version(),
            "build_digest": self.build_digest,
        }
