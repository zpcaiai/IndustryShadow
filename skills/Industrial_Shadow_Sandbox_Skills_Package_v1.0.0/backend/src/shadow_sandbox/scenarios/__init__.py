from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from shadow_sandbox.common import ActorContext, DomainError, EventEnvelope, Store
from shadow_sandbox.common.models import canonical_digest, validate_identifier

ALLOWED_OPERATORS = {
    "bias",
    "drift",
    "stuck_at",
    "noise_increase",
    "spike",
    "delay",
    "dropout",
    "reorder",
    "duplicate",
    "bad_quality",
    "multiplier",
    "ramp",
    "intermittent",
    "stiction",
    "blockage",
    "leak",
    "friction_increase",
    "heater_stuck",
}
FORBIDDEN_KEYS = {"gold", "gold_spec", "root_causes", "expected_symptoms", "forbidden_actions"}


@dataclass(frozen=True, slots=True)
class ClockSpec:
    duration_seconds: float
    warmup_seconds: float = 0
    step_ms: int = 100
    speed: int = 1


@dataclass(frozen=True, slots=True)
class FaultInjection:
    target: str
    operator: str
    parameters: Mapping[str, Any]
    duration_seconds: float | None = None
    combination: str = "reject"


@dataclass(frozen=True, slots=True)
class TimelineItem:
    at: float
    kind: str
    target: str | None = None
    value: Any = None
    fault: FaultInjection | None = None
    merge_policy: str | None = None


@dataclass(frozen=True, slots=True)
class ScenarioSpec:
    scenario_id: str
    scenario_version: int
    process_model_ref: str
    asset_model_ref: str
    seed: int
    clock: ClockSpec
    operating_profile: Mapping[str, Any]
    timeline: tuple[TimelineItem, ...]
    tags: tuple[str, ...] = ()
    schema_version: int = 1
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


def _walk_keys(value: Any, depth: int = 0) -> None:
    if depth > 20:
        raise DomainError("DOCUMENT_TOO_DEEP", "scenario nesting exceeds 20 levels")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in FORBIDDEN_KEYS:
                raise DomainError(
                    "GOLD_FIELD_FORBIDDEN", "Gold fields are forbidden in Scenario Spec"
                )
            _walk_keys(child, depth + 1)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            _walk_keys(child, depth + 1)


def parse_document(text: str) -> Mapping[str, Any]:
    if len(text.encode("utf-8")) > 1_000_000:
        raise DomainError("DOCUMENT_TOO_LARGE", "scenario document exceeds 1 MiB")
    if "!!" in text or "&" in text or "*" in text:
        raise DomainError("UNSAFE_YAML", "YAML tags, anchors, and aliases are forbidden")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:
            raise DomainError(
                "YAML_DEPENDENCY_UNAVAILABLE",
                "install PyYAML or submit canonical JSON",
                status=503,
            ) from exc
        value = yaml.safe_load(text)
    if not isinstance(value, Mapping):
        raise DomainError("INVALID_DOCUMENT", "scenario document must be an object")
    _walk_keys(value)
    return value


def scenario_from_mapping(data: Mapping[str, Any]) -> ScenarioSpec:
    allowed = {
        "schema_version",
        "scenario_id",
        "scenario_version",
        "process_model_ref",
        "asset_model_ref",
        "seed",
        "clock",
        "operating_profile",
        "timeline",
        "tags",
        "metadata",
    }
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise DomainError("UNKNOWN_FIELDS", "scenario contains unknown fields", {"fields": unknown})
    if data.get("schema_version", 1) != 1:
        raise DomainError("UNSUPPORTED_SCHEMA", "only Scenario Schema v1 is supported")
    clock = ClockSpec(**dict(data["clock"]))
    timeline: list[TimelineItem] = []
    for raw in data.get("timeline", []):
        item = dict(raw)
        fault = None
        if "inject" in item:
            injection = dict(item.pop("inject"))
            parameters = dict(injection.pop("parameters", {}))
            for key in tuple(injection):
                if key not in {"target", "operator", "duration_seconds", "combination"}:
                    parameters[key] = injection.pop(key)
            fault = FaultInjection(parameters=parameters, **injection)
            item["kind"] = "fault"
        timeline.append(TimelineItem(fault=fault, **item))
    return ScenarioSpec(
        scenario_id=str(data["scenario_id"]),
        scenario_version=int(data["scenario_version"]),
        process_model_ref=str(data["process_model_ref"]),
        asset_model_ref=str(data["asset_model_ref"]),
        seed=int(data["seed"]),
        clock=clock,
        operating_profile=dict(data.get("operating_profile", {})),
        timeline=tuple(timeline),
        tags=tuple(data.get("tags", ())),
        schema_version=1,
        metadata=dict(data.get("metadata", {})),
    )


def validate_scenario(spec: ScenarioSpec, signal_keys: set[str]) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    try:
        validate_identifier(spec.scenario_id, "scenario_id")
    except DomainError:
        errors.append({"code": "INVALID_SCENARIO_ID", "pointer": "/scenario_id"})
    if spec.scenario_version <= 0:
        errors.append({"code": "INVALID_VERSION", "pointer": "/scenario_version"})
    if spec.clock.duration_seconds <= 0 or spec.clock.warmup_seconds < 0:
        errors.append({"code": "INVALID_CLOCK", "pointer": "/clock"})
    if spec.clock.warmup_seconds >= spec.clock.duration_seconds:
        errors.append({"code": "WARMUP_EXCEEDS_DURATION", "pointer": "/clock/warmup_seconds"})
    if spec.clock.step_ms <= 0 or 1000 % spec.clock.step_ms:
        errors.append({"code": "INVALID_STEP", "pointer": "/clock/step_ms"})
    previous = -1.0
    active_targets: dict[tuple[float, str], int] = {}
    for index, item in enumerate(spec.timeline):
        pointer = f"/timeline/{index}"
        if item.at < previous:
            errors.append({"code": "TIMELINE_NOT_ORDERED", "pointer": pointer + "/at"})
        previous = item.at
        if item.at < 0 or item.at > spec.clock.duration_seconds:
            errors.append({"code": "TIME_OUT_OF_RANGE", "pointer": pointer + "/at"})
        target = item.fault.target if item.fault else item.target
        if target and target not in signal_keys and not target.startswith("Process."):
            errors.append({"code": "UNKNOWN_TARGET", "pointer": pointer + "/target"})
        if item.fault:
            if item.fault.operator not in ALLOWED_OPERATORS:
                errors.append({"code": "UNKNOWN_OPERATOR", "pointer": pointer + "/operator"})
            key = (item.at, item.fault.target)
            if key in active_targets and not item.merge_policy:
                errors.append({"code": "MERGE_POLICY_REQUIRED", "pointer": pointer})
            active_targets[key] = index
    return errors


class ScenarioService:
    def __init__(self, store: Store) -> None:
        self.store = store

    def publish(self, actor: ActorContext, spec: ScenarioSpec, signal_keys: set[str]) -> str:
        actor.require_role("Engineer", "PackAuthor", "Admin")
        errors = validate_scenario(spec, signal_keys)
        if errors:
            raise DomainError("SCENARIO_INVALID", "scenario validation failed", {"errors": errors})
        digest = self.store.put_artifact(
            kind="scenario",
            artifact_id=spec.scenario_id,
            workspace_id=actor.workspace_id,
            version=spec.scenario_version,
            payload=asdict(spec),
            sealed=True,
        )
        self.store.append_event(
            EventEnvelope(
                "scenario.published.v1",
                {
                    "scenario_id": spec.scenario_id,
                    "version": spec.scenario_version,
                    "digest": digest,
                },
                actor.tenant_id,
                actor.workspace_id,
                trace_id=actor.trace_id,
            )
        )
        return digest


@dataclass(frozen=True, slots=True)
class EpisodeManifest:
    episode_id: str
    scenario_ref: str
    split: str
    fault_type: str | None
    severity: str | None
    load: str
    seed: int

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


def expand_mvp_benchmark() -> tuple[EpisodeManifest, ...]:
    episodes: list[EpisodeManifest] = []
    for fault_number in range(1, 11):
        for severity in ("low", "medium", "high"):
            for load in ("low", "nominal", "high"):
                # Cover every severity/load cell while retaining the reviewed
                # 120-fault/54-normal exact corpus. Nominal receives the extra
                # repeat seed because it is the release reference condition.
                for seed in ((11, 29) if load == "nominal" else (11,)):
                    data = {
                        "scenario_ref": f"F{fault_number:02d}@1",
                        "fault_type": f"F{fault_number:02d}",
                        "severity": severity,
                        "load": load,
                        "seed": seed,
                        "split": "certification",
                    }
                    episodes.append(EpisodeManifest("ep_" + canonical_digest(data)[:24], **data))
    for normal in (
        "startup",
        "shutdown",
        "load-step",
        "valve-step",
        "heater-cycle",
        "network-jitter",
    ):
        for load in ("low", "nominal", "high"):
            for seed in (3, 17, 41):
                data = {
                    "scenario_ref": f"N-{normal}@1",
                    "fault_type": None,
                    "severity": None,
                    "load": load,
                    "seed": seed,
                    "split": "certification",
                }
                episodes.append(EpisodeManifest("ep_" + canonical_digest(data)[:24], **data))
    if len({episode.episode_id for episode in episodes}) != len(episodes):
        raise AssertionError("benchmark contains duplicate episodes")
    return tuple(episodes)
