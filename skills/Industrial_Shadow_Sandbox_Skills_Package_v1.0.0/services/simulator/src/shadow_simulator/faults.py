from __future__ import annotations

import copy
import random
from collections.abc import Mapping, MutableMapping
from dataclasses import asdict, dataclass, field, replace
from typing import Any

from shadow_sandbox.common.models import DomainError, canonical_digest

from .model import ProcessCommand, StateFrame

SENSOR_OPERATORS = {
    "bias",
    "drift",
    "stuck_at",
    "noise_increase",
    "spike",
    "bad_quality",
}
COMMUNICATION_OPERATORS = {"delay", "dropout", "reorder", "duplicate"}
PHYSICAL_OPERATORS = {
    "multiplier",
    "ramp",
    "stiction",
    "blockage",
    "leak",
    "friction_increase",
    "heater_stuck",
}


@dataclass(frozen=True, slots=True)
class FaultSpec:
    fault_id: str
    target: str
    operator: str
    start: float
    duration: float | None
    parameters: Mapping[str, Any]
    severity: str = "medium"
    combination: str = "reject"

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(slots=True)
class ActiveFault:
    spec: FaultSpec
    internal: dict[str, Any] = field(default_factory=dict)
    affected_frames: int = 0


class FaultRuntime:
    def __init__(self, specs: list[FaultSpec] | None = None) -> None:
        self.specs = sorted(specs or [], key=lambda spec: (spec.start, spec.fault_id))
        self.active: dict[str, ActiveFault] = {}
        self.delayed: list[tuple[float, StateFrame]] = []
        self.reorder_buffer: StateFrame | None = None
        self.metrics = {
            "activated": 0,
            "cleared": 0,
            "affected_frames": 0,
            "rejected": 0,
        }
        self._validate()

    def _validate(self) -> None:
        seen: dict[tuple[float, str], FaultSpec] = {}
        allowed = (
            SENSOR_OPERATORS
            | COMMUNICATION_OPERATORS
            | PHYSICAL_OPERATORS
            | {"intermittent"}
        )
        for spec in self.specs:
            if spec.operator not in allowed:
                self.metrics["rejected"] += 1
                raise DomainError("UNKNOWN_FAULT_OPERATOR", spec.operator)
            if spec.start < 0 or (spec.duration is not None and spec.duration <= 0):
                raise DomainError(
                    "INVALID_FAULT_TIME", "fault time must be non-negative"
                )
            key = (spec.start, spec.target)
            if key in seen and spec.combination == "reject":
                raise DomainError(
                    "FAULT_CONFLICT", f"conflicting faults for {spec.target}"
                )
            seen[key] = spec
            if any(
                key in spec.parameters
                for key in ("code", "script", "path", "url", "import", "expression")
            ):
                raise DomainError(
                    "UNSAFE_FAULT_SPEC", "executable fault parameters are forbidden"
                )

    def _refresh(self, now: float) -> None:
        for spec in self.specs:
            end = spec.start + spec.duration if spec.duration is not None else None
            should = spec.start <= now and (end is None or now < end)
            if should and spec.fault_id not in self.active:
                self.active[spec.fault_id] = ActiveFault(spec)
                self.metrics["activated"] += 1
            if not should and spec.fault_id in self.active:
                del self.active[spec.fault_id]
                self.metrics["cleared"] += 1

    def mutate_command(self, now: float, command: ProcessCommand) -> ProcessCommand:
        self._refresh(now)
        result = command
        for active in self.active.values():
            spec = active.spec
            if spec.operator != "stiction":
                continue
            deadband = float(spec.parameters.get("deadband", 10.0))
            field_name = {
                "Valve101.PositionCommand": "inlet_valve_percent",
                "Valve102.PositionCommand": "outlet_valve_percent",
            }.get(spec.target)
            if not field_name:
                continue
            current = getattr(result, field_name)
            held = float(active.internal.setdefault("held", current))
            if abs(current - held) < deadband:
                result = replace(result, **{field_name: held})
            else:
                active.internal["held"] = current
            active.affected_frames += 1
        return result

    def physical_factors(self, now: float) -> dict[str, float]:
        self._refresh(now)
        factors: dict[str, float] = {}
        for active in self.active.values():
            spec = active.spec
            elapsed = max(0.0, now - spec.start)
            if (
                spec.operator == "multiplier"
                and spec.target == "Process.PumpEfficiency"
            ):
                factors["pump_efficiency"] = float(spec.parameters.get("value", 0.6))
            elif spec.operator == "ramp" and spec.target == "Process.PumpEfficiency":
                start = float(spec.parameters.get("from", 1.0))
                target = float(
                    spec.parameters.get("to", spec.parameters.get("value", 0.6))
                )
                duration = float(
                    spec.parameters.get("ramp_seconds", spec.duration or 1.0)
                )
                factors["pump_efficiency"] = start + min(1.0, elapsed / duration) * (
                    target - start
                )
            elif spec.operator == "blockage":
                factors["outlet_blockage"] = float(spec.parameters.get("fraction", 0.5))
            elif spec.operator == "leak":
                factors["tank_leak_m3s"] = float(spec.parameters.get("flow_m3s", 0.01))
            elif spec.operator == "friction_increase":
                factors["bearing_friction"] = float(
                    spec.parameters.get("fraction", 0.5)
                )
            elif spec.operator == "heater_stuck":
                factors["heater_stuck"] = float(spec.parameters.get("power_kw", 80.0))
            active.affected_frames += 1
        return factors

    def mutate_observed(
        self,
        now: float,
        values: MutableMapping[str, float | str],
        quality: MutableMapping[str, str],
        rng: random.Random,
    ) -> tuple[dict[str, float | str], dict[str, str]]:
        self._refresh(now)
        result = copy.deepcopy(dict(values))
        quality_result = dict(quality)
        for active in self.active.values():
            spec = active.spec
            if spec.operator not in SENSOR_OPERATORS or spec.target not in result:
                continue
            value = result[spec.target]
            if not isinstance(value, (int, float)):
                continue
            elapsed = max(0.0, now - spec.start)
            if spec.operator == "bias":
                result[spec.target] = float(value) + float(
                    spec.parameters.get("value", 1.0)
                )
            elif spec.operator == "drift":
                result[spec.target] = float(value) + elapsed * float(
                    spec.parameters.get("per_second", 0.01)
                )
            elif spec.operator == "stuck_at":
                result[spec.target] = float(
                    active.internal.setdefault(
                        "value", spec.parameters.get("value", value)
                    )
                )
            elif spec.operator == "noise_increase":
                result[spec.target] = float(value) + rng.gauss(
                    0, float(spec.parameters.get("sigma", 1.0))
                )
            elif spec.operator == "spike":
                every = max(1, int(spec.parameters.get("every_frames", 20)))
                if active.affected_frames % every == 0:
                    result[spec.target] = float(value) + float(
                        spec.parameters.get("magnitude", 10.0)
                    )
            elif spec.operator == "bad_quality":
                quality_result[spec.target] = str(spec.parameters.get("status", "Bad"))
            active.affected_frames += 1
            self.metrics["affected_frames"] += 1
        return result, quality_result

    def deliver(self, now: float, frame: StateFrame) -> list[StateFrame]:
        self._refresh(now)
        delivered: list[StateFrame] = []
        for ready_at, delayed_frame in tuple(self.delayed):
            if ready_at <= now:
                delivered.append(delayed_frame)
                self.delayed.remove((ready_at, delayed_frame))
        current: list[StateFrame] = [frame]
        for active in self.active.values():
            spec = active.spec
            if spec.operator not in COMMUNICATION_OPERATORS:
                continue
            if spec.operator == "dropout":
                every = max(1, int(spec.parameters.get("every_frames", 5)))
                if frame.source_sequence % every == 0:
                    current = []
            elif spec.operator == "delay":
                delay = float(spec.parameters.get("seconds", 1.0))
                self.delayed.extend((now + delay, item) for item in current)
                current = []
            elif spec.operator == "duplicate":
                current = current + [replace(item) for item in current]
            elif spec.operator == "reorder":
                if self.reorder_buffer is None and current:
                    self.reorder_buffer = current[0]
                    current = []
                elif self.reorder_buffer is not None and current:
                    current = current + [self.reorder_buffer]
                    self.reorder_buffer = None
            active.affected_frames += 1
        return delivered + current

    def clear(self, fault_id: str) -> None:
        self.specs = [spec for spec in self.specs if spec.fault_id != fault_id]
        if fault_id in self.active:
            del self.active[fault_id]
            self.metrics["cleared"] += 1

    def snapshot_state(self) -> dict[str, Any]:
        return {
            "specs": [asdict(spec) for spec in self.specs],
            "active": {
                key: {
                    "internal": value.internal,
                    "affected_frames": value.affected_frames,
                }
                for key, value in self.active.items()
            },
            "metrics": dict(self.metrics),
        }

    def restore_state(self, state: Mapping[str, Any]) -> None:
        self.specs = [FaultSpec(**item) for item in state.get("specs", [])]
        self.active = {}
        by_id = {spec.fault_id: spec for spec in self.specs}
        for fault_id, value in state.get("active", {}).items():
            self.active[fault_id] = ActiveFault(
                by_id[fault_id], dict(value["internal"]), int(value["affected_frames"])
            )
        self.metrics = dict(state.get("metrics", self.metrics))
