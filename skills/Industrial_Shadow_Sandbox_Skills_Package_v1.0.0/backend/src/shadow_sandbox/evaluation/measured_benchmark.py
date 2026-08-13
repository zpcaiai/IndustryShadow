from __future__ import annotations

import json
import math
import platform
import statistics
import time
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from shadow_sandbox.asset_registry import pump_tank_model
from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now
from shadow_sandbox.evaluation.metrics.entities import EpisodeEvaluationInput
from shadow_sandbox.evaluation.metrics.evaluator import Evaluator
from shadow_sandbox.evaluation.metrics.gate import ReleaseGate
from shadow_sandbox.operations.evidence import GateCheck, GateEvidence, complete
from shadow_sandbox.scenarios import EpisodeManifest, expand_mvp_benchmark


@dataclass(frozen=True, slots=True)
class ObservedEpisode:
    frame_digest: str
    delivered_frames: int
    source_frames: int
    values: Mapping[str, tuple[float, ...]]
    quality_failures: int


@dataclass(frozen=True, slots=True)
class BenchmarkSummary:
    suite_digest: str
    result_digest: str
    episode_count: int
    fault_episodes: int
    normal_episodes: int
    elapsed_seconds: float
    episode_p95_ms: float
    evaluation: Mapping[str, Any]
    gate: Mapping[str, Any]
    runner: str


def _mean(values: Sequence[float]) -> float:
    return statistics.fmean(values) if values else 0.0


def _stdev(values: Sequence[float]) -> float:
    return statistics.pstdev(values) if len(values) > 1 else 0.0


def _paired_difference(first: Sequence[float], second: Sequence[float]) -> tuple[float, ...]:
    return tuple(left - right for left, right in zip(first, second, strict=False))


def _response(values: Sequence[float]) -> float:
    if len(values) < 20:
        return 0.0
    split = len(values) // 2
    return _mean(values[split:]) - _mean(values[:split])


class SignatureDiagnoser:
    """Deterministic rules consume observations and a same-profile healthy baseline only."""

    VERSION = "pump-tank-signature-v1"

    def diagnose(self, observed: ObservedEpisode, baseline: ObservedEpisode) -> tuple[str, ...]:
        def mean_delta(signal: str) -> float:
            return abs(
                _mean(observed.values.get(signal, ())) - _mean(baseline.values.get(signal, ()))
            )

        pressure_diff = _paired_difference(
            observed.values.get("Tank101.Pressure", ()),
            baseline.values.get("Tank101.Pressure", ()),
        )
        delivery_ratio = observed.delivered_frames / max(observed.source_frames, 1)
        inlet_observed = observed.values.get("Tank101.InletFlow", ())
        inlet_baseline = baseline.values.get("Tank101.InletFlow", ())
        inlet_response_gap = abs(_response(inlet_observed) - _response(inlet_baseline))

        if delivery_ratio < 0.95:
            return ("communication_failure",)
        if _stdev(pressure_diff) > 250.0:
            return ("pressure_sensor_noise",)
        if mean_delta("Pump101.Vibration") > 0.25 and mean_delta("Pump101.Current") > 0.5:
            return ("bearing_friction",)
        if mean_delta("Heater101.PowerActual") > 3.0:
            return ("heater_stuck",)
        if mean_delta("Valve101.PositionActual") > 0.8:
            return ("inlet_valve_stiction",)
        if mean_delta("Tank101.OutletFlow") > 0.0008:
            return ("outlet_blockage",)
        if mean_delta("Tank101.Level") > 0.15 and mean_delta("Tank101.Pressure") < 100.0:
            return ("sensor_bias",)
        if (
            inlet_response_gap > 0.0008
            and _stdev(inlet_observed) < _stdev(inlet_baseline) * 0.65
            and mean_delta("Pump101.Current") < 0.1
        ):
            return ("flow_sensor_stuck",)
        if mean_delta("Tank101.InletFlow") > 0.0007 and mean_delta("Pump101.Current") > 0.15:
            return ("pump_efficiency_loss",)
        if mean_delta("Tank101.Level") > 0.002 and mean_delta("Tank101.Pressure") > 10.0:
            return ("tank_leak",)
        return ()


class MeasuredBenchmark:
    """Execute a local diagnostic benchmark; formal target certification is imported separately."""

    def __init__(self, package_root: str | Path) -> None:
        self.root = Path(package_root)
        self.catalog_path = self.root / "domain-packs/pump-tank-v1/faults/catalog.json"
        self.suite_path = (
            self.root / "domain-packs/pump-tank-v1/scenarios/suites/mvp-benchmark.json"
        )
        self.catalog = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        self.catalog_by_id = {item["id"]: item for item in self.catalog["faults"]}
        if len(self.catalog_by_id) != 10:
            raise DomainError("BENCHMARK_CATALOG_INVALID", "benchmark requires ten fault types")
        self.diagnoser = SignatureDiagnoser()

    @staticmethod
    def _severity_parameters(fault: Mapping[str, Any], severity: str) -> dict[str, Any]:
        levels = {"low": 0, "medium": 1, "high": 2}
        index = levels[severity]
        parameters = dict(fault.get("parameters", {}))
        overrides: dict[str, Sequence[float | int]] = {
            "F01:value": (0.5, 1.0, 2.0),
            "F03:sigma": (1000.0, 3000.0, 6000.0),
            "F04:deadband": (10.0, 16.0, 25.0),
            "F05:to": (0.8, 0.6, 0.4),
            "F06:fraction": (0.2, 0.5, 0.8),
            "F07:fraction": (0.2, 0.5, 0.8),
            "F08:flow_m3s": (0.003, 0.008, 0.015),
            "F09:power_kw": (55.0, 75.0, 95.0),
            "F10:every_frames": (10, 5, 3),
        }
        for compound, values in overrides.items():
            fault_id, key = compound.split(":", 1)
            if fault["id"] == fault_id:
                parameters[key] = values[index]
        if fault["id"] == "F05":
            parameters["ramp_seconds"] = 3.0
        return parameters

    @staticmethod
    def _command(load: str, simulation_time: float) -> Any:
        try:
            from shadow_simulator.model import ProcessCommand
        except ImportError as error:
            raise DomainError(
                "SIMULATOR_DEPENDENCY_UNAVAILABLE", "simulator package is required", status=503
            ) from error
        speed = {"low": 1800.0, "nominal": 2400.0, "high": 3000.0}[load]
        if simulation_time < 5.0:
            return ProcessCommand(speed, 85.0, 60.0, 25.0)
        return ProcessCommand(speed, 77.0, 68.0, 35.0)

    def _execute(
        self, episode: EpisodeManifest, fault: Mapping[str, Any] | None
    ) -> ObservedEpisode:
        from shadow_simulator.faults import FaultRuntime, FaultSpec
        from shadow_simulator.model import SimulatorEngine

        specs = []
        if fault is not None:
            specs.append(
                FaultSpec(
                    fault_id=str(fault["id"]),
                    target=str(fault["target"]),
                    operator=str(fault["operator"]),
                    start=2.0,
                    duration=None,
                    parameters=self._severity_parameters(fault, episode.severity or "medium"),
                    severity=episode.severity or "medium",
                )
            )
        runtime = FaultRuntime(specs)
        engine = SimulatorEngine(
            asset_model_digest=pump_tank_model().digest,
            seed=episode.seed,
            step_ms=100,
            simulator_build_digest="measured-benchmark-v1",
            fault_runtime=runtime,
        )
        values: dict[str, list[float]] = {}
        quality_failures = 0
        frame_digests: list[str] = []
        delivered_frames = 0
        for _index in range(120):
            frame = engine.step(self._command(episode.load, engine.simulation_time))
            for delivered in engine.deliver(frame):
                delivered_frames += 1
                frame_digests.append(delivered.frame_digest)
                for key, value in delivered.observed_values.items():
                    if isinstance(value, (int, float)) and math.isfinite(float(value)):
                        values.setdefault(key, []).append(float(value))
                quality_failures += sum(status != "Good" for status in delivered.quality.values())
        return ObservedEpisode(
            canonical_digest(frame_digests),
            delivered_frames,
            engine.sequence,
            {key: tuple(items) for key, items in values.items()},
            quality_failures,
        )

    def run(self) -> tuple[GateEvidence, BenchmarkSummary]:
        started_at = utc_now()
        started_clock = time.perf_counter()
        episodes = expand_mvp_benchmark()
        evaluation_inputs: list[EpisodeEvaluationInput] = []
        timings: list[float] = []
        outcome_records: list[Mapping[str, Any]] = []
        for episode in episodes:
            episode_started = time.perf_counter()
            baseline = self._execute(episode, None)
            fault = self.catalog_by_id.get(episode.fault_type or "")
            observed = baseline if fault is None else self._execute(episode, fault)
            replay = baseline if fault is None else self._execute(episode, fault)
            ranked = self.diagnoser.diagnose(observed, baseline)
            expected = () if fault is None else (str(fault["cause"]),)
            replay_match = replay.frame_digest == observed.frame_digest
            evaluation_inputs.append(
                EpisodeEvaluationInput(
                    episode.episode_id,
                    fault is None,
                    expected,
                    ranked,
                    bool(ranked),
                    1.0 if fault is None or ranked == expected else 0.0,
                    False,
                    0,
                    0,
                    0,
                    0,
                    replay_match,
                    True,
                    True,
                    {
                        "fault": episode.fault_type or "normal",
                        "severity": episode.severity or "normal",
                        "load": episode.load,
                    },
                )
            )
            outcome_records.append(
                {
                    "episode_id": episode.episode_id,
                    "observation_digest": observed.frame_digest,
                    "ranked_digest": canonical_digest(ranked),
                    "detected": bool(ranked),
                    "replay_match": replay_match,
                }
            )
            timings.append((time.perf_counter() - episode_started) * 1000)
        evaluation = Evaluator().evaluate("measured-benchmark-v1", tuple(evaluation_inputs))
        bundle_digest = canonical_digest(
            [
                self.catalog_path.read_text(encoding="utf-8"),
                self.suite_path.read_text(encoding="utf-8"),
                self.diagnoser.VERSION,
                pump_tank_model().digest,
            ]
        )
        gate = ReleaseGate().evaluate("measured-benchmark-gate-v1", bundle_digest, evaluation)
        elapsed = time.perf_counter() - started_clock
        p95 = sorted(timings)[math.ceil(len(timings) * 0.95) - 1]
        result_digest = canonical_digest(outcome_records)
        summary = BenchmarkSummary(
            canonical_digest([asdict(item) for item in episodes]),
            result_digest,
            len(episodes),
            sum(item.fault_type is not None for item in episodes),
            sum(item.fault_type is None for item in episodes),
            elapsed,
            p95,
            asdict(evaluation),
            asdict(gate),
            f"{platform.system()}-{platform.machine()}-{platform.python_version()}",
        )
        checks = (
            GateCheck("episode_count", len(episodes) >= 150),
            GateCheck("fault_count", evaluation.metrics["fault_episodes"] >= 100),
            GateCheck("normal_count", evaluation.metrics["normal_episodes"] >= 50),
            GateCheck("all_replays_match", evaluation.metrics["deterministic_replay_rate"] == 1.0),
            GateCheck("safety_red_lines", not any(evaluation.red_lines.values())),
            GateCheck("release_gate", gate.passed, {"reason_count": len(gate.reasons)}),
        )
        evidence = complete(
            "benchmark_local",
            started_at=started_at,
            coordinates={
                "suite_digest": summary.suite_digest,
                "bundle_digest": bundle_digest,
                "result_digest": result_digest,
            },
            checks=checks,
            metrics={
                **{key: round(value, 6) for key, value in evaluation.metrics.items()},
                **evaluation.red_lines,
                "episodes": len(episodes),
                "elapsed_seconds": round(elapsed, 3),
                "episode_p95_ms": round(p95, 3),
            },
            limitations=(
                "measured_against_the_bundled_deterministic_pump_tank_model_only",
                "not_real_site_diagnosis_certification",
            ),
        )
        return evidence, summary
