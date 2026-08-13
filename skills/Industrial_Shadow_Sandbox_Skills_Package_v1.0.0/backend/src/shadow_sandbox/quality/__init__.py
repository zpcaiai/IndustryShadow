from __future__ import annotations

import statistics
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from shadow_sandbox.common.models import canonical_digest


class QualityState(StrEnum):
    TRUSTED = "TRUSTED"
    DEGRADED = "DEGRADED"
    UNTRUSTED = "UNTRUSTED"


@dataclass(frozen=True, slots=True)
class QualityWindow:
    run_id: str
    signal_key: str
    start: str
    end: str
    sample_count: int
    expected_count: int
    missing_ratio: float
    duplicate_ratio: float
    reorder_ratio: float
    bad_status_ratio: float
    flatline: bool
    issues: tuple[str, ...]
    state: QualityState
    source_event_refs: tuple[str, ...]
    policy_digest: str

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class AnomalyObservation:
    run_id: str
    signal_key: str
    detector_ref: str
    statistic: float
    baseline: float
    threshold: float
    direction: str
    severity: float
    quality_state: QualityState
    source_event_refs: tuple[str, ...]
    observation_code: str

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


class QualityService:
    def __init__(self, missing_degraded: float = 0.05, missing_untrusted: float = 0.25) -> None:
        self.policy = {
            "missing_degraded": missing_degraded,
            "missing_untrusted": missing_untrusted,
            "bad_untrusted": 0.2,
            "flatline_min_samples": 5,
        }
        self.policy_digest = canonical_digest(self.policy)

    def assess(
        self,
        events: Sequence[Any],
        expected_count: int,
    ) -> QualityWindow:
        if not events:
            return QualityWindow(
                "unknown",
                "unknown",
                "",
                "",
                0,
                expected_count,
                1.0,
                0,
                0,
                1.0,
                True,
                ("no_data",),
                QualityState.UNTRUSTED,
                (),
                self.policy_digest,
            )
        missing = max(0, expected_count - len(events)) / max(expected_count, 1)
        duplicate = sum("duplicate" in event.flags for event in events) / len(events)
        reorder = sum("reordered" in event.flags for event in events) / len(events)
        bad = sum(event.status_code not in {"Good", "GoodLocalOverride"} for event in events) / len(
            events
        )
        numeric = [float(event.value) for event in events if isinstance(event.value, (int, float))]
        flatline = len(numeric) >= self.policy["flatline_min_samples"] and max(numeric) == min(
            numeric
        )
        issues: list[str] = []
        if missing > 0:
            issues.append("missing")
        if duplicate > 0:
            issues.append("duplicate")
        if reorder > 0:
            issues.append("reorder")
        if bad > 0:
            issues.append("bad_status")
        if flatline:
            issues.append("flatline")
        if any("clock_future" in event.flags for event in events):
            issues.append("clock_skew")
        if missing >= self.policy["missing_untrusted"] or bad >= self.policy["bad_untrusted"]:
            state = QualityState.UNTRUSTED
        elif issues and (
            missing >= self.policy["missing_degraded"] or duplicate or reorder or flatline
        ):
            state = QualityState.DEGRADED
        else:
            state = QualityState.TRUSTED
        return QualityWindow(
            events[0].run_id,
            events[0].signal_key,
            events[0].source_timestamp,
            events[-1].source_timestamp,
            len(events),
            expected_count,
            round(missing, 6),
            round(duplicate, 6),
            round(reorder, 6),
            round(bad, 6),
            flatline,
            tuple(issues),
            state,
            tuple(event.logical_id for event in events),
            self.policy_digest,
        )


class UnivariateDetector:
    def __init__(self, detector_ref: str = "robust-univariate@1") -> None:
        self.detector_ref = detector_ref

    def detect(
        self,
        quality: QualityWindow,
        values: Sequence[float],
        baseline_values: Sequence[float],
        mode: str = "steady",
    ) -> tuple[AnomalyObservation, ...]:
        if quality.state == QualityState.UNTRUSTED or len(values) < 3 or len(baseline_values) < 3:
            return ()
        baseline = statistics.median(baseline_values)
        deviations = [abs(value - baseline) for value in baseline_values]
        mad = statistics.median(deviations) or max(abs(baseline) * 0.01, 1e-9)
        current = statistics.median(values)
        robust_z = 0.6745 * (current - baseline) / mad
        transition_factor = 2.0 if mode in {"startup", "shutdown", "load_step"} else 1.0
        threshold = 3.5 * transition_factor
        results: list[AnomalyObservation] = []
        if abs(robust_z) > threshold:
            results.append(
                AnomalyObservation(
                    quality.run_id,
                    quality.signal_key,
                    self.detector_ref,
                    robust_z,
                    baseline,
                    threshold,
                    "high" if robust_z > 0 else "low",
                    min(1.0, (abs(robust_z) - threshold) / threshold),
                    quality.state,
                    quality.source_event_refs,
                    "robust_z_deviation",
                )
            )
        slope = (values[-1] - values[0]) / max(len(values) - 1, 1)
        baseline_scale = mad * 0.25 * transition_factor
        if abs(slope) > baseline_scale:
            results.append(
                AnomalyObservation(
                    quality.run_id,
                    quality.signal_key,
                    "slope@1",
                    slope,
                    0.0,
                    baseline_scale,
                    "rising" if slope > 0 else "falling",
                    min(1.0, abs(slope) / max(baseline_scale * 4, 1e-9)),
                    quality.state,
                    quality.source_event_refs,
                    "slope_change",
                )
            )
        return tuple(results)
