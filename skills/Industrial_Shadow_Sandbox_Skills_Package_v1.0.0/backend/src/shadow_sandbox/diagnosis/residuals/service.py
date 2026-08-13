from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import ClassVar

from shadow_sandbox.common.models import canonical_digest

from .entities import ResidualObservation


class ResidualEngine:
    FORMULAS: ClassVar[Mapping[str, str]] = {
        "mass_balance": "area*dlevel_dt-(qin-qout)",
        "thermal_balance": "capacity*dtemp_dt-(power-loss+mixing)",
        "pump_performance": "qin-max_flow*speed_fraction*valve_fraction",
        "command_response": "actual-command",
        "current_load": "current-(base+gain*speed_fraction)",
        "vibration_mechanical": "vibration-(base+gain*speed_fraction)",
    }

    def __init__(self, tolerances: Mapping[str, float] | None = None) -> None:
        self.tolerances = dict(
            tolerances
            or {
                "mass_balance": 0.01,
                "thermal_balance": 2500.0,
                "pump_performance": 0.01,
                "command_response": 5.0,
                "current_load": 3.0,
                "vibration_mechanical": 1.0,
            }
        )

    def _result(
        self,
        run_id: str,
        ref: str,
        observed: float | None,
        expected: float | None,
        quality: str,
        sources: tuple[str, ...],
        units: str,
    ) -> ResidualObservation:
        digest = canonical_digest([self.FORMULAS[ref], self.tolerances[ref]])
        if quality == "UNTRUSTED" or observed is None or expected is None:
            return ResidualObservation(
                run_id, ref, None, None, None, None, None, "UNTRUSTED", (), sources, units, digest
            )
        residual = observed - expected
        return ResidualObservation(
            run_id,
            ref,
            observed,
            expected,
            residual,
            abs(residual) / max(self.tolerances[ref], 1e-12),
            "positive" if residual > 0 else "negative" if residual < 0 else "zero",
            "APPLICABLE",
            (),
            sources,
            units,
            digest,
        )

    def mass_balance(
        self,
        run_id: str,
        level: Sequence[float],
        qin: Sequence[float],
        qout: Sequence[float],
        step_s: float,
        area_m2: float,
        quality: str,
        sources: tuple[str, ...] = (),
    ) -> ResidualObservation:
        if min(len(level), len(qin), len(qout)) < 2:
            return self._result(run_id, "mass_balance", None, None, "UNTRUSTED", sources, "m3/s")
        observed = area_m2 * (level[-1] - level[0]) / (step_s * (len(level) - 1))
        expected = sum(qin) / len(qin) - sum(qout) / len(qout)
        return self._result(run_id, "mass_balance", observed, expected, quality, sources, "m3/s")

    def thermal_balance(
        self,
        run_id: str,
        temperature: Sequence[float],
        heater_kw: Sequence[float],
        step_s: float,
        capacity: float,
        heat_loss: float,
        ambient: float,
        quality: str,
        sources: tuple[str, ...] = (),
    ) -> ResidualObservation:
        if min(len(temperature), len(heater_kw)) < 2:
            return self._result(run_id, "thermal_balance", None, None, "UNTRUSTED", sources, "W")
        observed = capacity * (temperature[-1] - temperature[0]) / (step_s * (len(temperature) - 1))
        expected = sum(heater_kw) / len(heater_kw) * 1000 - heat_loss * (
            sum(temperature) / len(temperature) - ambient
        )
        return self._result(run_id, "thermal_balance", observed, expected, quality, sources, "W")

    def pump_performance(
        self,
        run_id: str,
        inlet_flow: float,
        speed_rpm: float,
        valve_percent: float,
        max_flow: float,
        quality: str,
        sources: tuple[str, ...] = (),
    ) -> ResidualObservation:
        return self._result(
            run_id,
            "pump_performance",
            inlet_flow,
            max_flow * speed_rpm / 3600 * valve_percent / 100,
            quality,
            sources,
            "m3/s",
        )

    def command_response(
        self,
        run_id: str,
        actual: float,
        command: float,
        quality: str,
        sources: tuple[str, ...] = (),
    ) -> ResidualObservation:
        return self._result(run_id, "command_response", actual, command, quality, sources, "%")

    def mechanical(
        self,
        run_id: str,
        speed_rpm: float,
        current: float,
        vibration: float,
        quality: str,
        sources: tuple[str, ...] = (),
    ) -> tuple[ResidualObservation, ResidualObservation]:
        speed = speed_rpm / 3600
        return (
            self._result(run_id, "current_load", current, 3 + 27 * speed, quality, sources, "A"),
            self._result(
                run_id,
                "vibration_mechanical",
                vibration,
                0.5 + 2.5 * speed,
                quality,
                sources,
                "mm/s",
            ),
        )
