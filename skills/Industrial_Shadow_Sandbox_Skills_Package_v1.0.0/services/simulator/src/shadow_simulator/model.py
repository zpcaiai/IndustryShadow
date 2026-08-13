from __future__ import annotations

import copy
import math
import random
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from typing import Any

from shadow_sandbox.common.models import DomainError, canonical_digest


class OperatingMode(StrEnum):
    STARTUP = "startup"
    STEADY = "steady"
    SHUTDOWN = "shutdown"
    MAINTENANCE = "maintenance"


MODE_TRANSITIONS: dict[OperatingMode, frozenset[OperatingMode]] = {
    OperatingMode.STARTUP: frozenset({OperatingMode.STEADY, OperatingMode.SHUTDOWN}),
    OperatingMode.STEADY: frozenset(
        {OperatingMode.SHUTDOWN, OperatingMode.MAINTENANCE}
    ),
    OperatingMode.SHUTDOWN: frozenset(
        {OperatingMode.STARTUP, OperatingMode.MAINTENANCE}
    ),
    OperatingMode.MAINTENANCE: frozenset({OperatingMode.SHUTDOWN}),
}


@dataclass(frozen=True, slots=True)
class ProcessParameters:
    tank_area_m2: float = 6.0
    tank_capacity_m: float = 10.0
    pump_max_flow_m3s: float = 0.08
    outlet_coefficient: float = 0.028
    thermal_capacity_j_per_c: float = 3_000_000.0
    heat_loss_w_per_c: float = 900.0
    ambient_temperature_c: float = 22.0
    actuator_time_constant_s: float = 1.5
    sensor_noise_fraction: float = 0.001
    current_base_a: float = 3.0
    current_gain_a: float = 27.0
    vibration_base_mms: float = 0.5
    vibration_gain_mms: float = 2.5

    def validate(self) -> None:
        positive = (
            self.tank_area_m2,
            self.tank_capacity_m,
            self.pump_max_flow_m3s,
            self.outlet_coefficient,
            self.thermal_capacity_j_per_c,
            self.actuator_time_constant_s,
        )
        if not all(math.isfinite(value) and value > 0 for value in positive):
            raise DomainError(
                "INVALID_PROCESS_PARAMETERS", "positive finite parameters required"
            )
        if not 0 <= self.sensor_noise_fraction <= 0.05:
            raise DomainError(
                "INVALID_NOISE", "sensor noise fraction must be within 0..0.05"
            )

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class ProcessCommand:
    pump_speed_rpm: float = 2400.0
    inlet_valve_percent: float = 85.0
    outlet_valve_percent: float = 60.0
    heater_power_kw: float = 25.0

    def validate(self) -> None:
        ranges = {
            "pump_speed_rpm": (self.pump_speed_rpm, 0.0, 3600.0),
            "inlet_valve_percent": (self.inlet_valve_percent, 0.0, 100.0),
            "outlet_valve_percent": (self.outlet_valve_percent, 0.0, 100.0),
            "heater_power_kw": (self.heater_power_kw, 0.0, 100.0),
        }
        for name, (value, lower, upper) in ranges.items():
            if not math.isfinite(value) or not lower <= value <= upper:
                raise DomainError("INVALID_COMMAND", f"{name} outside {lower}..{upper}")


@dataclass(frozen=True, slots=True)
class ProcessState:
    level_m: float = 4.0
    temperature_c: float = 28.0
    pump_speed_rpm: float = 0.0
    inlet_valve_percent: float = 0.0
    outlet_valve_percent: float = 0.0
    heater_power_kw: float = 0.0
    mode: OperatingMode = OperatingMode.STARTUP
    heartbeat: int = 0


@dataclass(frozen=True, slots=True)
class StateFrame:
    simulation_time: float
    mode: str
    true_values: Mapping[str, float | str]
    observed_values: Mapping[str, float | str]
    quality: Mapping[str, str]
    model_digest: str
    frame_digest: str = ""
    source_sequence: int = 0
    source_frame_digest: str | None = None

    def with_digest(self) -> StateFrame:
        payload = asdict(self)
        payload["frame_digest"] = ""
        return replace(self, frame_digest=canonical_digest(payload))


def _lag(actual: float, commanded: float, step_s: float, tau: float) -> float:
    alpha = min(1.0, step_s / tau)
    return actual + alpha * (commanded - actual)


class SimulatorEngine:
    """Deterministic fixed-step pump/valve/tank/heater process kernel."""

    def __init__(
        self,
        *,
        asset_model_digest: str,
        parameters: ProcessParameters | None = None,
        initial_state: ProcessState | None = None,
        seed: int = 42,
        step_ms: int = 100,
        simulator_build_digest: str = "dev-build",
        fault_runtime: Any | None = None,
    ) -> None:
        if step_ms <= 0 or 1000 % step_ms:
            raise DomainError(
                "INVALID_STEP", "step_ms must be a positive divisor of 1000"
            )
        self.parameters = parameters or ProcessParameters()
        self.parameters.validate()
        self.state = initial_state or ProcessState()
        self.asset_model_digest = asset_model_digest
        self.simulator_build_digest = simulator_build_digest
        self.step_ms = step_ms
        self.simulation_time = 0.0
        self.sequence = 0
        self.rng = random.Random(seed)
        self.seed = seed
        self.pending_events: list[dict[str, Any]] = []
        self.fault_runtime = fault_runtime
        self.last_command = ProcessCommand()
        self.paused = False
        self.stopped = False
        # FastAPI handlers and the background OPC UA publisher can access one
        # engine concurrently.  A re-entrant lock keeps frames, snapshots and
        # action mutations atomic without imposing an async runtime on the
        # deterministic process kernel.
        self._lock = threading.RLock()
        self.model_digest = canonical_digest(
            [
                asset_model_digest,
                self.parameters.digest,
                step_ms,
                simulator_build_digest,
            ]
        )

    @contextmanager
    def synchronized(self) -> Iterator[None]:
        with self._lock:
            yield

    def transition_mode(self, mode: OperatingMode) -> None:
        with self._lock:
            if mode not in MODE_TRANSITIONS[self.state.mode]:
                raise DomainError(
                    "INVALID_MODE_TRANSITION",
                    f"cannot transition {self.state.mode} to {mode}",
                )
            self.state = replace(self.state, mode=mode)

    def pause(self) -> None:
        with self._lock:
            self.paused = True

    def resume(self) -> None:
        with self._lock:
            if self.stopped:
                raise DomainError(
                    "SIMULATOR_STOPPED", "stopped simulator cannot resume", status=409
                )
            self.paused = False

    def stop(self) -> None:
        with self._lock:
            self.stopped = True
            self.paused = True

    def _command_for_mode(self, command: ProcessCommand) -> ProcessCommand:
        command.validate()
        if self.state.mode == OperatingMode.MAINTENANCE and (
            command.pump_speed_rpm > 0 or command.heater_power_kw > 0
        ):
            raise DomainError(
                "COMMAND_FORBIDDEN_IN_MODE", "active commands forbidden in maintenance"
            )
        if self.state.mode == OperatingMode.SHUTDOWN:
            return ProcessCommand(
                0.0, command.inlet_valve_percent, command.outlet_valve_percent, 0.0
            )
        return command

    def step(self, command: ProcessCommand | None = None) -> StateFrame:
        with self._lock:
            if self.stopped:
                raise DomainError(
                    "SIMULATOR_STOPPED", "simulator has stopped", status=409
                )
            if self.paused:
                raise DomainError(
                    "SIMULATOR_PAUSED", "manual step must use step_paused", status=409
                )
            return self._integrate(command or self.last_command)

    def step_paused(self, command: ProcessCommand | None = None) -> StateFrame:
        with self._lock:
            if not self.paused or self.stopped:
                raise DomainError(
                    "MANUAL_STEP_FORBIDDEN",
                    "manual step requires paused running simulator",
                )
            return self._integrate(command or self.last_command)

    def _integrate(self, command: ProcessCommand) -> StateFrame:
        command = self._command_for_mode(command)
        if self.fault_runtime:
            command = self.fault_runtime.mutate_command(self.simulation_time, command)
        self.last_command = command
        dt_s = self.step_ms / 1000.0
        p = self.parameters
        s = self.state
        pump_speed = _lag(
            s.pump_speed_rpm, command.pump_speed_rpm, dt_s, p.actuator_time_constant_s
        )
        inlet = _lag(
            s.inlet_valve_percent,
            command.inlet_valve_percent,
            dt_s,
            p.actuator_time_constant_s,
        )
        outlet = _lag(
            s.outlet_valve_percent,
            command.outlet_valve_percent,
            dt_s,
            p.actuator_time_constant_s,
        )
        heater = _lag(
            s.heater_power_kw, command.heater_power_kw, dt_s, p.actuator_time_constant_s
        )
        factors = (
            self.fault_runtime.physical_factors(self.simulation_time)
            if self.fault_runtime
            else {}
        )
        efficiency = float(factors.get("pump_efficiency", 1.0))
        blockage = float(factors.get("outlet_blockage", 0.0))
        leak = float(factors.get("tank_leak_m3s", 0.0))
        friction = float(factors.get("bearing_friction", 0.0))
        if factors.get("heater_stuck") is not None:
            heater = float(factors["heater_stuck"])
        qin = p.pump_max_flow_m3s * (pump_speed / 3600.0) * (inlet / 100.0) * efficiency
        qout = p.outlet_coefficient * (outlet / 100.0) * math.sqrt(max(s.level_m, 0.0))
        qout *= max(0.0, 1.0 - blockage)
        level = s.level_m + dt_s * (qin - qout - leak) / p.tank_area_m2
        level = min(p.tank_capacity_m, max(0.0, level))
        heat_in = heater * 1000.0
        heat_loss = p.heat_loss_w_per_c * (s.temperature_c - p.ambient_temperature_c)
        mixing = qin * 1000.0 * 4184.0 * (p.ambient_temperature_c - s.temperature_c)
        temperature = (
            s.temperature_c
            + dt_s * (heat_in - heat_loss + mixing) / p.thermal_capacity_j_per_c
        )
        current = p.current_base_a + p.current_gain_a * (pump_speed / 3600.0) / max(
            efficiency, 0.2
        )
        current += friction * 15.0
        vibration = p.vibration_base_mms + p.vibration_gain_mms * (pump_speed / 3600.0)
        vibration += friction * 8.0
        pressure = 101325.0 + 9810.0 * level
        values: dict[str, float | str] = {
            "Pump101.SpeedCommand": command.pump_speed_rpm,
            "Pump101.SpeedActual": pump_speed,
            "Pump101.Current": current,
            "Pump101.Vibration": vibration,
            "Tank101.InletFlow": qin,
            "Tank101.OutletFlow": qout,
            "Tank101.Level": level,
            "Tank101.Pressure": pressure,
            "Tank101.Temperature": temperature,
            "Valve101.PositionCommand": command.inlet_valve_percent,
            "Valve101.PositionActual": inlet,
            "Valve102.PositionCommand": command.outlet_valve_percent,
            "Valve102.PositionActual": outlet,
            "Heater101.PowerCommand": command.heater_power_kw,
            "Heater101.PowerActual": heater,
            "System.Heartbeat": float(1 - s.heartbeat),
            "System.SimulationTime": self.simulation_time + dt_s,
            "System.Mode": s.mode.value,
        }
        if not all(
            math.isfinite(float(value))
            for value in values.values()
            if not isinstance(value, str)
        ):
            raise DomainError("NUMERIC_DIVERGENCE", "non-finite simulator state")
        observed = copy.deepcopy(values)
        for key, value in tuple(observed.items()):
            if isinstance(value, float) and key not in {
                "System.SimulationTime",
                "System.Heartbeat",
            }:
                scale = max(abs(value), 1.0) * p.sensor_noise_fraction
                observed[key] = value + self.rng.uniform(-scale, scale)
        quality = {key: "Good" for key in observed}
        if self.fault_runtime:
            observed, quality = self.fault_runtime.mutate_observed(
                self.simulation_time + dt_s, observed, quality, self.rng
            )
        self.simulation_time = round(self.simulation_time + dt_s, 10)
        self.sequence += 1
        self.state = ProcessState(
            level,
            temperature,
            pump_speed,
            inlet,
            outlet,
            heater,
            s.mode,
            1 - s.heartbeat,
        )
        return StateFrame(
            self.simulation_time,
            s.mode.value,
            values,
            observed,
            quality,
            self.model_digest,
            source_sequence=self.sequence,
        ).with_digest()

    def run_until(
        self, target_time: float, command: ProcessCommand | None = None
    ) -> list[StateFrame]:
        with self._lock:
            if target_time < self.simulation_time:
                raise DomainError(
                    "TIME_REVERSAL", "target time precedes current virtual time"
                )
            frames: list[StateFrame] = []
            while self.simulation_time + 1e-12 < target_time:
                frames.append(self.step(command))
            return frames

    def deliver(self, frame: StateFrame) -> list[StateFrame]:
        with self._lock:
            if not self.fault_runtime:
                return [frame]
            return self.fault_runtime.deliver(self.simulation_time, frame)
