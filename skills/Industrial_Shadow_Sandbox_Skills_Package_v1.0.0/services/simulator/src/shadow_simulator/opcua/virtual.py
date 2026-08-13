from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from shadow_sandbox.asset_registry import AssetModel, SignalDefinition
from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now

from ..model import ProcessCommand, SimulatorEngine, StateFrame


@dataclass(frozen=True, slots=True)
class NodeValue:
    node_id: str
    signal_key: str
    value: Any
    data_type: str
    unit: str
    source_timestamp: str
    server_timestamp: str
    status_code: str
    access_mode: str
    minimum_sampling_interval_ms: int


class VirtualOpcUaServer:
    """In-process OPC UA contract model used by deterministic tests."""

    def __init__(self, model: AssetModel, engine: SimulatorEngine) -> None:
        self.model = model
        self.engine = engine
        self.nodes = {signal.node_id: signal for signal in model.signals}
        if len(self.nodes) != len(model.signals):
            raise DomainError(
                "DUPLICATE_NODE_ID", "address space has duplicate NodeIds"
            )
        self.values: dict[str, NodeValue] = {}
        self.subscribers: list[tuple[str, Callable[[NodeValue], None]]] = []
        self.audit: list[dict[str, Any]] = []
        self.application_uri = "urn:industrial-shadow:simulator:pump-tank"
        self.namespace_uri = "urn:industrial-shadow:pump-tank"
        self.identity_digest = canonical_digest(
            [self.application_uri, model.digest, engine.model_digest]
        )

    def browse(self, role: str) -> tuple[SignalDefinition, ...]:
        if role not in {"shadow", "simulator_operator"}:
            raise DomainError("OPCUA_ACCESS_DENIED", "unknown OPC UA role", status=403)
        return self.model.signals

    def read(self, role: str, node_id: str) -> NodeValue:
        if role not in {"shadow", "simulator_operator"}:
            raise DomainError("OPCUA_ACCESS_DENIED", "read denied", status=403)
        if node_id not in self.nodes:
            raise DomainError("OPCUA_NODE_UNKNOWN", "node not found", status=404)
        if node_id not in self.values:
            raise DomainError(
                "OPCUA_VALUE_UNAVAILABLE", "no value published yet", status=503
            )
        return self.values[node_id]

    def subscribe(
        self, role: str, node_id: str, callback: Callable[[NodeValue], None]
    ) -> None:
        if role not in {"shadow", "simulator_operator"}:
            raise DomainError("OPCUA_ACCESS_DENIED", "subscribe denied", status=403)
        if node_id not in self.nodes:
            raise DomainError("OPCUA_NODE_UNKNOWN", "node not found", status=404)
        self.subscribers.append((node_id, callback))

    def publish(self, frame: StateFrame) -> None:
        epoch = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
        source = (
            (epoch + dt.timedelta(seconds=frame.simulation_time))
            .isoformat()
            .replace("+00:00", "Z")
        )
        server = utc_now()
        for signal in self.model.signals:
            value = frame.observed_values[signal.key]
            node_value = NodeValue(
                signal.node_id,
                signal.key,
                value,
                signal.data_type,
                signal.unit,
                source,
                server,
                frame.quality[signal.key],
                signal.access_mode,
                signal.sample_period_ms,
            )
            self.values[signal.node_id] = node_value
            for node_id, callback in tuple(self.subscribers):
                if node_id == signal.node_id:
                    callback(node_value)

    def write(self, role: str, node_id: str, value: Any) -> None:
        signal = self.nodes.get(node_id)
        if (
            role != "simulator_operator"
            or not signal
            or signal.access_mode != "simulation_write"
        ):
            self.audit.append(
                {
                    "operation": "Write",
                    "node_id": node_id,
                    "role": role,
                    "result": "denied",
                }
            )
            raise DomainError(
                "OPCUA_WRITE_DENIED", "write is not permitted", status=403
            )
        current = self.engine.last_command
        mapping = {
            "Pump101.SpeedCommand": "pump_speed_rpm",
            "Valve101.PositionCommand": "inlet_valve_percent",
            "Valve102.PositionCommand": "outlet_valve_percent",
            "Heater101.PowerCommand": "heater_power_kw",
        }
        field_name = mapping.get(signal.key)
        if (
            not field_name
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
        ):
            raise DomainError("OPCUA_TYPE_MISMATCH", "command requires a numeric value")
        if signal.minimum is not None and value < signal.minimum:
            raise DomainError("OPCUA_RANGE", "command below range")
        if signal.maximum is not None and value > signal.maximum:
            raise DomainError("OPCUA_RANGE", "command above range")
        data = {
            "pump_speed_rpm": current.pump_speed_rpm,
            "inlet_valve_percent": current.inlet_valve_percent,
            "outlet_valve_percent": current.outlet_valve_percent,
            "heater_power_kw": current.heater_power_kw,
        }
        data[field_name] = float(value)
        self.engine.last_command = ProcessCommand(**data)
        self.audit.append(
            {
                "operation": "Write",
                "node_id": node_id,
                "role": role,
                "result": "allowed",
            }
        )

    def call(self, role: str, method_id: str, arguments: list[Any]) -> None:
        self.audit.append(
            {
                "operation": "Call",
                "method_id": method_id,
                "role": role,
                "result": "denied",
            }
        )
        raise DomainError(
            "OPCUA_CALL_DENIED", "method calls are not exposed", status=403
        )
