from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from shadow_sandbox.common import ActorContext, DomainError, EventEnvelope, Store
from shadow_sandbox.common.models import canonical_digest, validate_identifier

SCALAR_TYPES = {"Double", "Float", "Int32", "Int64", "Boolean", "String", "Enum"}
ACCESS_MODES = {"read_only", "simulation_write"}
UCUM_UNITS = {"1", "%", "m", "m3/s", "Pa", "degC", "A", "mm/s", "rpm", "kW", "s"}


@dataclass(frozen=True, slots=True)
class Asset:
    key: str
    kind: str
    display_name: str
    parent: str | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SignalDefinition:
    key: str
    asset_key: str
    display_name: str
    node_id: str
    data_type: str
    unit: str
    minimum: float | None
    maximum: float | None
    sample_period_ms: int
    access_mode: str = "read_only"
    semantic_tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TopologyEdge:
    source: str
    target: str
    edge_type: str


@dataclass(frozen=True, slots=True)
class AssetModel:
    model_id: str
    version: int
    assets: tuple[Asset, ...]
    signals: tuple[SignalDefinition, ...]
    topology: tuple[TopologyEdge, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


def validate_model(model: AssetModel) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    asset_keys = {asset.key for asset in model.assets}
    if len(asset_keys) != len(model.assets):
        errors.append({"code": "DUPLICATE_ASSET", "pointer": "/assets"})
    signal_keys: set[str] = set()
    node_ids: set[str] = set()
    parent_of: dict[str, str] = {}
    for index, asset in enumerate(model.assets):
        try:
            validate_identifier(asset.key, "asset.key")
        except DomainError:
            errors.append({"code": "INVALID_ASSET_KEY", "pointer": f"/assets/{index}/key"})
        if asset.parent:
            if asset.parent not in asset_keys:
                errors.append({"code": "MISSING_PARENT", "pointer": f"/assets/{index}/parent"})
            parent_of[asset.key] = asset.parent
    for key in asset_keys:
        seen: set[str] = set()
        current = key
        while current in parent_of:
            if current in seen:
                errors.append({"code": "CONTAINMENT_CYCLE", "pointer": "/assets"})
                break
            seen.add(current)
            current = parent_of[current]
    for index, signal in enumerate(model.signals):
        pointer = f"/signals/{index}"
        if signal.key in signal_keys:
            errors.append({"code": "DUPLICATE_SIGNAL", "pointer": pointer + "/key"})
        signal_keys.add(signal.key)
        if signal.node_id in node_ids:
            errors.append({"code": "DUPLICATE_NODE_ID", "pointer": pointer + "/node_id"})
        node_ids.add(signal.node_id)
        if signal.asset_key not in asset_keys:
            errors.append({"code": "MISSING_SIGNAL_ASSET", "pointer": pointer + "/asset_key"})
        if signal.data_type not in SCALAR_TYPES:
            errors.append({"code": "UNSUPPORTED_TYPE", "pointer": pointer + "/data_type"})
        if signal.unit not in UCUM_UNITS:
            errors.append({"code": "INVALID_UNIT", "pointer": pointer + "/unit"})
        if signal.sample_period_ms <= 0:
            errors.append(
                {"code": "INVALID_SAMPLE_PERIOD", "pointer": pointer + "/sample_period_ms"}
            )
        if (
            signal.minimum is not None
            and signal.maximum is not None
            and signal.minimum >= signal.maximum
        ):
            errors.append({"code": "INVALID_RANGE", "pointer": pointer + "/minimum"})
        if signal.access_mode not in ACCESS_MODES:
            errors.append({"code": "INVALID_ACCESS_MODE", "pointer": pointer + "/access_mode"})
        if signal.access_mode == "simulation_write" and "command" not in signal.semantic_tags:
            errors.append({"code": "UNSAFE_WRITABILITY", "pointer": pointer + "/access_mode"})
    for index, edge in enumerate(model.topology):
        if edge.source not in asset_keys or edge.target not in asset_keys:
            errors.append({"code": "BROKEN_TOPOLOGY", "pointer": f"/topology/{index}"})
    return errors


class AssetRegistryService:
    def __init__(self, store: Store) -> None:
        self.store = store

    def publish(self, actor: ActorContext, model: AssetModel) -> str:
        actor.require_role("Engineer", "PackAuthor", "Admin")
        errors = validate_model(model)
        if errors:
            raise DomainError("MODEL_INVALID", "asset model validation failed", {"errors": errors})
        payload = asdict(model)
        digest = self.store.put_artifact(
            kind="asset_model",
            artifact_id=model.model_id,
            workspace_id=actor.workspace_id,
            version=model.version,
            payload=payload,
            sealed=True,
        )
        self.store.append_event(
            EventEnvelope(
                "asset_model.published.v1",
                {"model_id": model.model_id, "version": model.version, "digest": digest},
                actor.tenant_id,
                actor.workspace_id,
                trace_id=actor.trace_id,
            )
        )
        return digest

    def resolve_signal(
        self, actor: ActorContext, model_id: str, version: int, signal_key: str
    ) -> SignalDefinition:
        artifact = self.store.get_artifact("asset_model", model_id, actor.workspace_id, version)
        for signal in artifact["payload"]["signals"]:
            if signal["key"] == signal_key:
                return SignalDefinition(**signal)
        raise DomainError("SIGNAL_NOT_FOUND", "signal is not in the published model", status=404)


def pump_tank_model() -> AssetModel:
    assets = (
        Asset("Factory", "site", "Factory"),
        Asset("Line1", "line", "Line 1", "Factory"),
        Asset("Pump101", "pump", "Pump P101", "Line1"),
        Asset("Valve101", "valve", "Inlet Valve V101", "Line1"),
        Asset("Tank101", "tank", "Tank T101", "Line1"),
        Asset("Valve102", "valve", "Outlet Valve V102", "Line1"),
        Asset("Heater101", "heater", "Heater H101", "Tank101"),
        Asset("System", "system", "Simulator System", "Line1"),
    )
    definitions = (
        ("Pump101.SpeedCommand", "Pump101", "rpm", 0.0, 3600.0, "simulation_write", ("command",)),
        ("Pump101.SpeedActual", "Pump101", "rpm", 0.0, 3600.0, "read_only", ("actual",)),
        ("Pump101.Current", "Pump101", "A", 0.0, 100.0, "read_only", ("measurement",)),
        ("Pump101.Vibration", "Pump101", "mm/s", 0.0, 50.0, "read_only", ("measurement",)),
        ("Tank101.InletFlow", "Tank101", "m3/s", 0.0, 1.0, "read_only", ("measurement",)),
        ("Tank101.OutletFlow", "Tank101", "m3/s", 0.0, 1.0, "read_only", ("measurement",)),
        ("Tank101.Level", "Tank101", "m", 0.0, 10.0, "read_only", ("measurement",)),
        ("Tank101.Pressure", "Tank101", "Pa", 0.0, 150000.0, "read_only", ("measurement",)),
        ("Tank101.Temperature", "Tank101", "degC", -20.0, 150.0, "read_only", ("measurement",)),
        ("Valve101.PositionCommand", "Valve101", "%", 0.0, 100.0, "simulation_write", ("command",)),
        ("Valve101.PositionActual", "Valve101", "%", 0.0, 100.0, "read_only", ("actual",)),
        ("Valve102.PositionCommand", "Valve102", "%", 0.0, 100.0, "simulation_write", ("command",)),
        ("Valve102.PositionActual", "Valve102", "%", 0.0, 100.0, "read_only", ("actual",)),
        ("Heater101.PowerCommand", "Heater101", "kW", 0.0, 100.0, "simulation_write", ("command",)),
        ("Heater101.PowerActual", "Heater101", "kW", 0.0, 100.0, "read_only", ("actual",)),
        ("System.Heartbeat", "System", "1", 0.0, 1.0, "read_only", ("status",)),
        ("System.SimulationTime", "System", "s", 0.0, None, "read_only", ("status",)),
        ("System.Mode", "System", "1", None, None, "read_only", ("status",)),
    )
    signals = tuple(
        SignalDefinition(
            key=key,
            asset_key=asset,
            display_name=key.rsplit(".", 1)[-1],
            node_id=f"nsu=urn:industrial-shadow:pump-tank;s={key}",
            data_type="String" if key == "System.Mode" else "Double",
            unit=unit,
            minimum=minimum,
            maximum=maximum,
            sample_period_ms=500,
            access_mode=access,
            semantic_tags=tags,
        )
        for key, asset, unit, minimum, maximum, access, tags in definitions
    )
    topology = (
        TopologyEdge("Pump101", "Valve101", "process"),
        TopologyEdge("Valve101", "Tank101", "process"),
        TopologyEdge("Tank101", "Valve102", "process"),
        TopologyEdge("Heater101", "Tank101", "thermal"),
    )
    return AssetModel("pump-tank-v1", 1, assets, signals, topology, {"non_safety_model": True})
