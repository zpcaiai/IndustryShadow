from __future__ import annotations

from dataclasses import dataclass

from shadow_sandbox.asset_registry import AssetModel
from shadow_sandbox.common.models import DomainError


@dataclass(frozen=True, slots=True)
class AddressNode:
    node_id: str
    browse_path: tuple[str, ...]
    signal_key: str
    data_type: str
    unit: str
    access_mode: str
    minimum_sampling_interval_ms: int


def build_address_space(model: AssetModel) -> tuple[AddressNode, ...]:
    assets = {asset.key: asset for asset in model.assets}
    for asset in model.assets:
        if asset.parent and asset.parent not in assets:
            raise DomainError(
                "OPCUA_MAPPING_INVALID", "asset references an unknown parent"
            )
    seen: set[str] = set()
    result: list[AddressNode] = []
    for signal in model.signals:
        if signal.asset_key not in assets:
            raise DomainError(
                "OPCUA_MAPPING_INVALID", "signal references an unknown asset"
            )
        if signal.node_id in seen:
            raise DomainError(
                "DUPLICATE_NODE_ID", "address space has duplicate NodeIds"
            )
        seen.add(signal.node_id)
        path: list[str] = []
        current = assets[signal.asset_key]
        visited: set[str] = set()
        while current:
            if current.key in visited:
                raise DomainError(
                    "OPCUA_MAPPING_INVALID", "asset containment has a cycle"
                )
            visited.add(current.key)
            path.append(current.display_name)
            current = assets.get(current.parent) if current.parent else None
        result.append(
            AddressNode(
                signal.node_id,
                ("Objects", *reversed(path), signal.display_name),
                signal.key,
                signal.data_type,
                signal.unit,
                signal.access_mode,
                signal.sample_period_ms,
            )
        )
    return tuple(result)
