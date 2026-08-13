from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from typing import Any

from shadow_sandbox.common.models import DomainError

from ..model import StateFrame


class FramePublisher:
    def __init__(self, ua_module: Any, nodes: Mapping[str, Any]) -> None:
        self.ua = ua_module
        self.nodes = dict(nodes)
        self.epoch = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)

    async def publish(self, frame: StateFrame) -> None:
        source_time = self.epoch + dt.timedelta(seconds=frame.simulation_time)
        server_time = dt.datetime.now(dt.UTC)
        missing = set(self.nodes) - set(frame.observed_values)
        if missing:
            raise DomainError(
                "OPCUA_FRAME_INCOMPLETE",
                "state frame is missing mapped signals",
                {"missing": sorted(missing)},
            )
        for signal_key, node in self.nodes.items():
            value = frame.observed_values[signal_key]
            status_name = frame.quality.get(signal_key, "Bad")
            status_value = {
                "Good": self.ua.StatusCodes.Good,
                "Uncertain": self.ua.StatusCodes.Uncertain,
            }.get(status_name, self.ua.StatusCodes.Bad)
            variant_type = (
                self.ua.VariantType.String
                if isinstance(value, str)
                else self.ua.VariantType.Double
            )
            data_value = self.ua.DataValue(
                Value=self.ua.Variant(value, variant_type),
                StatusCode_=self.ua.StatusCode(status_value),
                SourceTimestamp=source_time,
                ServerTimestamp=server_time,
            )
            await node.write_value(data_value)
