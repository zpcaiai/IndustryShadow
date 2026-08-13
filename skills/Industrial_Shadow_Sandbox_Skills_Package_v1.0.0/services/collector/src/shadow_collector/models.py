from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from shadow_sandbox.common.models import canonical_digest, utc_now


@dataclass(frozen=True, slots=True)
class RawSignalEvent:
    tenant_id: str
    workspace_id: str
    run_id: str
    scenario_id: str
    endpoint_id: str
    node_id: str
    signal_key: str
    data_type: str
    value: Any
    source_timestamp: str
    server_timestamp: str
    received_timestamp: str
    status_code: str
    sequence: int
    flags: tuple[str, ...] = ()
    ingest_version: int = 1
    trace_id: str | None = None

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))

    @property
    def logical_id(self) -> str:
        return canonical_digest(
            [
                self.run_id,
                self.node_id,
                self.source_timestamp,
                self.sequence,
                self.value,
            ]
        )


class RawSignalNormalizer:
    def __init__(self, expected_interval_ms: Mapping[str, int]) -> None:
        self.expected = dict(expected_interval_ms)
        self.previous: dict[str, tuple[int, dt.datetime, str]] = {}
        self.collector_sequence = 0

    def normalize(
        self,
        *,
        trusted_context: Mapping[str, str],
        notification: Any,
        trace_id: str | None = None,
    ) -> RawSignalEvent:
        self.collector_sequence += 1
        flags: list[str] = []
        source = dt.datetime.fromisoformat(
            notification.source_timestamp.replace("Z", "+00:00")
        )
        prior = self.previous.get(notification.signal_key)
        source_key = canonical_digest(
            [notification.node_id, notification.source_timestamp, notification.value]
        )
        if prior:
            _prior_sequence, prior_time, prior_key = prior
            if source_key == prior_key:
                flags.append("duplicate")
            if source < prior_time:
                flags.append("reordered")
            expected = self.expected.get(notification.signal_key, 500) / 1000.0
            interval = (source - prior_time).total_seconds()
            if interval > expected * 1.5:
                flags.append("gap")
            if interval >= 0 and abs(interval - expected) > expected * 0.25:
                flags.append("interval_drift")
        received = dt.datetime.now(dt.UTC)
        if source > received + dt.timedelta(minutes=5):
            flags.append("clock_future")
        self.previous[notification.signal_key] = (
            self.collector_sequence,
            source,
            source_key,
        )
        return RawSignalEvent(
            tenant_id=trusted_context["tenant_id"],
            workspace_id=trusted_context["workspace_id"],
            run_id=trusted_context["run_id"],
            scenario_id=trusted_context["scenario_id"],
            endpoint_id=trusted_context["endpoint_id"],
            node_id=notification.node_id,
            signal_key=notification.signal_key,
            data_type=notification.data_type,
            value=notification.value,
            source_timestamp=notification.source_timestamp,
            server_timestamp=notification.server_timestamp,
            received_timestamp=utc_now(),
            status_code=notification.status_code,
            sequence=self.collector_sequence,
            flags=tuple(sorted(set(flags))),
            trace_id=trace_id,
        )
