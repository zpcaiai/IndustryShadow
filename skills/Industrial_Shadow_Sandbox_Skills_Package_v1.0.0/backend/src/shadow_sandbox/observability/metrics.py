from __future__ import annotations

from typing import Any


class NullMetric:
    def labels(self, *_values: str, **_labels: str) -> NullMetric:
        return self

    def inc(self, _amount: float = 1.0) -> None:
        return None

    def observe(self, _value: float) -> None:
        return None

    def set_to_current_time(self) -> None:
        return None


try:
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram
except ImportError:
    REGISTRY: Any = None
    HTTP_REQUESTS = NullMetric()
    HTTP_DURATION = NullMetric()
    SAFETY_POLICY_VIOLATIONS = NullMetric()
    VIRTUAL_ACTIONS = NullMetric()
    INGESTION_LAST_RECEIVED = NullMetric()
else:
    REGISTRY = CollectorRegistry()
    HTTP_REQUESTS = Counter(
        "shadow_http_requests_total",
        "HTTP requests by method, route and status",
        ("method", "route", "status"),
        registry=REGISTRY,
    )
    HTTP_DURATION = Histogram(
        "shadow_http_request_duration_seconds",
        "HTTP request duration by method and route",
        ("method", "route"),
        registry=REGISTRY,
    )
    SAFETY_POLICY_VIOLATIONS = Counter(
        "shadow_safety_policy_violations_total",
        "Denied safety boundary violations",
        ("code",),
        registry=REGISTRY,
    )
    VIRTUAL_ACTIONS = Counter(
        "shadow_virtual_actions_total",
        "Virtual action terminal states",
        ("state", "outcome"),
        registry=REGISTRY,
    )
    INGESTION_LAST_RECEIVED = Gauge(
        "shadow_ingestion_last_received_timestamp_seconds",
        "Last successfully persisted signal event",
        ("endpoint_id",),
        registry=REGISTRY,
    )
