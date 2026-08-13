from __future__ import annotations

import contextlib
import contextvars
import time
from collections.abc import Iterator
from typing import Any

from shadow_sandbox.common.models import new_id

from .metrics import HTTP_DURATION, HTTP_REQUESTS, REGISTRY

_trace_id: contextvars.ContextVar[str] = contextvars.ContextVar("shadow_trace_id", default="")


@contextlib.contextmanager
def correlation_id(value: str | None = None) -> Iterator[str]:
    trace_id = value or new_id("trace")
    token = _trace_id.set(trace_id)
    try:
        yield trace_id
    finally:
        _trace_id.reset(token)


def current_trace_id() -> str:
    return _trace_id.get() or new_id("trace")


def instrument_application(app: Any) -> Any:
    """Attach optional OTel instrumentation when its runtime profile is installed."""
    try:
        from opentelemetry.instrumentation.fastapi import (
            FastAPIInstrumentor,  # type: ignore[import-not-found]
        )
    except ImportError:
        pass
    else:
        FastAPIInstrumentor.instrument_app(app)
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
        from starlette.responses import Response
    except ImportError:
        return app

    @app.middleware("http")
    async def prometheus_metrics(request: Any, call_next: Any) -> Any:
        started = time.perf_counter()
        response = await call_next(request)
        route = request.scope.get("route")
        template = getattr(route, "path", "unmatched")
        HTTP_REQUESTS.labels(request.method, template, str(response.status_code)).inc()
        HTTP_DURATION.labels(request.method, template).observe(time.perf_counter() - started)
        return response

    @app.get("/internal/metrics", include_in_schema=False)
    def metrics() -> Any:
        return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)

    return app
