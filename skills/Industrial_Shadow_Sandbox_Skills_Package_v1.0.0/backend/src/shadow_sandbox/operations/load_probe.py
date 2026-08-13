from __future__ import annotations

import concurrent.futures
import json
import math
import os
import platform
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

from shadow_sandbox.common.models import DomainError, utc_now

from .evidence import GateCheck, GateEvidence, complete


@dataclass(frozen=True, slots=True)
class LoadTarget:
    name: str
    path: str
    method: str = "GET"
    body: Mapping[str, Any] | None = None
    expected_status: int = 200


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return math.inf
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(percentile * len(ordered)) - 1))
    return ordered[index]


class HttpLoadProbe:
    """Bounded HTTP load probe that publishes the measured envelope, never projections."""

    def __init__(
        self,
        base_url: str,
        target: LoadTarget,
        *,
        bearer_value: str | None,
        requests_per_second: float,
        concurrency: int,
        duration_seconds: float,
        p95_limit_ms: float,
        maximum_error_rate: float,
        warmup_requests: int = 5,
        maximum_consecutive_errors: int = 20,
        minimum_achieved_rate_ratio: float = 0.95,
    ) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise DomainError("LOAD_TARGET_INVALID", "production load target must use HTTPS")
        if not 0 < requests_per_second <= 10_000 or not 1 <= concurrency <= 1000:
            raise DomainError("LOAD_PROFILE_INVALID", "load rate or concurrency is invalid")
        if not 1 <= duration_seconds <= 86_400:
            raise DomainError("LOAD_PROFILE_INVALID", "load duration is invalid")
        if int(requests_per_second * duration_seconds) > 250_000:
            raise DomainError(
                "LOAD_PROFILE_INVALID", "load profile exceeds the 250000-request safety cap"
            )
        if (
            not 0 <= warmup_requests <= 1000
            or not 1 <= maximum_consecutive_errors <= 1000
            or not 0.5 <= minimum_achieved_rate_ratio <= 1.0
        ):
            raise DomainError("LOAD_PROFILE_INVALID", "load warmup or abort policy is invalid")
        target_url = urlsplit(target.path)
        if (
            not target.path.startswith("/")
            or target_url.scheme
            or target_url.netloc
            or target.method.upper() not in {"GET", "POST"}
            or not 100 <= target.expected_status <= 599
            or p95_limit_ms <= 0
            or not 0 <= maximum_error_rate <= 1
        ):
            raise DomainError("LOAD_PROFILE_INVALID", "load target or thresholds are invalid")
        self.base_url = base_url.rstrip("/")
        self.target = target
        self.bearer_value = bearer_value
        self.requests_per_second = requests_per_second
        self.concurrency = concurrency
        self.duration_seconds = duration_seconds
        self.p95_limit_ms = p95_limit_ms
        self.maximum_error_rate = maximum_error_rate
        self.warmup_requests = warmup_requests
        self.maximum_consecutive_errors = maximum_consecutive_errors
        self.minimum_achieved_rate_ratio = minimum_achieved_rate_ratio
        self.run_nonce = os.urandom(12).hex()

    def _request(self, sequence: int) -> tuple[float, bool]:
        url = urljoin(self.base_url + "/", self.target.path.lstrip("/"))
        headers = {"Accept": "application/json", "X-Load-Probe": "industrial-shadow"}
        if self.bearer_value:
            headers["Authorization"] = "Bearer " + self.bearer_value
        data = None
        if self.target.body is not None:
            data = json.dumps(self.target.body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
            headers["Idempotency-Key"] = f"load-probe-{self.run_nonce}-{sequence}"
        request = Request(url, data=data, headers=headers, method=self.target.method.upper())
        started = time.perf_counter()
        status = 0
        try:
            with urlopen(request, timeout=30) as response:
                status = int(response.status)
                response.read(65_537)
        except HTTPError as error:
            status = int(error.code)
            error.read(65_537)
        except (TimeoutError, URLError, OSError):
            status = 0
        return (time.perf_counter() - started) * 1000, status == self.target.expected_status

    def run(self) -> GateEvidence:
        started_at = utc_now()
        total = max(1, int(self.requests_per_second * self.duration_seconds))
        interval = 1.0 / self.requests_per_second
        latencies: list[float] = []
        successes = 0
        consecutive_errors = 0
        aborted = False

        warmup_successes = sum(
            int(self._request(-(sequence + 1))[1]) for sequence in range(self.warmup_requests)
        )
        start_clock = time.monotonic()

        def scheduled(sequence: int) -> tuple[float, bool]:
            deadline = start_clock + sequence * interval
            delay = deadline - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            return self._request(sequence)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            pending: set[concurrent.futures.Future[tuple[float, bool]]] = set()
            sequence = 0
            while (sequence < total or pending) and not aborted:
                while sequence < total and len(pending) < self.concurrency:
                    pending.add(executor.submit(scheduled, sequence))
                    sequence += 1
                done, pending = concurrent.futures.wait(
                    pending, return_when=concurrent.futures.FIRST_COMPLETED
                )
                for future in done:
                    latency, success = future.result()
                    latencies.append(latency)
                    successes += int(success)
                    consecutive_errors = 0 if success else consecutive_errors + 1
                completed = len(latencies)
                observed_error_rate = (completed - successes) / max(completed, 1)
                if consecutive_errors >= self.maximum_consecutive_errors or (
                    completed >= 50
                    and observed_error_rate > max(0.10, self.maximum_error_rate * 5)
                ):
                    aborted = True
            for future in pending:
                future.cancel()
        elapsed = time.monotonic() - start_clock
        completed = len(latencies)
        errors = completed - successes
        error_rate = errors / max(completed, 1)
        p50 = _percentile(latencies, 0.50)
        p95 = _percentile(latencies, 0.95)
        p99 = _percentile(latencies, 0.99)
        actual_rate = completed / max(elapsed, 1e-9)
        checks = (
            GateCheck("warmup", warmup_successes == self.warmup_requests),
            GateCheck("circuit_breaker_not_triggered", not aborted),
            GateCheck("all_requests_completed", completed == total),
            GateCheck("error_rate", error_rate <= self.maximum_error_rate),
            GateCheck("p95_latency", p95 <= self.p95_limit_ms),
            GateCheck(
                "achieved_rate",
                actual_rate >= self.requests_per_second * self.minimum_achieved_rate_ratio,
            ),
        )
        return complete(
            "performance",
            started_at=started_at,
            coordinates={
                "origin": f"{urlsplit(self.base_url).scheme}://{urlsplit(self.base_url).netloc}",
                "target_name": self.target.name,
                "method": self.target.method.upper(),
            },
            checks=checks,
            metrics={
                "requests": completed,
                "planned_requests": total,
                "warmup_requests": self.warmup_requests,
                "successes": successes,
                "error_rate": round(error_rate, 6),
                "configured_rps": self.requests_per_second,
                "achieved_rps": round(actual_rate, 3),
                "concurrency": self.concurrency,
                "duration_seconds": round(elapsed, 3),
                "p50_ms": round(p50, 3),
                "p95_ms": round(p95, 3),
                "p99_ms": round(p99, 3),
                "runner": f"{platform.system()}-{platform.machine()}-{platform.python_version()}",
                "aborted": int(aborted),
            },
        )


def run_http_load_suite(
    base_url: str,
    profiles: Sequence[Mapping[str, Any]],
    *,
    bearer_value: str | None,
    health_path: str = "/api/v1/health/ready",
) -> GateEvidence:
    started = utc_now()
    if not profiles:
        raise DomainError("LOAD_PROFILE_INVALID", "at least one load profile is required")
    checks: list[GateCheck] = []
    metrics: dict[str, float | int | str] = {"profiles": len(profiles)}
    profile_digests: dict[str, str] = {}
    from shadow_sandbox.common.models import canonical_digest

    if not health_path.startswith("/"):
        raise DomainError("LOAD_PROFILE_INVALID", "health path must be origin-relative")

    def healthy() -> bool:
        try:
            with urlopen(
                Request(urljoin(base_url.rstrip("/") + "/", health_path.lstrip("/"))),
                timeout=15,
            ) as response:
                return int(response.status) == 200
        except OSError:
            return False

    prepared: list[tuple[str, HttpLoadProbe]] = []
    names: set[str] = set()
    for profile in profiles:
        name = str(profile["name"])
        if not name or name in names:
            raise DomainError("LOAD_PROFILE_INVALID", "load profile names must be unique")
        names.add(name)
        target = LoadTarget(name=name, **dict(profile["target"]))
        prepared.append(
            (
                name,
                HttpLoadProbe(
                    base_url,
                    target,
                    bearer_value=bearer_value,
                    requests_per_second=float(profile["requests_per_second"]),
                    concurrency=int(profile["concurrency"]),
                    duration_seconds=float(profile["duration_seconds"]),
                    p95_limit_ms=float(profile["p95_limit_ms"]),
                    maximum_error_rate=float(profile["maximum_error_rate"]),
                    warmup_requests=int(profile.get("warmup_requests", 5)),
                    maximum_consecutive_errors=int(
                        profile.get("maximum_consecutive_errors", 20)
                    ),
                    minimum_achieved_rate_ratio=float(
                        profile.get("minimum_achieved_rate_ratio", 0.95)
                    ),
                ),
            )
        )
    planned_requests = sum(
        int(probe.requests_per_second * probe.duration_seconds) for _name, probe in prepared
    )
    if planned_requests > 500_000:
        raise DomainError("LOAD_PROFILE_INVALID", "load suite exceeds the request safety cap")

    before_healthy = healthy()
    for name, probe in prepared:
        evidence = probe.run()
        profile_digests[name] = evidence.digest
        checks.extend(
            GateCheck(f"{name}_{check.name}", check.passed, check.details)
            for check in evidence.checks
        )
        for key in ("requests", "error_rate", "achieved_rps", "p95_ms", "p99_ms"):
            metrics[f"{name}_{key}"] = evidence.metrics[key]
    metrics["planned_requests"] = planned_requests
    after_healthy = healthy()
    checks.extend(
        (
            GateCheck("service_healthy_before_load", before_healthy),
            GateCheck("service_healthy_after_load", after_healthy),
        )
    )
    return complete(
        "performance",
        started_at=started,
        coordinates={
            "origin": f"{urlsplit(base_url).scheme}://{urlsplit(base_url).netloc}",
            "profile_set_digest": canonical_digest(profile_digests),
        },
        checks=checks,
        metrics=metrics,
    )
