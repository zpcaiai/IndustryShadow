from __future__ import annotations

import json
import re
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any
from urllib.request import Request, urlopen

from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now
from shadow_sandbox.common.sqlalchemy_store import SqlAlchemyStore

from .evidence import GateCheck, GateEvidence, complete

CommandRunner = Callable[[Sequence[str], int], str]


def _run(command: Sequence[str], timeout: int) -> str:
    completed = subprocess.run(
        list(command),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode:
        raise DomainError(
            "KUBERNETES_DRILL_FAILED",
            "Kubernetes drill command failed",
            {
                "verb": command[1] if len(command) > 1 else "unknown",
                "exit_code": completed.returncode,
            },
            status=503,
        )
    return completed.stdout


def _ready(url: str) -> bool:
    try:
        with urlopen(Request(url, method="GET"), timeout=15) as response:
            return int(response.status) == 200
    except OSError:
        return False


def _require_https_health(url: str) -> str:
    if not url.startswith("https://"):
        raise DomainError("DRILL_READINESS_URL_INVALID", "readiness URL must use HTTPS")
    return url


def _require_postgresql(url: str) -> str:
    if not url.startswith(("postgresql://", "postgresql+psycopg://")):
        raise DomainError("DRILL_DATABASE_INVALID", "drill database must use PostgreSQL")
    return url


def _database_state(database_url: str) -> dict[str, int]:
    store = SqlAlchemyStore(database_url)
    try:
        return {
            "migration_head": int(
                store.query("SELECT MAX(version) AS version FROM schema_migrations")[0]["version"]
            ),
            "runs": int(store.query("SELECT COUNT(*) AS count FROM runs")[0]["count"]),
            "actions": int(
                store.query("SELECT COUNT(*) AS count FROM action_executions")[0]["count"]
            ),
            "duplicate_action_keys": int(
                store.query(
                    """SELECT COUNT(*) AS count FROM (
                         SELECT idempotency_key FROM action_executions
                         GROUP BY idempotency_key HAVING COUNT(*) > 1
                       ) duplicates"""
                )[0]["count"]
            ),
            "outbox": int(store.query("SELECT COUNT(*) AS count FROM outbox")[0]["count"]),
        }
    finally:
        store.close()


class KubernetesDrill:
    def __init__(
        self,
        namespace: str,
        deployment: str,
        container: str,
        readiness_url: str,
        database_url: str,
        *,
        confirmation: str,
        runner: CommandRunner = _run,
        maximum_rollback_seconds: int = 900,
    ) -> None:
        if not re.fullmatch(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?", namespace):
            raise DomainError("DRILL_NAMESPACE_INVALID", "namespace is invalid")
        if namespace in {"default", "kube-system", "kube-public", "kube-node-lease"}:
            raise DomainError("DRILL_NAMESPACE_INVALID", "system namespaces are forbidden")
        if confirmation != f"{namespace}:{deployment}":
            raise DomainError("DRILL_CONFIRMATION_REQUIRED", "exact drill confirmation is required")
        self.namespace = namespace
        self.deployment = deployment
        self.container = container
        self.readiness_url = _require_https_health(readiness_url)
        self.database_url = _require_postgresql(database_url)
        self.runner = runner
        if not 1 <= maximum_rollback_seconds <= 3600:
            raise DomainError("DRILL_THRESHOLD_INVALID", "rollback threshold is invalid")
        self.maximum_rollback_seconds = maximum_rollback_seconds

    def _kubectl(self, arguments: Sequence[str], timeout: int = 600) -> str:
        return self.runner(("kubectl", "-n", self.namespace, *arguments), timeout)

    def terminate_one_pod(self) -> GateEvidence:
        started = utc_now()
        deployment = json.loads(
            self._kubectl(("get", "deployment", self.deployment, "-o", "json"), 60)
        )
        desired = int(deployment.get("spec", {}).get("replicas", 0))
        available = int(deployment.get("status", {}).get("availableReplicas", 0))
        if desired < 2 or available < 2:
            raise DomainError(
                "CHAOS_AVAILABILITY_INVALID",
                "pod termination requires at least two desired and available replicas",
            )
        before = _database_state(self.database_url)
        pods = json.loads(
            self._kubectl(("get", "pods", "-l", f"app={self.deployment}", "-o", "json"), 60)
        ).get("items", ())
        names = sorted(
            str(item.get("metadata", {}).get("name"))
            for item in pods
            if item.get("status", {}).get("phase") == "Running"
        )
        if not names:
            raise DomainError("CHAOS_POD_MISSING", "no running pod was found")
        started_clock = time.monotonic()
        self._kubectl(("delete", "pod", names[0], "--wait=false"), 60)
        self._kubectl(("rollout", "status", f"deployment/{self.deployment}", "--timeout=10m"))
        recovery_seconds = time.monotonic() - started_clock
        after = _database_state(self.database_url)
        checks = (
            GateCheck("minimum_availability", desired >= 2 and available >= 2),
            GateCheck("rollout_recovered", _ready(self.readiness_url)),
            GateCheck("migration_unchanged", after["migration_head"] == before["migration_head"]),
            GateCheck(
                "durable_rows_not_lost",
                after["runs"] >= before["runs"] and after["actions"] >= before["actions"],
            ),
            GateCheck("no_duplicate_actions", after["duplicate_action_keys"] == 0),
        )
        return complete(
            "resilience",
            started_at=started,
            coordinates={"namespace": self.namespace, "deployment": self.deployment},
            checks=checks,
            metrics={"recovery_seconds": round(recovery_seconds, 3), "desired_replicas": desired},
        )

    def upgrade_and_rollback(self, candidate_image: str, migration_job: str) -> GateEvidence:
        started = utc_now()
        if "@sha256:" not in candidate_image:
            raise DomainError("CANDIDATE_IMAGE_INVALID", "candidate image must be digest pinned")
        migration = json.loads(self._kubectl(("get", "job", migration_job, "-o", "json"), 60))
        migration_complete = any(
            item.get("type") == "Complete" and item.get("status") == "True"
            for item in migration.get("status", {}).get("conditions", ())
        )
        migration_images = {
            str(item.get("image"))
            for item in migration.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", ())
        }
        if not migration_complete or candidate_image not in migration_images:
            raise DomainError(
                "CANDIDATE_MIGRATION_UNVERIFIED",
                "completed candidate-image migration Job is required before upgrade",
            )
        deployment = json.loads(
            self._kubectl(("get", "deployment", self.deployment, "-o", "json"), 60)
        )
        containers = (
            deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", ())
        )
        current = next(
            (str(item.get("image")) for item in containers if item.get("name") == self.container),
            None,
        )
        if not current or "@sha256:" not in current or current == candidate_image:
            raise DomainError(
                "ROLLBACK_IMAGE_INVALID",
                "current rollback and candidate images must be distinct digest-pinned images",
            )
        before = _database_state(self.database_url)
        candidate_ready = False
        rollback_ready = False
        candidate_image_observed = ""
        rollback_image_observed = ""
        started_clock = time.monotonic()
        try:
            self._kubectl(
                (
                    "set",
                    "image",
                    f"deployment/{self.deployment}",
                    f"{self.container}={candidate_image}",
                )
            )
            self._kubectl(("rollout", "status", f"deployment/{self.deployment}", "--timeout=10m"))
            candidate_ready = _ready(self.readiness_url)
            candidate_state = json.loads(
                self._kubectl(("get", "deployment", self.deployment, "-o", "json"), 60)
            )
            candidate_image_observed = next(
                (
                    str(item.get("image"))
                    for item in candidate_state.get("spec", {})
                    .get("template", {})
                    .get("spec", {})
                    .get("containers", ())
                    if item.get("name") == self.container
                ),
                "",
            )
        finally:
            self._kubectl(
                (
                    "set",
                    "image",
                    f"deployment/{self.deployment}",
                    f"{self.container}={current}",
                )
            )
            self._kubectl(("rollout", "status", f"deployment/{self.deployment}", "--timeout=10m"))
            rollback_ready = _ready(self.readiness_url)
            rollback_state = json.loads(
                self._kubectl(("get", "deployment", self.deployment, "-o", "json"), 60)
            )
            rollback_image_observed = next(
                (
                    str(item.get("image"))
                    for item in rollback_state.get("spec", {})
                    .get("template", {})
                    .get("spec", {})
                    .get("containers", ())
                    if item.get("name") == self.container
                ),
                "",
            )
        after = _database_state(self.database_url)
        elapsed = time.monotonic() - started_clock
        checks = (
            GateCheck("candidate_migration_completed", migration_complete),
            GateCheck("candidate_ready", candidate_ready),
            GateCheck("candidate_image_exact", candidate_image_observed == candidate_image),
            GateCheck("rollback_ready", rollback_ready),
            GateCheck("rollback_image_exact", rollback_image_observed == current),
            GateCheck("rollback_rto", elapsed <= self.maximum_rollback_seconds),
            GateCheck("migration_compatible", after["migration_head"] >= before["migration_head"]),
            GateCheck(
                "durable_rows_not_lost",
                after["runs"] >= before["runs"] and after["actions"] >= before["actions"],
            ),
            GateCheck("outbox_not_lost", after["outbox"] >= before["outbox"]),
            GateCheck("no_duplicate_actions", after["duplicate_action_keys"] == 0),
        )
        return complete(
            "upgrade_rollback",
            started_at=started,
            coordinates={
                "namespace": self.namespace,
                "deployment": self.deployment,
                "candidate_image": candidate_image,
                "rollback_image": current,
                "migration_job": migration_job,
            },
            checks=checks,
            metrics={"drill_seconds": round(elapsed, 3), "migration_head": after["migration_head"]},
        )


class KubernetesChaosSuite:
    """Controlled pod-loss and scale-outage matrix with unconditional replica restoration."""

    def __init__(
        self,
        namespace: str,
        database_url: str,
        *,
        confirmation: str,
        runner: CommandRunner = _run,
    ) -> None:
        if not re.fullmatch(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?", namespace) or namespace in {
            "default",
            "kube-system",
            "kube-public",
            "kube-node-lease",
        }:
            raise DomainError("DRILL_NAMESPACE_INVALID", "namespace is invalid")
        if confirmation != f"{namespace}:chaos":
            raise DomainError("DRILL_CONFIRMATION_REQUIRED", "exact chaos confirmation is required")
        self.namespace = namespace
        self.database_url = _require_postgresql(database_url)
        self.runner = runner

    def _kubectl(self, arguments: Sequence[str], timeout: int = 600) -> str:
        return self.runner(("kubectl", "-n", self.namespace, *arguments), timeout)

    def _pod_termination(self, scenario: Mapping[str, Any]) -> tuple[bool, float]:
        workload = str(scenario["workload"])
        resource = json.loads(self._kubectl(("get", "deployment", workload, "-o", "json"), 60))
        desired = int(resource.get("spec", {}).get("replicas", 0))
        available = int(resource.get("status", {}).get("availableReplicas", 0))
        if desired < 2 or available < 2:
            raise DomainError(
                "CHAOS_AVAILABILITY_INVALID", "pod termination requires two available replicas"
            )
        pods = json.loads(
            self._kubectl(("get", "pods", "-l", f"app={workload}", "-o", "json"), 60)
        ).get("items", ())
        names = sorted(
            str(item.get("metadata", {}).get("name"))
            for item in pods
            if item.get("status", {}).get("phase") == "Running"
        )
        if not names:
            raise DomainError("CHAOS_POD_MISSING", "no running pod was found")
        started = time.monotonic()
        self._kubectl(("delete", "pod", names[0], "--wait=false"), 60)
        self._kubectl(("rollout", "status", f"deployment/{workload}", "--timeout=10m"))
        return True, time.monotonic() - started

    def _scale_outage(self, scenario: Mapping[str, Any]) -> tuple[bool, float]:
        kind = str(scenario.get("kind", "deployment"))
        workload = str(scenario["workload"])
        if kind not in {"deployment", "statefulset"}:
            raise DomainError("CHAOS_KIND_INVALID", "only Deployment or StatefulSet is supported")
        resource = json.loads(self._kubectl(("get", kind, workload, "-o", "json"), 60))
        replicas = int(resource.get("spec", {}).get("replicas", 0))
        if replicas < 1:
            raise DomainError("CHAOS_REPLICA_INVALID", "workload already has zero replicas")
        started = time.monotonic()
        try:
            self._kubectl(("scale", f"{kind}/{workload}", "--replicas=0"), 120)
            self._kubectl(
                (
                    "wait",
                    "--for=jsonpath={.status.replicas}=0",
                    f"{kind}/{workload}",
                    "--timeout=5m",
                ),
                360,
            )
        finally:
            self._kubectl(("scale", f"{kind}/{workload}", f"--replicas={replicas}"), 120)
            self._kubectl(("rollout", "status", f"{kind}/{workload}", "--timeout=10m"))
        return True, time.monotonic() - started

    def run(self, scenarios: Sequence[Mapping[str, Any]]) -> GateEvidence:
        started = utc_now()
        if not scenarios:
            raise DomainError("CHAOS_SCENARIOS_REQUIRED", "chaos scenarios are required")
        required_categories = {"api", "worker", "collector", "simulator"}
        categories = [str(item.get("category", "")) for item in scenarios]
        if set(categories) != required_categories or len(categories) != len(set(categories)):
            raise DomainError(
                "CHAOS_COVERAGE_INCOMPLETE",
                "chaos matrix must cover API, worker, collector, and simulator exactly once",
            )
        names = [str(item.get("name", "")) for item in scenarios]
        for scenario in scenarios:
            operation = str(scenario.get("operation", ""))
            kind = str(scenario.get("kind", "deployment"))
            maximum_recovery_seconds = float(
                scenario.get("maximum_recovery_seconds", 0)
            )
            readiness_url = str(scenario.get("readiness_url", ""))
            if (
                not str(scenario.get("name", ""))
                or not str(scenario.get("workload", ""))
                or operation not in {"pod_termination", "scale_outage"}
                or (operation == "scale_outage" and kind not in {"deployment", "statefulset"})
                or not 1 <= maximum_recovery_seconds <= 3600
            ):
                raise DomainError(
                    "CHAOS_SCENARIO_INVALID", "chaos scenario contract is invalid"
                )
            if readiness_url:
                _require_https_health(readiness_url)
        if len(names) != len(set(names)):
            raise DomainError("CHAOS_SCENARIO_INVALID", "chaos names must be unique")
        before = _database_state(self.database_url)
        checks: list[GateCheck] = []
        metrics: dict[str, float | int | str] = {"scenarios": len(scenarios)}
        for scenario in scenarios:
            name = str(scenario["name"])
            operation = str(scenario["operation"])
            maximum_recovery_seconds = float(scenario.get("maximum_recovery_seconds", 0))
            if not 1 <= maximum_recovery_seconds <= 3600:
                raise DomainError(
                    "CHAOS_THRESHOLD_INVALID", "each scenario needs a bounded recovery threshold"
                )
            readiness_url = str(scenario.get("readiness_url", ""))
            if readiness_url:
                _require_https_health(readiness_url)
            ready_before = _ready(readiness_url) if readiness_url else True
            if operation == "pod_termination":
                recovered, elapsed = self._pod_termination(scenario)
            elif operation == "scale_outage":
                recovered, elapsed = self._scale_outage(scenario)
            else:
                raise DomainError("CHAOS_OPERATION_INVALID", "unsupported chaos operation")
            ready = _ready(readiness_url) if readiness_url else recovered
            checks.extend(
                (
                    GateCheck(f"{name}_ready_before", ready_before),
                    GateCheck(f"{name}_recovered", recovered and ready),
                    GateCheck(
                        f"{name}_recovery_rto", elapsed <= maximum_recovery_seconds
                    ),
                )
            )
            metrics[f"{name}_recovery_seconds"] = round(elapsed, 3)
        after = _database_state(self.database_url)
        checks.extend(
            (
                GateCheck(
                    "migration_unchanged", after["migration_head"] == before["migration_head"]
                ),
                GateCheck(
                    "durable_rows_not_lost",
                    after["runs"] >= before["runs"] and after["actions"] >= before["actions"],
                ),
                GateCheck("no_duplicate_actions", after["duplicate_action_keys"] == 0),
                GateCheck("outbox_not_lost", after["outbox"] >= before["outbox"]),
            )
        )
        return complete(
            "resilience",
            started_at=started,
            coordinates={
                "namespace": self.namespace,
                "scenario_digest": canonical_digest([dict(item) for item in scenarios]),
            },
            checks=checks,
            metrics=metrics,
        )
