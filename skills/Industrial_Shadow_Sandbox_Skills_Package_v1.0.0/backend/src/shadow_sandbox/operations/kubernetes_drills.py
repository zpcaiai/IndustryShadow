from __future__ import annotations

import json
import re
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now
from shadow_sandbox.common.sqlalchemy_store import SqlAlchemyStore

from .evidence import GateCheck, GateEvidence, complete
from .production_deployment import (
    ProductionDeploymentPlan,
    cluster_identity,
    validate_exact_rbac,
)

CommandRunner = Callable[[Sequence[str], int], str]
ROLLBACK_DRILL_RBAC = frozenset(
    {
        *(
            ("apps", resource, verb)
            for resource in ("deployments", "statefulsets")
            for verb in ("get", "list", "watch", "patch")
        ),
        ("apps", "replicasets", "get"),
        ("apps", "replicasets", "list"),
        ("batch", "jobs", "get"),
        ("batch", "jobs", "create"),
        ("batch", "jobs", "patch"),
        ("batch", "jobs", "delete"),
        ("batch", "jobs", "watch"),
        ("", "pods", "get"),
        ("", "pods", "list"),
    }
)
CHAOS_DRILL_RBAC = frozenset(
    {
        *(("apps", resource, "get") for resource in ("deployments", "statefulsets", "replicasets")),
        ("apps", "replicasets", "list"),
        *(
            ("apps", resource, verb)
            for resource in ("deployments/scale", "statefulsets/scale")
            for verb in ("get", "update")
        ),
        ("", "pods", "get"),
        ("", "pods", "list"),
        ("", "pods", "delete"),
    }
)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


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
        with build_opener(_NoRedirect()).open(Request(url, method="GET"), timeout=15) as response:
            return int(response.status) == 200
    except (HTTPError, OSError):
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
        web_readiness_url: str,
        database_url: str,
        *,
        confirmation: str,
        context: str = "",
        expected_cluster_uid_digest: str = "",
        expected_kubernetes_api_ca_digest: str = "",
        plan: ProductionDeploymentPlan | None = None,
        runner: CommandRunner = _run,
        maximum_rollback_seconds: int = 900,
    ) -> None:
        if not re.fullmatch(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?", namespace):
            raise DomainError("DRILL_NAMESPACE_INVALID", "namespace is invalid")
        if namespace in {"default", "kube-system", "kube-public", "kube-node-lease"}:
            raise DomainError("DRILL_NAMESPACE_INVALID", "system namespaces are forbidden")
        if confirmation != f"{namespace}:{deployment}":
            raise DomainError("DRILL_CONFIRMATION_REQUIRED", "exact drill confirmation is required")
        if (
            plan is None
            or namespace != plan.namespace
            or deployment != "control-api"
            or container != "api"
        ):
            raise DomainError("DRILL_PLAN_MISMATCH", "rollback drill must match the sealed plan")
        if not re.fullmatch(r"[a-f0-9]{64}", expected_cluster_uid_digest) or not re.fullmatch(
            r"[a-f0-9]{64}", expected_kubernetes_api_ca_digest
        ):
            raise DomainError(
                "KUBERNETES_CLUSTER_IDENTITY_INVALID", "signed cluster digest is required"
            )
        self.namespace = namespace
        self.deployment = deployment
        self.container = container
        self.readiness_url = _require_https_health(readiness_url)
        self.web_readiness_url = _require_https_health(web_readiness_url)
        self.database_url = _require_postgresql(database_url)
        self.runner = runner
        self.context = context
        self.expected_cluster_uid_digest = expected_cluster_uid_digest
        self.expected_kubernetes_api_ca_digest = expected_kubernetes_api_ca_digest
        self.plan = plan
        if not 1 <= maximum_rollback_seconds <= 3600:
            raise DomainError("DRILL_THRESHOLD_INVALID", "rollback threshold is invalid")
        self.maximum_rollback_seconds = maximum_rollback_seconds

    def _kubectl(self, arguments: Sequence[str], timeout: int = 600) -> str:
        return self.runner(
            ("kubectl", "--context", self.context, "-n", self.namespace, *arguments),
            timeout,
        )

    def _verify_cluster(self) -> tuple[str, str]:
        identity, api_ca_digest = cluster_identity(self.runner, self.context)
        if (
            identity != self.expected_cluster_uid_digest
            or api_ca_digest != self.expected_kubernetes_api_ca_digest
        ):
            raise DomainError(
                "KUBERNETES_CLUSTER_IDENTITY_MISMATCH",
                "rollback drill cluster does not match the signed target profile",
            )
        return identity, api_ca_digest

    def _verify_rbac(self) -> None:
        payload = json.loads(self._kubectl(("auth", "can-i", "--list", "-o", "json"), 60))
        if not isinstance(payload, Mapping) or not validate_exact_rbac(
            payload, ROLLBACK_DRILL_RBAC
        ):
            raise DomainError("DRILL_RBAC_OVERBROAD", "rollback drill RBAC is not exact")

    def _apply_migration(self) -> Mapping[str, Any]:
        artifact = self.plan.migration_manifest
        self._kubectl(
            (
                "apply",
                "--server-side",
                "--dry-run=server",
                "-f",
                str(artifact.path),
                "-o",
                "name",
            )
        )
        self._kubectl(
            (
                "apply",
                "--server-side",
                "--field-manager=industrial-shadow-acceptance-drill",
                "-f",
                str(artifact.path),
            )
        )
        self._kubectl(
            (
                "wait",
                "--for=condition=complete",
                f"job/{self.plan.migration_job}",
                "--timeout=10m",
            )
        )
        value = json.loads(
            self._kubectl(("get", "job", self.plan.migration_job, "-o", "json"), 60)
        )
        if not isinstance(value, Mapping):
            raise DomainError("CANDIDATE_MIGRATION_UNVERIFIED", "migration Job is invalid")
        return value

    def _cleanup_migration(self) -> None:
        self._kubectl(
            (
                "delete",
                "job",
                self.plan.migration_job,
                "--cascade=foreground",
                "--wait=true",
                "--ignore-not-found=true",
            ),
            600,
        )
        pods = json.loads(
            self._kubectl(
                ("get", "pods", "-l", f"job-name={self.plan.migration_job}", "-o", "json"),
                60,
            )
        ).get("items", ())
        if pods:
            raise DomainError(
                "CANDIDATE_MIGRATION_CLEANUP_FAILED",
                "migration Job Pods remain after acceptance cleanup",
            )

    def terminate_one_pod(self) -> GateEvidence:
        started = utc_now()
        cluster_uid_digest, api_ca_digest = self._verify_cluster()
        self._verify_rbac()
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
        revision = str(
            deployment.get("metadata", {})
            .get("annotations", {})
            .get("deployment.kubernetes.io/revision", "")
        )
        replica_sets = json.loads(
            self._kubectl(("get", "replicasets", "-l", f"app={self.deployment}", "-o", "json"), 60)
        ).get("items", ())
        owner_uids = {
            str(item.get("metadata", {}).get("uid"))
            for item in replica_sets
            if item.get("metadata", {})
            .get("annotations", {})
            .get("deployment.kubernetes.io/revision")
            == revision
            and any(
                owner.get("uid") == deployment.get("metadata", {}).get("uid")
                and owner.get("controller") is True
                for owner in item.get("metadata", {}).get("ownerReferences", ())
            )
        }
        if len(owner_uids) != 1:
            raise DomainError("CHAOS_OWNER_INVALID", "current Deployment revision is ambiguous")
        identities = sorted(
            (str(item.get("metadata", {}).get("name")), str(item.get("metadata", {}).get("uid")))
            for item in pods
            if item.get("status", {}).get("phase") == "Running"
            and any(
                owner.get("uid") in owner_uids and owner.get("controller") is True
                for owner in item.get("metadata", {}).get("ownerReferences", ())
            )
        )
        if not identities:
            raise DomainError("CHAOS_POD_MISSING", "no running pod was found")
        started_clock = time.monotonic()
        self._kubectl(("delete", "pod", identities[0][0], "--wait=true"), 60)
        remaining = json.loads(
            self._kubectl(("get", "pods", "-l", f"app={self.deployment}", "-o", "json"), 60)
        ).get("items", ())
        disrupted = all(
            item.get("metadata", {}).get("uid") != identities[0][1] for item in remaining
        )
        self._kubectl(("rollout", "status", f"deployment/{self.deployment}", "--timeout=10m"))
        recovery_seconds = time.monotonic() - started_clock
        after = _database_state(self.database_url)
        checks = (
            GateCheck("minimum_availability", desired >= 2 and available >= 2),
            GateCheck("target_pod_interrupted", disrupted),
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
            coordinates={
                "namespace": self.namespace,
                "deployment": self.deployment,
                "plan_digest": self.plan.digest,
                "cluster_uid_digest": cluster_uid_digest,
                "kubernetes_api_ca_digest": api_ca_digest,
            },
            checks=checks,
            metrics={"recovery_seconds": round(recovery_seconds, 3), "desired_replicas": desired},
        )

    def upgrade_and_rollback(self, candidate_image: str, migration_job: str) -> GateEvidence:
        started = utc_now()
        cluster_uid_digest, api_ca_digest = self._verify_cluster()
        self._verify_rbac()
        if candidate_image != self.plan.backend_image or migration_job != self.plan.migration_job:
            raise DomainError(
                "CANDIDATE_IMAGE_INVALID", "drill must use the sealed candidate and Job"
            )
        migration = self._apply_migration()
        migration_complete = any(
            item.get("type") == "Complete" and item.get("status") == "True"
            for item in migration.get("status", {}).get("conditions", ())
        )
        migration_containers = (
            migration.get("spec", {}).get("template", {}).get("spec", {}).get("containers", ())
        )
        if (
            not migration_complete
            or not isinstance(migration_containers, list)
            or len(migration_containers) != 1
            or migration_containers[0].get("name") != "migrate"
            or migration_containers[0].get("image") != candidate_image
            or int(migration.get("status", {}).get("succeeded", 0)) != 1
            or int(migration.get("status", {}).get("failed", 0)) != 0
        ):
            raise DomainError(
                "CANDIDATE_MIGRATION_UNVERIFIED",
                "completed candidate-image migration Job is required before upgrade",
            )
        prior_images: dict[str, str] = {}
        for workload in self.plan.workloads:
            resource = json.loads(
                self._kubectl(("get", workload.kind, workload.name, "-o", "json"), 60)
            )
            containers = (
                resource.get("spec", {}).get("template", {}).get("spec", {}).get("containers", ())
            )
            current = next(
                (
                    str(item.get("image"))
                    for item in containers
                    if item.get("name") == workload.container
                ),
                "",
            )
            if (
                not re.fullmatch(r"[^@\s]+@sha256:[a-f0-9]{64}", current)
                or current == workload.image
            ):
                raise DomainError(
                    "ROLLBACK_IMAGE_INVALID",
                    "every prior workload image must be distinct and digest pinned",
                )
            prior_images[workload.name] = current
        before = _database_state(self.database_url)
        prior_contract_ready = _ready(self.readiness_url) and _ready(self.web_readiness_url)
        candidate_images: dict[str, str] = {}
        rollback_images: dict[str, str] = {}
        candidate_contract_ready = False
        rollback_contract_ready = False
        upgrade_started = time.monotonic()
        rollback_seconds = self.maximum_rollback_seconds + 1.0
        try:
            for workload in self.plan.workloads:
                self._kubectl(
                    (
                        "set",
                        "image",
                        f"{workload.kind}/{workload.name}",
                        f"{workload.container}={workload.image}",
                    )
                )
                self._kubectl(
                    ("rollout", "status", f"{workload.kind}/{workload.name}", "--timeout=10m")
                )
                candidate_state = json.loads(
                    self._kubectl(("get", workload.kind, workload.name, "-o", "json"), 60)
                )
                candidate_images[workload.name] = next(
                    (
                        str(item.get("image"))
                        for item in candidate_state.get("spec", {})
                        .get("template", {})
                        .get("spec", {})
                        .get("containers", ())
                        if item.get("name") == workload.container
                    ),
                    "",
                )
            candidate_contract_ready = _ready(self.readiness_url) and _ready(self.web_readiness_url)
        finally:
            rollback_started = time.monotonic()
            try:
                for workload in reversed(self.plan.workloads):
                    self._kubectl(
                        (
                            "set",
                            "image",
                            f"{workload.kind}/{workload.name}",
                            f"{workload.container}={prior_images[workload.name]}",
                        )
                    )
                    self._kubectl(
                        (
                            "rollout",
                            "status",
                            f"{workload.kind}/{workload.name}",
                            "--timeout=10m",
                        )
                    )
                    rollback_state = json.loads(
                        self._kubectl(("get", workload.kind, workload.name, "-o", "json"), 60)
                    )
                    rollback_images[workload.name] = next(
                        (
                            str(item.get("image"))
                            for item in rollback_state.get("spec", {})
                            .get("template", {})
                            .get("spec", {})
                            .get("containers", ())
                            if item.get("name") == workload.container
                        ),
                        "",
                    )
                rollback_contract_ready = _ready(self.readiness_url) and _ready(
                    self.web_readiness_url
                )
                rollback_seconds = time.monotonic() - rollback_started
            finally:
                self._cleanup_migration()
        after = _database_state(self.database_url)
        elapsed = time.monotonic() - upgrade_started
        checks = (
            GateCheck("candidate_migration_completed", migration_complete),
            GateCheck("candidate_migration_cleanup", True),
            GateCheck("prior_contract_ready", prior_contract_ready),
            GateCheck("candidate_contract_ready", candidate_contract_ready),
            GateCheck(
                "all_candidate_images_exact",
                candidate_images == {item.name: item.image for item in self.plan.workloads},
            ),
            GateCheck("rollback_contract_ready", rollback_contract_ready),
            GateCheck("all_rollback_images_exact", rollback_images == prior_images),
            GateCheck("rollback_rto", rollback_seconds <= self.maximum_rollback_seconds),
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
                "candidate_image": candidate_image,
                "migration_job": migration_job,
                "plan_digest": self.plan.digest,
                "cluster_uid_digest": cluster_uid_digest,
                "kubernetes_api_ca_digest": api_ca_digest,
            },
            checks=checks,
            metrics={
                "drill_seconds": round(elapsed, 3),
                "rollback_seconds": round(rollback_seconds, 3),
                "migration_head": after["migration_head"],
                "workloads": len(self.plan.workloads),
            },
        )


class KubernetesChaosSuite:
    """Controlled pod-loss and scale-outage matrix with unconditional replica restoration."""

    def __init__(
        self,
        namespace: str,
        database_url: str,
        *,
        confirmation: str,
        context: str,
        expected_cluster_uid_digest: str,
        expected_kubernetes_api_ca_digest: str,
        plan: ProductionDeploymentPlan,
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
        if (
            namespace != plan.namespace
            or not re.fullmatch(r"[a-f0-9]{64}", expected_cluster_uid_digest)
            or not re.fullmatch(r"[a-f0-9]{64}", expected_kubernetes_api_ca_digest)
        ):
            raise DomainError("DRILL_PLAN_MISMATCH", "chaos drill must match the sealed target")
        self.namespace = namespace
        self.database_url = _require_postgresql(database_url)
        self.runner = runner
        self.context = context
        self.expected_cluster_uid_digest = expected_cluster_uid_digest
        self.expected_kubernetes_api_ca_digest = expected_kubernetes_api_ca_digest
        self.plan = plan
        self.workloads = {(item.kind, item.name): item for item in plan.workloads}

    def _kubectl(self, arguments: Sequence[str], timeout: int = 600) -> str:
        return self.runner(
            ("kubectl", "--context", self.context, "-n", self.namespace, *arguments),
            timeout,
        )

    def _verify_rbac(self) -> None:
        payload = json.loads(self._kubectl(("auth", "can-i", "--list", "-o", "json"), 60))
        if not isinstance(payload, Mapping) or not validate_exact_rbac(payload, CHAOS_DRILL_RBAC):
            raise DomainError("DRILL_RBAC_OVERBROAD", "chaos drill RBAC is not exact")

    def _pod_termination(self, scenario: Mapping[str, Any]) -> tuple[bool, float]:
        workload = str(scenario["workload"])
        kind = str(scenario.get("kind", "deployment"))
        resource = json.loads(self._kubectl(("get", kind, workload, "-o", "json"), 60))
        desired = int(resource.get("spec", {}).get("replicas", 0))
        available = int(resource.get("status", {}).get("availableReplicas", 0))
        if desired < 2 or available < 2:
            raise DomainError(
                "CHAOS_AVAILABILITY_INVALID", "pod termination requires two available replicas"
            )
        pods = json.loads(
            self._kubectl(("get", "pods", "-l", f"app={workload}", "-o", "json"), 60)
        ).get("items", ())
        if kind == "deployment":
            revision = str(
                resource.get("metadata", {})
                .get("annotations", {})
                .get("deployment.kubernetes.io/revision", "")
            )
            replica_sets = json.loads(
                self._kubectl(("get", "replicasets", "-l", f"app={workload}", "-o", "json"), 60)
            ).get("items", ())
            owner_uids = {
                str(item.get("metadata", {}).get("uid"))
                for item in replica_sets
                if item.get("metadata", {})
                .get("annotations", {})
                .get("deployment.kubernetes.io/revision")
                == revision
                and any(
                    owner.get("uid") == resource.get("metadata", {}).get("uid")
                    and owner.get("controller") is True
                    for owner in item.get("metadata", {}).get("ownerReferences", ())
                )
            }
        else:
            owner_uids = {str(resource.get("metadata", {}).get("uid", ""))}
        if len(owner_uids) != 1:
            raise DomainError("CHAOS_OWNER_INVALID", "current workload controller is ambiguous")
        identities = sorted(
            (str(item.get("metadata", {}).get("name")), str(item.get("metadata", {}).get("uid")))
            for item in pods
            if item.get("status", {}).get("phase") == "Running"
            and any(
                owner.get("uid") in owner_uids and owner.get("controller") is True
                for owner in item.get("metadata", {}).get("ownerReferences", ())
            )
        )
        if not identities:
            raise DomainError("CHAOS_POD_MISSING", "no running pod was found")
        started = time.monotonic()
        self._kubectl(("delete", "pod", identities[0][0], "--wait=true"), 60)
        remaining = json.loads(
            self._kubectl(("get", "pods", "-l", f"app={workload}", "-o", "json"), 60)
        ).get("items", ())
        disrupted = all(
            item.get("metadata", {}).get("uid") != identities[0][1] for item in remaining
        )
        self._kubectl(("rollout", "status", f"{kind}/{workload}", "--timeout=10m"))
        return disrupted, time.monotonic() - started

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
            zero = json.loads(self._kubectl(("get", kind, workload, "-o", "json"), 60))
            disrupted = int(zero.get("status", {}).get("replicas", 0)) == 0
        finally:
            self._kubectl(("scale", f"{kind}/{workload}", f"--replicas={replicas}"), 120)
            self._kubectl(("rollout", "status", f"{kind}/{workload}", "--timeout=10m"))
        return disrupted, time.monotonic() - started

    def run(self, scenarios: Sequence[Mapping[str, Any]]) -> GateEvidence:
        started = utc_now()
        cluster_uid_digest, api_ca_digest = cluster_identity(self.runner, self.context)
        if (
            cluster_uid_digest != self.expected_cluster_uid_digest
            or api_ca_digest != self.expected_kubernetes_api_ca_digest
        ):
            raise DomainError(
                "KUBERNETES_CLUSTER_IDENTITY_MISMATCH",
                "chaos drill cluster does not match the signed target profile",
            )
        self._verify_rbac()
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
            maximum_recovery_seconds = float(scenario.get("maximum_recovery_seconds", 0))
            readiness_url = str(scenario.get("readiness_url", ""))
            if (
                not str(scenario.get("name", ""))
                or not str(scenario.get("workload", ""))
                or operation not in {"pod_termination", "scale_outage"}
                or (operation == "scale_outage" and kind not in {"deployment", "statefulset"})
                or not 1 <= maximum_recovery_seconds <= 3600
                or (kind, str(scenario.get("workload", ""))) not in self.workloads
                or not readiness_url
            ):
                raise DomainError("CHAOS_SCENARIO_INVALID", "chaos scenario contract is invalid")
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
                    GateCheck(f"{name}_disruption_observed", recovered),
                    GateCheck(f"{name}_recovered", recovered and ready),
                    GateCheck(f"{name}_recovery_rto", elapsed <= maximum_recovery_seconds),
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
                "plan_digest": self.plan.digest,
                "cluster_uid_digest": cluster_uid_digest,
                "kubernetes_api_ca_digest": api_ca_digest,
            },
            checks=checks,
            metrics=metrics,
        )
