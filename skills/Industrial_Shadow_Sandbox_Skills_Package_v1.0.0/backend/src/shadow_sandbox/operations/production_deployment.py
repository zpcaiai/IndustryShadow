from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

import yaml  # pyright: ignore[reportMissingModuleSource]

from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now

from .evidence import GateCheck, GateEvidence, complete

IMAGE_DIGEST = re.compile(r"^[^@\s]+@sha256:[a-f0-9]{64}$")
DIGEST = re.compile(r"^[a-f0-9]{64}$")
KUBERNETES_NAME = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
PLACEHOLDER = re.compile(
    r"(?:\.invalid\b|\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\."
    r"|sha256:0{64}\b)",
    re.IGNORECASE,
)
PLAN_KEYS = frozenset(
    {
        "schema_version",
        "plan_id",
        "namespace",
        "backend_image",
        "web_image",
        "bootstrap_manifest",
        "migration_manifest",
        "runtime_manifest",
        "rollback_manifest",
        "migration_job",
        "workloads",
        "digest",
    }
)
MANIFEST_KEYS = frozenset({"path", "sha256"})
WORKLOAD_KEYS = frozenset({"kind", "name", "container", "image", "readiness_url"})
EXPECTED_WORKLOADS = frozenset(
    {
        ("deployment", "control-api", "api", "backend"),
        ("deployment", "worker", "worker", "backend"),
        ("deployment", "action-executor", "action-executor", "backend"),
        ("statefulset", "simulator", "simulator", "backend"),
        ("deployment", "collector", "collector", "backend"),
        ("deployment", "web", "web", "web"),
    }
)
PHASE_KINDS = {
    "bootstrap_manifest": frozenset(
        {"ConfigMap", "ServiceAccount", "Service", "NetworkPolicy", "CronJob"}
    ),
    "migration_manifest": frozenset({"Job"}),
    "runtime_manifest": frozenset({"Deployment", "StatefulSet", "Service"}),
    "rollback_manifest": frozenset(
        {
            "ConfigMap",
            "ServiceAccount",
            "Service",
            "NetworkPolicy",
            "CronJob",
            "Deployment",
            "StatefulSet",
        }
    ),
}
POD_KINDS = frozenset({"Deployment", "StatefulSet", "Job", "CronJob"})

CommandRunner = Callable[[Sequence[str], int], str]
ReadinessProbe = Callable[[str], bool]


def _manifest_objects(text: str) -> list[Mapping[str, Any]]:
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as error:
        raise DomainError(
            "DEPLOYMENT_ARTIFACT_INVALID", "deployment artifact is not valid YAML"
        ) from error
    objects: list[Mapping[str, Any]] = []

    def append(value: Any) -> None:
        if not isinstance(value, Mapping):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_INVALID",
                "deployment artifact contains an invalid Kubernetes object",
            )
        if value.get("kind") == "List":
            items = value.get("items")
            if not isinstance(items, list) or not items:
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_INVALID",
                    "Kubernetes List artifacts require non-empty items",
                )
            for item in items:
                append(item)
            return
        objects.append(value)

    for document in documents:
        if document is not None:
            append(document)
    if not objects:
        raise DomainError("DEPLOYMENT_ARTIFACT_INVALID", "deployment artifact contains no objects")
    return objects


def _pod_spec(value: Mapping[str, Any]) -> Mapping[str, Any] | None:
    kind = value.get("kind")
    spec = value.get("spec")
    if not isinstance(spec, Mapping):
        return None
    if kind in {"Deployment", "StatefulSet", "Job"}:
        template = spec.get("template")
    elif kind == "CronJob":
        job_template = spec.get("jobTemplate")
        job_spec = job_template.get("spec") if isinstance(job_template, Mapping) else None
        template = job_spec.get("template") if isinstance(job_spec, Mapping) else None
    else:
        return None
    template_spec = template.get("spec") if isinstance(template, Mapping) else None
    return template_spec if isinstance(template_spec, Mapping) else None


def _validate_pod_security(value: Mapping[str, Any], allowed_images: frozenset[str] | None) -> None:
    pod_spec = _pod_spec(value)
    if pod_spec is None:
        raise DomainError("DEPLOYMENT_ARTIFACT_INVALID", "workload Pod specification is missing")
    if any(pod_spec.get(name) is True for name in ("hostNetwork", "hostPID", "hostIPC")):
        raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "host namespace access is forbidden")
    security = pod_spec.get("securityContext")
    seccomp = security.get("seccompProfile") if isinstance(security, Mapping) else None
    if (
        not isinstance(security, Mapping)
        or security.get("runAsNonRoot") is not True
        or not isinstance(seccomp, Mapping)
        or seccomp.get("type") not in {"RuntimeDefault", "Localhost"}
    ):
        raise DomainError(
            "DEPLOYMENT_ARTIFACT_UNSAFE",
            "restricted Pod security context is required",
        )
    volumes = pod_spec.get("volumes", [])
    if not isinstance(volumes, list) or any(
        isinstance(volume, Mapping) and "hostPath" in volume for volume in volumes
    ):
        raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "hostPath volumes are forbidden")
    containers: list[Any] = []
    for field in ("initContainers", "containers"):
        raw = pod_spec.get(field, [])
        if not isinstance(raw, list):
            raise DomainError("DEPLOYMENT_ARTIFACT_INVALID", "workload containers are invalid")
        containers.extend(raw)
    if not containers:
        raise DomainError("DEPLOYMENT_ARTIFACT_INVALID", "workload containers are missing")
    for container in containers:
        image = str(container.get("image", "")) if isinstance(container, Mapping) else ""
        if (
            not isinstance(container, Mapping)
            or not IMAGE_DIGEST.fullmatch(image)
            or (allowed_images is not None and image not in allowed_images)
        ):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_IMAGE_INVALID",
                "every workload image must be closure-bound and scanned",
            )
        ports = container.get("ports", [])
        if not isinstance(ports, list) or any(
            isinstance(port, Mapping) and "hostPort" in port for port in ports
        ):
            raise DomainError("DEPLOYMENT_ARTIFACT_UNSAFE", "host ports are forbidden")
        container_security = container.get("securityContext")
        capabilities = (
            container_security.get("capabilities")
            if isinstance(container_security, Mapping)
            else None
        )
        drops = capabilities.get("drop", ()) if isinstance(capabilities, Mapping) else ()
        additions = capabilities.get("add", ()) if isinstance(capabilities, Mapping) else ()
        if (
            not isinstance(container_security, Mapping)
            or container_security.get("privileged") is True
            or container_security.get("allowPrivilegeEscalation") is not False
            or container_security.get("readOnlyRootFilesystem") is not True
            or not isinstance(drops, list)
            or "ALL" not in drops
            or bool(additions)
        ):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_UNSAFE",
                "restricted container security context is required",
            )


def _run(command: Sequence[str], timeout: int) -> str:
    import subprocess

    completed = subprocess.run(
        list(command),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode:
        raise DomainError(
            "PRODUCTION_DEPLOY_COMMAND_FAILED",
            "production deployment command failed",
            {
                "verb": command[1] if len(command) > 1 else "unknown",
                "exit_code": completed.returncode,
            },
            status=503,
        )
    return completed.stdout


def _ready(url: str) -> bool:
    if not url:
        return True
    try:
        with urlopen(Request(url, method="GET"), timeout=15) as response:
            return int(response.status) == 200
    except OSError:
        return False


@dataclass(frozen=True, slots=True)
class DeploymentArtifact:
    path: Path
    sha256: str


@dataclass(frozen=True, slots=True)
class DeploymentWorkload:
    kind: str
    name: str
    container: str
    image: str
    readiness_url: str


@dataclass(frozen=True, slots=True)
class ProductionDeploymentPlan:
    plan_id: str
    namespace: str
    backend_image: str
    web_image: str
    bootstrap_manifest: DeploymentArtifact
    migration_manifest: DeploymentArtifact
    runtime_manifest: DeploymentArtifact
    rollback_manifest: DeploymentArtifact
    migration_job: str
    workloads: tuple[DeploymentWorkload, ...]
    rollback_images: tuple[str, ...]
    digest: str

    @classmethod
    def load(
        cls,
        repository_root: str | Path,
        path: str | Path,
        *,
        candidate_image: str,
        expected_digest: str,
    ) -> ProductionDeploymentPlan:
        root = Path(repository_root).resolve(strict=True)
        source = Path(path)
        if not source.is_absolute():
            source = root / source
        resolved_source = source.resolve(strict=True)
        if root not in resolved_source.parents or resolved_source.is_symlink():
            raise DomainError(
                "DEPLOYMENT_PLAN_INVALID", "deployment plan must be inside the repository"
            )
        try:
            payload = json.loads(resolved_source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise DomainError(
                "DEPLOYMENT_PLAN_INVALID", "deployment plan is not valid JSON"
            ) from error
        if (
            not isinstance(payload, Mapping)
            or set(payload) != PLAN_KEYS
            or payload.get("schema_version") != 1
        ):
            raise DomainError("DEPLOYMENT_PLAN_INVALID", "deployment plan fields are invalid")
        claimed_digest = str(payload.get("digest", ""))
        if (
            not DIGEST.fullmatch(claimed_digest)
            or claimed_digest != canonical_digest({**payload, "digest": ""})
            or claimed_digest != expected_digest
        ):
            raise DomainError("DEPLOYMENT_PLAN_DIGEST_INVALID", "deployment plan digest mismatch")
        plan_id = str(payload.get("plan_id", ""))
        namespace = str(payload.get("namespace", ""))
        backend_image = str(payload.get("backend_image", ""))
        web_image = str(payload.get("web_image", ""))
        migration_job = str(payload.get("migration_job", ""))
        if (
            not KUBERNETES_NAME.fullmatch(plan_id)
            or not KUBERNETES_NAME.fullmatch(namespace)
            or namespace in {"default", "kube-system", "kube-public", "kube-node-lease"}
            or not KUBERNETES_NAME.fullmatch(migration_job)
            or plan_id not in migration_job
            or backend_image != candidate_image
            or not IMAGE_DIGEST.fullmatch(backend_image)
            or not IMAGE_DIGEST.fullmatch(web_image)
        ):
            raise DomainError(
                "DEPLOYMENT_PLAN_INVALID",
                "deployment identifiers or immutable images are invalid",
            )

        def artifact(name: str) -> DeploymentArtifact:
            value = payload.get(name)
            if not isinstance(value, Mapping) or set(value) != MANIFEST_KEYS:
                raise DomainError(
                    "DEPLOYMENT_PLAN_INVALID", "deployment artifact fields are invalid"
                )
            expected = str(value.get("sha256", ""))
            artifact_path = (root / str(value.get("path", ""))).resolve(strict=True)
            if (
                root not in artifact_path.parents
                or artifact_path.is_symlink()
                or not artifact_path.is_file()
                or not DIGEST.fullmatch(expected)
                or hashlib.sha256(artifact_path.read_bytes()).hexdigest() != expected
            ):
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_INVALID",
                    "deployment artifact is missing, unsafe, or digest-mismatched",
                )
            return DeploymentArtifact(artifact_path, expected)

        artifacts = {
            name: artifact(name)
            for name in (
                "bootstrap_manifest",
                "migration_manifest",
                "runtime_manifest",
                "rollback_manifest",
            )
        }
        if len({value.path for value in artifacts.values()}) != len(artifacts):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_INVALID", "deployment artifacts must be distinct"
            )
        manifest_text = {
            name: value.path.read_text(encoding="utf-8") for name, value in artifacts.items()
        }
        if any(PLACEHOLDER.search(value) for value in manifest_text.values()) or any(
            re.search(r"(?m)^kind:\s*Secret\s*$", value) for value in manifest_text.values()
        ):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_INVALID",
                "deployment artifacts contain non-production placeholders",
            )
        manifest_objects: dict[str, list[Mapping[str, Any]]] = {}
        for phase, text in manifest_text.items():
            objects = _manifest_objects(text)
            identities: set[tuple[str, str]] = set()
            for value in objects:
                kind = str(value.get("kind", ""))
                api_version = str(value.get("apiVersion", ""))
                metadata = value.get("metadata")
                name = str(metadata.get("name", "")) if isinstance(metadata, Mapping) else ""
                object_namespace = (
                    str(metadata.get("namespace", "")) if isinstance(metadata, Mapping) else ""
                )
                identity = (kind, name)
                if (
                    kind not in PHASE_KINDS[phase]
                    or not api_version
                    or not isinstance(metadata, Mapping)
                    or "generateName" in metadata
                    or not KUBERNETES_NAME.fullmatch(name)
                    or object_namespace not in {"", namespace}
                    or identity in identities
                ):
                    raise DomainError(
                        "DEPLOYMENT_ARTIFACT_SCOPE_INVALID",
                        "deployment artifact contains an undeclared or out-of-scope object",
                    )
                identities.add(identity)
                if kind in POD_KINDS:
                    _validate_pod_security(
                        value,
                        None
                        if phase == "rollback_manifest"
                        else frozenset({backend_image, web_image}),
                    )
            manifest_objects[phase] = objects
        if (
            migration_job not in manifest_text["migration_manifest"]
            or backend_image not in manifest_text["migration_manifest"]
            or backend_image not in manifest_text["runtime_manifest"]
            or web_image not in manifest_text["runtime_manifest"]
            or "@sha256:" not in manifest_text["rollback_manifest"]
        ):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_INVALID",
                "phased manifests do not carry the declared release images and Job",
            )
        raw_workloads = payload.get("workloads")
        if not isinstance(raw_workloads, list) or any(
            not isinstance(item, Mapping) or set(item) != WORKLOAD_KEYS for item in raw_workloads
        ):
            raise DomainError("DEPLOYMENT_PLAN_INVALID", "deployment workloads are invalid")
        workloads: list[DeploymentWorkload] = []
        observed: set[tuple[str, str, str, str]] = set()
        for item in raw_workloads:
            kind = str(item["kind"])
            name = str(item["name"])
            container = str(item["container"])
            image_role = str(item["image"])
            readiness_url = str(item["readiness_url"])
            identity = (kind, name, container, image_role)
            if (
                identity not in EXPECTED_WORKLOADS
                or not KUBERNETES_NAME.fullmatch(name)
                or not KUBERNETES_NAME.fullmatch(container)
                or (readiness_url and not readiness_url.startswith("https://"))
                or bool(PLACEHOLDER.search(readiness_url))
            ):
                raise DomainError("DEPLOYMENT_PLAN_INVALID", "deployment workload is invalid")
            observed.add(identity)
            workloads.append(
                DeploymentWorkload(
                    kind,
                    name,
                    container,
                    backend_image if image_role == "backend" else web_image,
                    readiness_url,
                )
            )
        if observed != EXPECTED_WORKLOADS or len(workloads) != len(observed):
            raise DomainError(
                "DEPLOYMENT_PLAN_COVERAGE_INCOMPLETE",
                "deployment plan must cover every production workload exactly once",
            )
        expected_resources = {(kind, name) for kind, name, _container, _role in observed}
        runtime_resources = {
            (str(value["kind"]).lower(), str(value["metadata"]["name"]))
            for value in manifest_objects["runtime_manifest"]
            if value["kind"] in {"Deployment", "StatefulSet"}
        }
        bootstrap_resources = {
            (str(value["kind"]), str(value["metadata"]["name"]))
            for value in manifest_objects["bootstrap_manifest"]
        }
        runtime_all_resources = {
            (str(value["kind"]), str(value["metadata"]["name"]))
            for value in manifest_objects["runtime_manifest"]
        }
        rollback_resources = {
            (str(value["kind"]), str(value["metadata"]["name"]))
            for value in manifest_objects["rollback_manifest"]
        }
        migration_jobs = {
            str(value["metadata"]["name"]) for value in manifest_objects["migration_manifest"]
        }
        if (
            runtime_resources != expected_resources
            or bootstrap_resources & runtime_all_resources
            or rollback_resources != bootstrap_resources | runtime_all_resources
            or migration_jobs != {migration_job}
        ):
            raise DomainError(
                "DEPLOYMENT_PLAN_COVERAGE_INCOMPLETE",
                "phased manifests must exactly cover the declared Job and workloads",
            )
        runtime_objects = {
            (str(value["kind"]).lower(), str(value["metadata"]["name"])): value
            for value in manifest_objects["runtime_manifest"]
            if value["kind"] in {"Deployment", "StatefulSet"}
        }
        rollback_objects = {
            (str(value["kind"]).lower(), str(value["metadata"]["name"])): value
            for value in manifest_objects["rollback_manifest"]
        }

        def declared_image(value: Mapping[str, Any], container_name: str) -> str:
            pod_spec = _pod_spec(value)
            containers = pod_spec.get("containers", []) if pod_spec else []
            if not isinstance(containers, list) or len(containers) != 1:
                raise DomainError(
                    "DEPLOYMENT_PLAN_COVERAGE_INCOMPLETE",
                    "declared workloads must contain exactly one runtime container",
                )
            container = containers[0]
            if not isinstance(container, Mapping) or container.get("name") != container_name:
                raise DomainError(
                    "DEPLOYMENT_PLAN_COVERAGE_INCOMPLETE",
                    "manifest container does not match the declared workload",
                )
            return str(container.get("image", ""))

        rollback_images: list[str] = []
        rollback_roles: dict[str, set[str]] = {"backend": set(), "web": set()}
        for workload, raw in zip(workloads, raw_workloads, strict=True):
            identity = (workload.kind, workload.name)
            if declared_image(runtime_objects[identity], workload.container) != workload.image:
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_IMAGE_INVALID",
                    "runtime manifest image does not match the deployment plan",
                )
            rollback_image = declared_image(rollback_objects[identity], workload.container)
            if not IMAGE_DIGEST.fullmatch(rollback_image):
                raise DomainError(
                    "DEPLOYMENT_ARTIFACT_IMAGE_INVALID",
                    "rollback workload image must be immutable",
                )
            rollback_images.append(rollback_image)
            rollback_roles[str(raw["image"])].add(rollback_image)
        if any(len(images) != 1 for images in rollback_roles.values()):
            raise DomainError(
                "DEPLOYMENT_ARTIFACT_IMAGE_INVALID",
                "rollback backend and Web workloads must each use one exact image",
            )
        if not all(item.readiness_url for item in workloads if item.name in {"control-api", "web"}):
            raise DomainError(
                "DEPLOYMENT_PLAN_COVERAGE_INCOMPLETE",
                "API and web readiness URLs are required",
            )
        return cls(
            plan_id,
            namespace,
            backend_image,
            web_image,
            artifacts["bootstrap_manifest"],
            artifacts["migration_manifest"],
            artifacts["runtime_manifest"],
            artifacts["rollback_manifest"],
            migration_job,
            tuple(workloads),
            tuple(rollback_images),
            claimed_digest,
        )


class KubernetesProductionPublisher:
    """Apply an approved phased manifest bundle and restore the prior bundle on failure."""

    def __init__(
        self,
        plan: ProductionDeploymentPlan,
        *,
        confirmation: str,
        runner: CommandRunner = _run,
        readiness_probe: ReadinessProbe = _ready,
    ) -> None:
        if confirmation != f"{plan.namespace}:{plan.plan_id}:deploy":
            raise DomainError(
                "PRODUCTION_DEPLOY_CONFIRMATION_REQUIRED",
                "exact production deployment confirmation is required",
            )
        self.plan = plan
        self.runner = runner
        self.readiness_probe = readiness_probe

    def _kubectl(self, arguments: Sequence[str], timeout: int = 900) -> str:
        return self.runner(("kubectl", "-n", self.plan.namespace, *arguments), timeout)

    def _apply(self, artifact: DeploymentArtifact) -> None:
        self._kubectl(
            (
                "apply",
                "--server-side",
                "--field-manager=industrial-shadow-release",
                "-f",
                str(artifact.path),
            )
        )

    def _rollouts(self) -> None:
        for workload in self.plan.workloads:
            self._kubectl(
                (
                    "rollout",
                    "status",
                    f"{workload.kind}/{workload.name}",
                    "--timeout=10m",
                )
            )

    def _observed_workloads(self) -> tuple[dict[str, str], dict[str, bool]]:
        observed_images: dict[str, str] = {}
        readiness: dict[str, bool] = {}
        for workload in self.plan.workloads:
            state = json.loads(
                self._kubectl(("get", workload.kind, workload.name, "-o", "json"), 60)
            )
            containers = (
                state.get("spec", {}).get("template", {}).get("spec", {}).get("containers", ())
            )
            observed_images[workload.name] = next(
                (
                    str(item.get("image"))
                    for item in containers
                    if item.get("name") == workload.container
                ),
                "",
            )
            readiness[workload.name] = self.readiness_probe(workload.readiness_url)
        return observed_images, readiness

    def _rollback(self) -> None:
        self._apply(self.plan.rollback_manifest)
        self._rollouts()
        observed_images, readiness = self._observed_workloads()
        expected = {
            workload.name: image
            for workload, image in zip(self.plan.workloads, self.plan.rollback_images, strict=True)
        }
        if observed_images != expected or not all(readiness.values()):
            raise DomainError(
                "PRODUCTION_DEPLOY_ROLLBACK_VERIFICATION_FAILED",
                "prior images or readiness were not restored",
                status=503,
            )

    def run(self) -> GateEvidence:
        started = utc_now()
        permissions = tuple(
            (verb, resource)
            for resource, verbs in (
                ("deployments.apps", ("get", "watch", "create", "patch")),
                ("statefulsets.apps", ("get", "watch", "create", "patch")),
                ("jobs.batch", ("get", "list", "watch", "create", "patch")),
                ("configmaps", ("get", "create", "patch")),
                ("services", ("get", "create", "patch")),
                ("serviceaccounts", ("get", "create", "patch")),
                (
                    "networkpolicies.networking.k8s.io",
                    ("get", "create", "patch"),
                ),
                ("cronjobs.batch", ("get", "create", "patch")),
            )
            for verb in verbs
        )
        for verb, resource in permissions:
            allowed = self._kubectl(("auth", "can-i", verb, resource), 60).strip()
            if allowed != "yes":
                raise DomainError(
                    "PRODUCTION_DEPLOY_RBAC_DENIED",
                    "deployment runner lacks the required narrow Kubernetes permission",
                )
        forbidden_permissions = (
            ("*", "*"),
            *((verb, "secrets") for verb in ("get", "list", "watch", "create", "patch")),
            *(
                (verb, resource)
                for verb in ("create", "patch", "update")
                for resource in (
                    "roles.rbac.authorization.k8s.io",
                    "rolebindings.rbac.authorization.k8s.io",
                )
            ),
            ("create", "serviceaccounts/token"),
            ("create", "pods/exec"),
        )
        for verb, resource in forbidden_permissions:
            allowed = self._kubectl(("auth", "can-i", verb, resource), 60).strip()
            if allowed == "yes":
                raise DomainError(
                    "PRODUCTION_DEPLOY_RBAC_OVERBROAD",
                    "deployment runner has forbidden broad or secret-reading permissions",
                )
        for artifact in (
            self.plan.bootstrap_manifest,
            self.plan.migration_manifest,
            self.plan.runtime_manifest,
            self.plan.rollback_manifest,
        ):
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
        mutation_attempted = False
        rollback_completed = False
        try:
            mutation_attempted = True
            self._apply(self.plan.bootstrap_manifest)
            self._apply(self.plan.migration_manifest)
            self._kubectl(
                (
                    "wait",
                    "--for=condition=complete",
                    f"job/{self.plan.migration_job}",
                    "--timeout=10m",
                )
            )
            migration = json.loads(
                self._kubectl(("get", "job", self.plan.migration_job, "-o", "json"), 60)
            )
            migration_images = {
                str(item.get("image"))
                for item in migration.get("spec", {})
                .get("template", {})
                .get("spec", {})
                .get("containers", ())
            }
            if migration_images != {self.plan.backend_image}:
                raise DomainError(
                    "PRODUCTION_DEPLOY_MIGRATION_INVALID",
                    "migration Job does not exclusively use the closure-bound backend image",
                )
            self._apply(self.plan.runtime_manifest)
            self._rollouts()
            observed_images, readiness = self._observed_workloads()
            checks = (
                GateCheck("narrow_rbac", True),
                GateCheck("server_side_dry_run", True),
                GateCheck("candidate_migration_completed", True),
                GateCheck(
                    "exact_workload_images",
                    all(observed_images[item.name] == item.image for item in self.plan.workloads),
                ),
                GateCheck("all_rollouts_ready", all(readiness.values())),
            )
            evidence = complete(
                "production_deployment",
                started_at=started,
                coordinates={
                    "plan_digest": self.plan.digest,
                    "namespace": self.plan.namespace,
                    "backend_image": self.plan.backend_image,
                    "web_image": self.plan.web_image,
                },
                checks=checks,
                metrics={
                    "workloads": len(self.plan.workloads),
                    "ready_workloads": sum(readiness.values()),
                },
            )
            if evidence.status != "PASSED":
                self._rollback()
                rollback_completed = True
            return evidence
        except Exception:
            if mutation_attempted and not rollback_completed:
                try:
                    self._rollback()
                except Exception as rollback_error:
                    raise DomainError(
                        "PRODUCTION_DEPLOY_ROLLBACK_FAILED",
                        "deployment failed and the prior manifest could not be restored",
                        status=503,
                    ) from rollback_error
            raise
