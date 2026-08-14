from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json, utc_now

from .evidence import GateCheck, GateEvidence, complete
from .production_deployment import (
    ProductionDeploymentPlan,
    cluster_identity,
    validate_exact_rbac,
)

CommandRunner = Callable[[Sequence[str], int], str]
PROBE_RBAC = frozenset(
    {
        ("", "pods", "create"),
        ("", "pods", "delete"),
        ("", "pods", "get"),
        ("", "pods/log", "get"),
        ("networking.k8s.io", "networkpolicies", "get"),
        ("networking.k8s.io", "networkpolicies", "list"),
    }
)


def _run(command: Sequence[str], timeout: int) -> str:
    completed = subprocess.run(
        list(command), capture_output=True, text=True, timeout=timeout, check=False
    )
    if completed.returncode:
        raise DomainError(
            "NETWORK_PROBE_COMMAND_FAILED",
            "network probe Kubernetes command failed",
            {"exit_code": completed.returncode},
            status=503,
        )
    return completed.stdout


@dataclass(frozen=True, slots=True)
class NetworkProbeCase:
    name: str
    host: str
    port: int
    expect_allowed: bool

    def validate(self) -> None:
        if not self.name or not self.host or not 1 <= self.port <= 65535:
            raise DomainError("NETWORK_PROBE_INVALID", "network probe case is invalid")


def validate_policy_contract(path: str | Path) -> tuple[GateCheck, ...]:
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as error:
        raise DomainError(
            "YAML_DEPENDENCY_UNAVAILABLE", "PyYAML is required", status=503
        ) from error
    documents = [item for item in yaml.safe_load_all(Path(path).read_text()) if item]
    policies = [item for item in documents if item.get("kind") == "NetworkPolicy"]
    names = {item.get("metadata", {}).get("name") for item in policies}
    broad: list[str] = []
    invalid_cidrs: list[str] = []
    for policy in policies:
        for direction in ("ingress", "egress"):
            for rule in policy.get("spec", {}).get(direction, ()) or ():
                for peer_key in ("to", "from"):
                    for peer in rule.get(peer_key, ()) or ():
                        cidr = peer.get("ipBlock", {}).get("cidr")
                        if not cidr:
                            continue
                        try:
                            network = ipaddress.ip_network(cidr)
                        except ValueError:
                            invalid_cidrs.append(str(cidr))
                            continue
                        if network.prefixlen == 0:
                            broad.append(str(cidr))
    required = {
        "default-deny",
        "dns-egress",
        "control-api-ingress",
        "action-plane",
        "simulator-plane",
        "real-ot-collector-read-only-egress",
        "simulator-collector-read-only-egress",
        "data-jobs-egress",
    }
    return (
        GateCheck("default_deny", "default-deny" in names),
        GateCheck("required_plane_policies", required.issubset(names)),
        GateCheck("no_world_cidrs", not broad, {"broad_cidrs": len(broad)}),
        GateCheck("valid_cidrs", not invalid_cidrs, {"invalid_cidrs": len(invalid_cidrs)}),
    )


def validate_live_policy_contract(
    namespace: str,
    path: str | Path,
    *,
    context: str,
    runner: CommandRunner = _run,
) -> tuple[GateCheck, ...]:
    import yaml  # type: ignore[import-untyped]

    declared = {
        str(item.get("metadata", {}).get("name")): item.get("spec", {})
        for item in yaml.safe_load_all(Path(path).read_text(encoding="utf-8"))
        if item and item.get("kind") == "NetworkPolicy"
    }
    payload = json.loads(
        runner(
            (
                "kubectl",
                "--context",
                context,
                "-n",
                namespace,
                "get",
                "networkpolicy",
                "-o",
                "json",
            ),
            60,
        )
    )
    live = {
        str(item.get("metadata", {}).get("name")): item.get("spec", {})
        for item in payload.get("items", ())
    }
    return (
        GateCheck("live_policy_set_exact", set(live) == set(declared)),
        GateCheck(
            "live_policy_specs_exact",
            set(live) == set(declared)
            and all(
                canonical_digest(live[name]) == canonical_digest(spec)
                for name, spec in declared.items()
            ),
        ),
    )


def validate_probe_rbac(
    namespace: str, *, context: str, runner: CommandRunner = _run
) -> tuple[GateCheck, ...]:
    payload = json.loads(
        runner(
            (
                "kubectl",
                "--context",
                context,
                "-n",
                namespace,
                "auth",
                "can-i",
                "--list",
                "-o",
                "json",
            ),
            30,
        )
    )
    return (GateCheck("probe_rbac_exact", validate_exact_rbac(payload, PROBE_RBAC)),)


def run_network_probe(
    plane: str,
    cases: Sequence[NetworkProbeCase],
    *,
    policy_path: str | Path,
    timeout_seconds: float = 3.0,
) -> GateEvidence:
    started = utc_now()
    if not cases:
        raise DomainError("NETWORK_PROBE_EMPTY", "at least one network case is required")
    checks = list(validate_policy_contract(policy_path))
    allowed = 0
    denied = 0
    for case in cases:
        case.validate()
        connected = False
        started_case = time.monotonic()
        try:
            with socket.create_connection((case.host, case.port), timeout=timeout_seconds):
                connected = True
        except OSError:
            connected = False
        elapsed_ms = int((time.monotonic() - started_case) * 1000)
        passed = connected is case.expect_allowed
        allowed += int(connected)
        denied += int(not connected)
        checks.append(
            GateCheck(
                f"connection_{case.name}",
                passed,
                {
                    "expected": "allowed" if case.expect_allowed else "denied",
                    "observed": "allowed" if connected else "denied",
                    "elapsed_ms": elapsed_ms,
                    "destination_digest": hashlib.sha256(
                        f"{case.host}:{case.port}".encode()
                    ).hexdigest(),
                },
            )
        )
    return complete(
        "network_policy",
        started_at=started,
        coordinates={
            "plane": plane,
            "policy_digest": hashlib.sha256(Path(policy_path).read_bytes()).hexdigest(),
        },
        checks=checks,
        metrics={"cases": len(cases), "connected": allowed, "blocked": denied},
    )


def run_connection_probe(
    plane: str, cases: Sequence[NetworkProbeCase], timeout_seconds: float = 3.0
) -> GateEvidence:
    started = utc_now()
    checks: list[GateCheck] = []
    connected_count = 0
    for case in cases:
        case.validate()
        connected = False
        started_case = time.monotonic()
        try:
            with socket.create_connection((case.host, case.port), timeout=timeout_seconds):
                connected = True
        except OSError:
            connected = False
        connected_count += int(connected)
        checks.append(
            GateCheck(
                f"connection_{case.name}",
                connected is case.expect_allowed,
                {
                    "expected": "allowed" if case.expect_allowed else "denied",
                    "observed": "allowed" if connected else "denied",
                    "elapsed_ms": int((time.monotonic() - started_case) * 1000),
                    "destination_digest": hashlib.sha256(
                        f"{case.host}:{case.port}".encode()
                    ).hexdigest(),
                },
            )
        )
    return complete(
        "network_policy",
        started_at=started,
        coordinates={"plane": plane},
        checks=checks,
        metrics={
            "cases": len(cases),
            "connected": connected_count,
            "blocked": len(cases) - connected_count,
        },
    )


def run_kubernetes_network_probe(
    *,
    namespace: str,
    plane: str,
    image: str,
    cases: Sequence[NetworkProbeCase],
    policy_path: str | Path,
    confirmation: str,
    context: str,
    timeout_seconds: int = 120,
) -> GateEvidence:
    if not re.fullmatch(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?", namespace):
        raise DomainError("NETWORK_PROBE_NAMESPACE_INVALID", "namespace is invalid")
    if namespace in {"default", "kube-system", "kube-public", "kube-node-lease"}:
        raise DomainError("NETWORK_PROBE_NAMESPACE_INVALID", "system namespace is forbidden")
    if not re.fullmatch(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?", plane):
        raise DomainError("NETWORK_PROBE_PLANE_INVALID", "plane label is invalid")
    if confirmation != f"{namespace}:network-policy" or not re.fullmatch(
        r"[^@\s]+@sha256:[a-f0-9]{64}", image
    ):
        raise DomainError(
            "NETWORK_PROBE_CONFIRMATION_REQUIRED",
            "exact confirmation and a digest-pinned image are required",
        )
    pod = "shadow-netprobe-" + uuid.uuid4().hex[:12]
    encoded = base64.b64encode(
        json.dumps([asdict(item) for item in cases], separators=(",", ":")).encode()
    ).decode("ascii")
    labels = {"app": plane, "shadow-probe": "network-policy"}
    if plane == "real-ot-collector":
        labels["collector-target"] = "real-ot"
    elif plane == "simulator-collector":
        labels["collector-target"] = "simulator"
    manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod,
            "namespace": namespace,
            "labels": labels,
        },
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {
                "runAsNonRoot": True,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [
                {
                    "name": "network-probe",
                    "image": image,
                    "command": ["python", "-m", "shadow_sandbox.operations.network_probe"],
                    "args": ["--connection-only"],
                    "env": [
                        {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                        {"name": "SHADOW_NETWORK_CASES_B64", "value": encoded},
                        {"name": "SHADOW_NETWORK_PLANE", "value": plane},
                    ],
                    "resources": {
                        "requests": {"cpu": "10m", "memory": "32Mi"},
                        "limits": {"cpu": "250m", "memory": "128Mi"},
                    },
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]},
                    },
                }
            ],
        },
    }
    command = ["kubectl", "--context", context, "-n", namespace, "create", "-f", "-"]
    started = utc_now()
    result: GateEvidence | None = None
    cleanup_succeeded = False
    try:
        created = subprocess.run(
            command,
            input=canonical_json(manifest),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if created.returncode:
            raise DomainError(
                "NETWORK_PROBE_POD_FAILED", "could not create network probe pod", status=503
            )
        deadline = time.monotonic() + timeout_seconds
        phase = ""
        while time.monotonic() < deadline:
            status = subprocess.run(
                (
                    "kubectl",
                    "--context",
                    context,
                    "-n",
                    namespace,
                    "get",
                    "pod",
                    pod,
                    "-o",
                    "jsonpath={.status.phase}",
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
            )
            phase = status.stdout
            if phase in {"Succeeded", "Failed"}:
                break
            time.sleep(1)
        if phase not in {"Succeeded", "Failed"}:
            raise DomainError("NETWORK_PROBE_TIMEOUT", "network probe pod timed out")
        logs = subprocess.run(
            ("kubectl", "--context", context, "-n", namespace, "logs", pod),
            capture_output=True,
            text=True,
            check=False,
        )
        if logs.returncode or not logs.stdout.strip():
            raise DomainError("NETWORK_PROBE_LOGS_MISSING", "network probe output is missing")
        payload = json.loads(logs.stdout.strip().splitlines()[-1])
        payload["checks"] = tuple(GateCheck(**item) for item in payload["checks"])
        live = GateEvidence(**payload)
        live.verify()
        checks = (*validate_policy_contract(policy_path), *live.checks)
        result = complete(
            "network_policy",
            started_at=started,
            coordinates={
                "namespace": namespace,
                "plane": plane,
                "image": image,
                "policy_digest": hashlib.sha256(Path(policy_path).read_bytes()).hexdigest(),
            },
            checks=checks,
            metrics=dict(live.metrics),
        )
    finally:
        deleted = subprocess.run(
            (
                "kubectl",
                "--context",
                context,
                "-n",
                namespace,
                "delete",
                "pod",
                pod,
                "--ignore-not-found=true",
            ),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        cleanup_succeeded = deleted.returncode == 0
    if result is None:
        raise DomainError("NETWORK_PROBE_FAILED", "network probe produced no evidence")
    if not cleanup_succeeded:
        raise DomainError("NETWORK_PROBE_CLEANUP_FAILED", "network probe pod cleanup failed")
    return complete(
        "network_policy",
        started_at=result.started_at,
        coordinates={"probe_digest": result.digest, "cleanup": "deleted"},
        checks=(*result.checks, GateCheck("probe_pod_deleted", True)),
        metrics=result.metrics,
    )


def run_kubernetes_policy_suite(
    *,
    namespace: str,
    probes: Sequence[Mapping[str, Any]],
    policy_path: str | Path,
    confirmation: str,
    context: str,
    expected_cluster_uid_digest: str,
    expected_kubernetes_api_ca_digest: str,
    plan: ProductionDeploymentPlan,
    runner: CommandRunner = _run,
    timeout_seconds: int = 120,
) -> GateEvidence:
    started = utc_now()
    if (
        namespace != plan.namespace
        or Path(policy_path).resolve(strict=True) != plan.bootstrap_manifest.path
    ):
        raise DomainError(
            "NETWORK_POLICY_PLAN_MISMATCH",
            "network policy suite must use the sealed plan namespace and bootstrap policy artifact",
        )
    observed_cluster_uid_digest, api_ca_digest = cluster_identity(runner, context)
    if (
        observed_cluster_uid_digest != expected_cluster_uid_digest
        or api_ca_digest != expected_kubernetes_api_ca_digest
    ):
        raise DomainError(
            "KUBERNETES_CLUSTER_IDENTITY_MISMATCH",
            "network probe cluster does not match the signed target profile",
        )
    if not probes:
        raise DomainError("NETWORK_PROBE_EMPTY", "at least one plane probe is required")
    planes = [str(item.get("plane", "")) for item in probes]
    if len(planes) != len(set(planes)) or not {
        "control-api",
        "action-executor",
        "real-ot-collector",
        "simulator-collector",
    }.issubset(planes):
        raise DomainError(
            "NETWORK_PROBE_COVERAGE_INVALID",
            "network probes must uniquely cover the required planes",
        )
    for item in probes:
        image = str(item.get("image", ""))
        cases = tuple(NetworkProbeCase(**case) for case in item.get("cases", ()))
        for case in cases:
            case.validate()
        if (
            confirmation != f"{namespace}:network-policy"
            or not re.fullmatch(r"[^@\s]+@sha256:[a-f0-9]{64}", image)
            or {case.expect_allowed for case in cases} != {False, True}
        ):
            raise DomainError(
                "NETWORK_PROBE_COVERAGE_INVALID",
                "every plane needs a pinned image and allowed/denied cases",
            )
    checks = [
        *validate_policy_contract(policy_path),
        *validate_live_policy_contract(namespace, policy_path, context=context, runner=runner),
        *validate_probe_rbac(namespace, context=context, runner=runner),
    ]
    case_count = 0
    connected = 0
    blocked = 0
    plane_digests: dict[str, str] = {}
    for item in probes:
        plane = str(item["plane"])
        cases = tuple(NetworkProbeCase(**case) for case in item["cases"])
        if not {case.expect_allowed for case in cases} == {False, True}:
            raise DomainError(
                "NETWORK_PROBE_COVERAGE_INVALID",
                "each plane requires at least one allowed and one denied destination",
            )
        evidence = run_kubernetes_network_probe(
            namespace=namespace,
            plane=plane,
            image=str(item["image"]),
            cases=cases,
            policy_path=policy_path,
            confirmation=confirmation,
            context=context,
            timeout_seconds=timeout_seconds,
        )
        plane_digests[plane] = evidence.digest
        checks.extend(
            GateCheck(f"{plane}_{check.name}", check.passed, check.details)
            for check in evidence.checks
            if check.name.startswith("connection_")
        )
        case_count += int(evidence.metrics["cases"])
        connected += int(evidence.metrics["connected"])
        blocked += int(evidence.metrics["blocked"])
    return complete(
        "network_policy",
        started_at=started,
        coordinates={
            "namespace": namespace,
            "planes": plane_digests,
            "policy_digest": hashlib.sha256(Path(policy_path).read_bytes()).hexdigest(),
            "plan_digest": plan.digest,
            "cluster_uid_digest": observed_cluster_uid_digest,
            "kubernetes_api_ca_digest": api_ca_digest,
        },
        checks=checks,
        metrics={
            "planes": len(probes),
            "cases": case_count,
            "connected": connected,
            "blocked": blocked,
        },
    )


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--connection-only", action="store_true")
    args = parser.parse_args()
    if not args.connection_only:
        parser.error("this module entrypoint is only for the isolated connection probe")
    encoded = os.environ.get("SHADOW_NETWORK_CASES_B64", "")
    plane = os.environ.get("SHADOW_NETWORK_PLANE", "")
    try:
        raw = json.loads(base64.b64decode(encoded, validate=True))
        cases = tuple(NetworkProbeCase(**item) for item in raw)
    except Exception as error:
        raise SystemExit("invalid network probe configuration") from error
    evidence = run_connection_probe(plane, cases)
    print(canonical_json(asdict(evidence)))
    return 0 if evidence.status == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
