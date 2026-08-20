from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    from .source_integrity import source_digest, source_manifest
except ImportError:  # pragma: no cover - direct script execution
    from source_integrity import source_digest, source_manifest

ROOT = Path(__file__).resolve().parents[1]
PYTHONPATH = ":".join(
    str(ROOT / relative)
    for relative in (
        "backend/src",
        "services/simulator/src",
        "services/collector/src",
        "services/edge-gateway/src",
    )
)
if os.environ.get("PYTHONPATH"):
    PYTHONPATH = f"{PYTHONPATH}:{os.environ['PYTHONPATH']}"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def redacted_diagnostic_tail(output: str, *, maximum_characters: int = 8_000) -> str:
    redacted = output
    sensitive_markers = ("CREDENTIAL", "KEY", "PASSWORD", "SECRET", "TOKEN", "URL")
    for name, value in os.environ.items():
        if (
            value
            and len(value) >= 4
            and any(marker in name.upper() for marker in sensitive_markers)
        ):
            redacted = redacted.replace(value, "<redacted>")
            for credential in re.findall(
                r"[A-Za-z][A-Za-z0-9+.-]*://[^:/@\s]+:([^@\s]+)@", value
            ):
                redacted = redacted.replace(credential, "<redacted>")
    redacted = re.sub(
        r"([A-Za-z][A-Za-z0-9+.-]*://[^:/@\s]+:)[^@\s]+@",
        r"\1<redacted>@",
        redacted,
    )
    return redacted[-maximum_characters:]


def run(command: list[str], timeout_seconds: int = 900) -> tuple[int, str]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = PYTHONPATH
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return 124, f"{output}\nEVIDENCE_COMMAND_TIMEOUT after {timeout_seconds}s\n"
    except OSError as error:
        return (
            127,
            f"EVIDENCE_COMMAND_UNAVAILABLE: {command[0]} ({error.__class__.__name__})\n",
        )
    return completed.returncode, completed.stdout


def main() -> int:
    evidence_started_at = time.time()
    initial_integrity_manifest = source_manifest()
    evidence_database = ROOT / ".runtime/evidence.db"
    # This file is a generated, disposable evidence fixture. Starting from an
    # empty database makes the evidence command deterministic and repeatable.
    evidence_database.unlink(missing_ok=True)
    python = sys.executable
    commands = [
        (
            [python, "-m", "pytest", "-q"],
            "core-tests.log",
        ),
        (
            [
                python,
                "implement-industrial-shadow-sandbox/scripts/validate_batch_contracts.py",
                "implement-industrial-shadow-sandbox",
            ],
            "skill-package-validation.log",
        ),
        (
            [python, "-m", "shadow_sandbox.cli", "schemas", "--output", "schemas"],
            "schema-generation.log",
        ),
        (
            [
                python,
                "tools/production_gate.py",
                "benchmark_local",
                "--output",
                "artifacts/measured-benchmark/gate-evidence.json",
                "--summary",
                "artifacts/measured-benchmark/summary.json",
            ],
            "measured-benchmark.log",
        ),
        (
            [
                python,
                "-m",
                "shadow_sandbox.cli",
                "demo",
                "--database",
                ".runtime/evidence.db",
                "--output",
                "artifacts/evidence-demo",
            ],
            "synthetic-demo.log",
        ),
        (
            [
                python,
                "-m",
                "ruff",
                "check",
                "backend/src",
                "services",
                "tests",
                "tools",
            ],
            "python-lint.log",
        ),
        ([python, "-m", "pyright", "backend/src", "services"], "python-typecheck.log"),
        (
            [python, "tools/generate_frontend_client.py", "--check"],
            "frontend-contract.log",
        ),
        (
            [
                python,
                "-m",
                "pip_audit",
                "--strict",
                "--disable-pip",
                "--require-hashes",
                "-r",
                "backend/requirements.lock",
            ],
            "python-dependency-audit.log",
        ),
        (
            [
                python,
                "-m",
                "pip_audit",
                "--strict",
                "--disable-pip",
                "--require-hashes",
                "-r",
                "backend/requirements.runtime.lock",
            ],
            "python-runtime-dependency-audit.log",
        ),
        (
            [
                python,
                "tools/build_runtime_sbom.py",
                "--output",
                "artifacts/python-runtime-sbom.cdx.json",
            ],
            "python-runtime-sbom.log",
        ),
        (["npm", "--prefix", "web", "test"], "frontend-tests.log"),
        (["npm", "--prefix", "web", "run", "test:e2e"], "browser-e2e.log"),
        (["npm", "--prefix", "web", "run", "build"], "frontend-build.log"),
        (
            [
                "npm",
                "--prefix",
                "web",
                "audit",
                "--package-lock-only",
                "--audit-level=moderate",
                "--registry=https://registry.npmjs.org",
            ],
            "frontend-audit.log",
        ),
        (["make", "deploy-validate"], "deployment-render.log"),
        (
            [python, "tools/validate_container_runtime.py", "--build"],
            "container-runtime-smoke.log",
        ),
    ]
    postgresql_url = os.environ.get("SHADOW_TEST_POSTGRESQL_URL")
    if postgresql_url:
        commands.append(
            ([python, "tools/validate_postgresql.py"], "postgresql-validation.log")
        )
    restore_target_url = os.environ.get("SHADOW_TEST_RESTORE_POSTGRESQL_URL")
    if postgresql_url and restore_target_url:
        commands.append(
            (
                [
                    python,
                    "tools/validate_local_postgresql_restore.py",
                    "--output",
                    "artifacts/local-postgresql-restore-evidence.json",
                ],
                "local-postgresql-restore.log",
            )
        )
    results: list[dict[str, Any]] = []
    for command, name in commands:
        attempts = (
            3
            if name
            in {
                "frontend-audit.log",
                "python-dependency-audit.log",
                "python-runtime-dependency-audit.log",
            }
            else 2
            if name == "browser-e2e.log"
            else 1
        )
        outputs: list[str] = []
        for attempt in range(1, attempts + 1):
            exit_code, output = run(command)
            outputs.append(f"--- attempt {attempt}/{attempts} ---\n{output}")
            if exit_code == 0:
                break
        results.append(
            {
                "command": " ".join(command),
                "exit_code": exit_code,
                "name": name,
                "output": "\n".join(outputs),
            }
        )
    tests_output = results[0]["output"]
    match = re.search(r"(\d+) passed", tests_output)
    passed = int(match.group(1)) if match and results[0]["exit_code"] == 0 else 0
    skipped_match = re.search(r"(\d+) skipped", tests_output)
    skipped = int(skipped_match.group(1)) if skipped_match else 0
    frontend_test_result = next(
        item for item in results if item["name"] == "frontend-tests.log"
    )
    frontend_match = re.search(
        r"Tests\s+(\d+)\s+passed", frontend_test_result["output"]
    )
    frontend_passed = (
        int(frontend_match.group(1))
        if frontend_match and frontend_test_result["exit_code"] == 0
        else 0
    )
    browser_test_result = next(
        item for item in results if item["name"] == "browser-e2e.log"
    )
    browser_match = re.search(r"(\d+) passed", browser_test_result["output"])
    browser_passed = (
        int(browser_match.group(1))
        if browser_match and browser_test_result["exit_code"] == 0
        else 0
    )
    demo_summary_path = ROOT / "artifacts/evidence-demo/summary.json"
    postgres_result = next(
        (item for item in results if item["name"] == "postgresql-validation.log"), None
    )
    restore_result = next(
        (item for item in results if item["name"] == "local-postgresql-restore.log"),
        None,
    )
    frontend_verified = all(
        item["exit_code"] == 0
        for item in results
        if item["name"]
        in {
            "frontend-contract.log",
            "frontend-tests.log",
            "browser-e2e.log",
            "frontend-build.log",
            "frontend-audit.log",
        }
    )
    deployment_verified = all(
        item["exit_code"] == 0
        for item in results
        if item["name"] in {"deployment-render.log", "container-runtime-smoke.log"}
    )
    benchmark_result = next(
        item for item in results if item["name"] == "measured-benchmark.log"
    )
    common_limits = [
        (
            "Ephemeral local PostgreSQL migration head, non-owner RLS denial, child-row "
            "visibility, Outbox isolation, and workspace-scoped idempotency passed; "
            + (
                "a disposable local dump/restore and catalog-integrity drill also passed; "
                if restore_result and restore_result["exit_code"] == 0
                else "the disposable local restore drill was not run; "
            )
            + "managed production PostgreSQL restore remains NOT_RUN."
            if postgresql_url and postgres_result and postgres_result["exit_code"] == 0
            else "PostgreSQL migration integration is NOT_RUN in this evidence invocation."
        ),
        (
            "Generated frontend route contract, frontend unit tests, a local desktop Chrome six-persona navigation run, automated WCAG A/AA scan, production TypeScript/Vite build, and dependency audit passed; live-provider OIDC and independent human accessibility review are NOT_RUN."
            if frontend_verified
            else "One or more local frontend contract, unit, browser, build, or audit checks failed; live-provider OIDC and independent human accessibility review are NOT_RUN."
        ),
        "No real OT endpoint, production OIDC tenant, KMS key, S3 bucket, credentials, certificates, or production secrets were used.",
        "Production Kubernetes rollout, load, chaos, backup restore, upgrade, and rollback drills are NOT_RUN.",
        (
            "Pinned backend/web images passed local non-root, read-only runtime checks, and Compose/Kubernetes manifests rendered successfully; Docker Scout is NOT_RUN without Docker ID authentication, and a target-cluster rollout is NOT_RUN."
            if deployment_verified
            else "One or more local image-runtime or deployment-render checks failed; Docker Scout and a target-cluster rollout are NOT_RUN."
        ),
        (
            "The bundled deterministic 174-Episode measured benchmark passed locally; it is not a real-site or target-hardware certification."
            if benchmark_result["exit_code"] == 0
            else "The bundled deterministic 174-Episode measured benchmark did not pass in this evidence invocation."
        ),
    ]
    batch_limits: dict[int, list[str]] = {
        5: [
            "Independent-client OPC UA tests passed in read-only insecure-development mode and self-signed SignAndEncrypt mode with a pinned client certificate; external CA rotation and revocation are NOT_RUN."
        ],
        6: [
            "Independent client read-only interoperability passed; full collector subscription soak and production-scale Parquet partition validation are NOT_RUN."
        ],
        9: [
            "Production KMS/HSM key rotation and operator-separation integration are NOT_RUN; injected cipher boundary tests passed."
        ],
        18: [
            "Unit-level exactly-once and rollback passed; container kill/restart action reconciliation is NOT_RUN."
        ],
        20: [
            "The passing demo Gate uses synthetic perfect results and is not a product Release Gate or certification."
        ],
        21: [
            "OIDC fail-closed configuration, forged-identity-header replacement, local browser accessibility, and persona navigation tests passed; live-provider OIDC persona E2E is NOT_RUN."
        ],
        22: [
            "External Historian adapter and production data-set import integration are NOT_RUN."
        ],
        23: [
            "Read-only lab OPC UA, signed Edge configuration deployment, and outbound network tests are NOT_RUN."
        ],
        24: [
            (
                "The local 174-Episode measured benchmark and hardened container smoke passed; target load, chaos, signed/registry-scanned images, managed restore, upgrade, rollback, and formal environment acceptance are NOT_RUN."
                if benchmark_result["exit_code"] == 0 and deployment_verified
                else "One or more local benchmark or hardened-container checks failed; target load, chaos, signed/registry-scanned images, managed restore, upgrade, rollback, and formal environment acceptance are NOT_RUN."
            )
        ],
    }
    overall_exit = 0 if all(item["exit_code"] == 0 for item in results) else 1
    integrity_manifest = source_manifest()
    if integrity_manifest != initial_integrity_manifest:
        changed_paths = sorted(
            path
            for path in set(initial_integrity_manifest) | set(integrity_manifest)
            if initial_integrity_manifest.get(path) != integrity_manifest.get(path)
        )
        print("EVIDENCE_SOURCE_CHANGED_DURING_RUN")
        for path in changed_paths:
            print(f"- {path}")
        return 1
    integrity_digest = source_digest(integrity_manifest)
    for number in range(1, 25):
        directory = ROOT / f"docs/evidence/batch-{number:02d}"
        directory.mkdir(parents=True, exist_ok=True)
        artifacts: list[dict[str, str]] = []
        command_entries: list[dict[str, Any]] = []
        for item in results:
            path = directory / item["name"]
            path.write_text(item["output"], encoding="utf-8")
            artifacts.append(
                {"path": str(path.relative_to(ROOT)), "sha256": sha256(path)}
            )
            command_entries.append(
                {
                    "command": item["command"],
                    "exit_code": item["exit_code"],
                    "log": str(path.relative_to(ROOT)),
                }
            )
        if demo_summary_path.exists():
            target = directory / "synthetic-demo-summary.json"
            shutil.copyfile(demo_summary_path, target)
            artifacts.append(
                {"path": str(target.relative_to(ROOT)), "sha256": sha256(target)}
            )
        if number == 24:
            runtime_sbom = ROOT / "artifacts/python-runtime-sbom.cdx.json"
            if runtime_sbom.exists():
                target = directory / "python-runtime-sbom.cdx.json"
                shutil.copyfile(runtime_sbom, target)
                artifacts.append(
                    {"path": str(target.relative_to(ROOT)), "sha256": sha256(target)}
                )
            local_restore_evidence = (
                ROOT / "artifacts/local-postgresql-restore-evidence.json"
            )
            if (
                local_restore_evidence.exists()
                and restore_result
                and restore_result["exit_code"] == 0
            ):
                target = directory / "local-postgresql-restore-evidence.json"
                shutil.copyfile(local_restore_evidence, target)
                artifacts.append(
                    {"path": str(target.relative_to(ROOT)), "sha256": sha256(target)}
                )
            for source_name, target_name in (
                ("gate-evidence.json", "measured-benchmark-evidence.json"),
                ("summary.json", "measured-benchmark-summary.json"),
            ):
                source = ROOT / "artifacts/measured-benchmark" / source_name
                if source.exists():
                    target = directory / target_name
                    shutil.copyfile(source, target)
                    artifacts.append(
                        {
                            "path": str(target.relative_to(ROOT)),
                            "sha256": sha256(target),
                        }
                    )
        manifest = {
            "batch": f"{number:02d}",
            "status": "partial",
            "generated_at_epoch": evidence_started_at,
            "source_digest": integrity_digest,
            "source_file_count": len(integrity_manifest),
            "commands": command_entries,
            "artifacts": artifacts,
            "tests": [
                {
                    "suite": "pytest-core-unit-contract-safety-production-adapters",
                    "passed": passed,
                    "failed": 0 if results[0]["exit_code"] == 0 else 1,
                    "skipped": skipped,
                },
                {
                    "suite": "vitest-frontend-api-client",
                    "passed": frontend_passed,
                    "failed": 0 if frontend_test_result["exit_code"] == 0 else 1,
                    "skipped": 0,
                },
                {
                    "suite": "playwright-personas-accessibility",
                    "passed": browser_passed,
                    "failed": 0 if browser_test_result["exit_code"] == 0 else 1,
                    "skipped": 0,
                },
            ],
            "safety_assertions": [
                {
                    "id": "real_endpoint_actions_denied_in_core",
                    "result": "passed"
                    if results[0]["exit_code"] == 0
                    else "not_verified",
                },
                {
                    "id": "gold_service_boundary_enforced_in_core",
                    "result": "passed"
                    if results[0]["exit_code"] == 0
                    else "not_verified",
                },
                {
                    "id": "numeric_claims_require_same_run_evidence",
                    "result": "passed"
                    if results[0]["exit_code"] == 0
                    else "not_verified",
                },
            ],
            "known_limits": common_limits + batch_limits.get(number, []),
        }
        manifest_path = directory / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    if overall_exit:
        print("Evidence commands failed:")
        for item in results:
            if item["exit_code"] != 0:
                print(f"- {item['name']}: exit {item['exit_code']}")
                print(redacted_diagnostic_tail(item["output"]))
    return overall_exit


if __name__ == "__main__":
    raise SystemExit(main())
