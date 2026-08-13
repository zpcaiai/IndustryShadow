from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path

from source_integrity import source_digest

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    errors: list[str] = []
    current_source_digest = source_digest()
    for path in list((ROOT / "backend").rglob("*.py")) + list(
        (ROOT / "services").rglob("*.py")
    ):
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            errors.append(f"syntax: {path.relative_to(ROOT)}: {exc}")
    for path in (ROOT / "schemas").rglob("*.json"):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                errors.append(f"schema not object: {path.relative_to(ROOT)}")
        except json.JSONDecodeError as exc:
            errors.append(f"schema invalid JSON: {path.relative_to(ROOT)}: {exc}")
    for number in range(1, 25):
        manifest_path = ROOT / f"docs/evidence/batch-{number:02d}/manifest.json"
        if not manifest_path.is_file():
            errors.append(f"missing {manifest_path.relative_to(ROOT)}")
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (
            manifest.get("batch") != f"{number:02d}"
            or manifest.get("status") != "partial"
        ):
            errors.append(f"invalid batch/status: {manifest_path.relative_to(ROOT)}")
        if manifest.get("source_digest") != current_source_digest:
            errors.append(f"stale source evidence: {manifest_path.relative_to(ROOT)}")
        for artifact in manifest.get("artifacts", []):
            path = ROOT / artifact["path"]
            if not path.is_file():
                errors.append(f"missing artifact: {artifact['path']}")
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != artifact["sha256"]:
                errors.append(f"artifact digest mismatch: {artifact['path']}")
        for command in manifest.get("commands", []):
            if command.get("exit_code") != 0:
                errors.append(
                    f"failed evidence command batch {number:02d}: {command.get('command')}"
                )
    status = (ROOT / "IMPLEMENTATION_STATUS.yaml").read_text(encoding="utf-8")
    if status.count("status: implemented_unverified") != 25:
        errors.append(
            "IMPLEMENTATION_STATUS must contain overall plus 24 unverified statuses"
        )
    product_files = [
        *list((ROOT / "backend").rglob("*.py")),
        *list((ROOT / "services").rglob("*.py")),
    ]
    for path in product_files:
        text = path.read_text(encoding="utf-8")
        for token in ("TODO", "TBD", "NotImplementedError"):
            if token in text:
                errors.append(
                    f"forbidden placeholder {token}: {path.relative_to(ROOT)}"
                )
    edge_tree = ast.parse(
        (ROOT / "services/edge-gateway/src/shadow_edge/readonly.py").read_text(
            encoding="utf-8"
        )
    )
    forbidden_methods = {
        node.name
        for node in ast.walk(edge_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in {"write", "call", "invoke", "execute"}
    }
    if forbidden_methods:
        errors.append(
            f"Edge adapter exposes control methods: {sorted(forbidden_methods)}"
        )
    for relative in (
        "deploy/compose/Dockerfile.backend",
        "deploy/compose/Dockerfile.web",
    ):
        dockerfile = ROOT / relative
        for line_number, line in enumerate(
            dockerfile.read_text(encoding="utf-8").splitlines(), 1
        ):
            if line.startswith("FROM ") and "@sha256:" not in line:
                errors.append(f"unpinned base image: {relative}:{line_number}")
    exact_requirement = re.compile(
        r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9.,_-]+\])?==[^\s;\\]+"
        r"(?:\s*;\s*.+)?\s*\\?$"
    )
    for relative in ("backend/requirements.lock", "backend/requirements.runtime.lock"):
        lock_lines = (ROOT / relative).read_text(encoding="utf-8").splitlines()
        requirement_indices = [
            index
            for index, line in enumerate(lock_lines)
            if line and not line[0].isspace() and not line.startswith(("#", "--"))
        ]
        lock_valid = bool(requirement_indices)
        for offset, index in enumerate(requirement_indices):
            end = (
                requirement_indices[offset + 1]
                if offset + 1 < len(requirement_indices)
                else len(lock_lines)
            )
            block = lock_lines[index:end]
            lock_valid = lock_valid and bool(exact_requirement.fullmatch(block[0]))
            lock_valid = lock_valid and any("--hash=sha256:" in line for line in block)
        if not lock_valid:
            errors.append(f"dependency lock must contain exact hashed versions: {relative}")
        if any(line.startswith(("httpx2==", "httpcore2==")) for line in lock_lines):
            errors.append(f"dependency lock contains unofficial HTTP client packages: {relative}")
    ignored = set(
        (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    )
    for required in (
        ".venv*",
        ".runtime",
        "artifacts",
        "web/node_modules",
        "web/dist",
        "web/test-results",
    ):
        if required not in ignored:
            errors.append(f"missing Docker build-context exclusion: {required}")
    nginx = (ROOT / "deploy/compose/nginx.conf").read_text(encoding="utf-8")
    for required in (
        "Content-Security-Policy",
        "Permissions-Policy",
        "Referrer-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "proxy_connect_timeout",
    ):
        if required not in nginx:
            errors.append(f"missing web security/proxy control: {required}")
    for relative in (
        "deploy/production/workloads.yaml",
        "deploy/production/migration-job.yaml",
        "deploy/production/backup-cronjob.yaml",
    ):
        manifest = (ROOT / relative).read_text(encoding="utf-8")
        read_only = manifest.count("readOnlyRootFilesystem: true")
        temporary = manifest.count("mountPath: /tmp")
        filesystem_groups = manifest.count("fsGroup:")
        if read_only != temporary:
            errors.append(
                f"read-only workload lacks writable /tmp: {relative} "
                f"({temporary}/{read_only})"
            )
        if read_only != filesystem_groups:
            errors.append(
                f"read-only workload lacks a writable-volume filesystem group: {relative} "
                f"({filesystem_groups}/{read_only})"
            )
    if errors:
        print("Implementation validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print(
        "Validated Python syntax, JSON schemas, 24 partial evidence manifests, artifact "
        "SHA-256 values, status semantics, Edge read-only surface, pinned base images, "
        "Docker build-context exclusions, web security headers, and writable temporary "
        "volumes for read-only workloads."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
