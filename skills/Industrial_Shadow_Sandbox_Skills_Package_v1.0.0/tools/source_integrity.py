from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATHS = (
    ".dockerignore",
    ".github/workflows",
    "IMPLEMENTATION_STATUS.yaml",
    "Makefile",
    "README.md",
    "backend/pyproject.toml",
    "backend/requirements.lock",
    "backend/requirements.runtime.lock",
    "backend/src",
    "deploy",
    "migrations",
    "schemas",
    "services",
    "tests",
    "tools",
    "web/e2e",
    "web/index.html",
    "web/package-lock.json",
    "web/package.json",
    "web/playwright.config.ts",
    "web/src",
    "web/tests",
    "web/tsconfig.json",
    "web/vite.config.ts",
)


def source_manifest() -> dict[str, str]:
    result: dict[str, str] = {}
    for relative in SOURCE_PATHS:
        candidate = ROOT / relative
        paths = [candidate] if candidate.is_file() else candidate.rglob("*")
        for path in paths:
            if path.is_file() and "__pycache__" not in path.parts:
                result[path.relative_to(ROOT).as_posix()] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
    return dict(sorted(result.items()))


def source_digest(manifest: dict[str, str] | None = None) -> str:
    payload = manifest if manifest is not None else source_manifest()
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
