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
GENERATED_SOURCE_DIRECTORY_NAMES = frozenset(
    {
        "__pycache__",
        ".eggs",
        ".mypy_cache",
        ".pyright",
        ".pytest_cache",
        ".ruff_cache",
        ".runtime",
        ".venv",
        "venv",
    }
)
GENERATED_SOURCE_DIRECTORY_SUFFIXES = (".dist-info", ".egg-info")
GENERATED_SOURCE_FILE_SUFFIXES = (".pyc", ".pyd", ".pyo")


def _is_generated_source_path(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if any(
        part in GENERATED_SOURCE_DIRECTORY_NAMES
        or part.endswith(GENERATED_SOURCE_DIRECTORY_SUFFIXES)
        for part in relative.parts
    ):
        return True
    name = relative.name
    return (
        name == ".coverage"
        or name.startswith(".coverage.")
        or name.endswith(GENERATED_SOURCE_FILE_SUFFIXES)
    )


def source_manifest() -> dict[str, str]:
    result: dict[str, str] = {}
    for relative in SOURCE_PATHS:
        candidate = ROOT / relative
        paths = [candidate] if candidate.is_file() else candidate.rglob("*")
        for path in paths:
            if not _is_generated_source_path(path) and path.is_file():
                result[path.relative_to(ROOT).as_posix()] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
    return dict(sorted(result.items()))


def source_digest(manifest: dict[str, str] | None = None) -> str:
    payload = manifest if manifest is not None else source_manifest()
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
