from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError, canonical_json

ROOT = Path(__file__).resolve().parents[1]
DIGEST_KEYS = frozenset({"path", "sha256"})


def _regular_file(path: Path, *, code: str) -> Path:
    if path.is_symlink():
        raise DomainError(code, "bundle entries must not be symlinks")
    resolved = path.resolve(strict=True)
    mode = resolved.stat().st_mode
    if (
        not stat.S_ISREG(mode)
        or resolved.stat().st_nlink != 1
        or not 1 <= resolved.stat().st_size <= 64 * 1024 * 1024
    ):
        raise DomainError(code, "bundle entries must be single-link regular files")
    return resolved


def _inside(parent: Path, value: str, *, code: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise DomainError(code, "bundle path is invalid")
    cursor = parent
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise DomainError(code, "bundle paths must not contain symlinks")
    candidate = parent / relative
    resolved = _regular_file(candidate, code=code)
    if parent.resolve() not in resolved.parents:
        raise DomainError(code, "bundle path escaped its directory")
    return resolved


def _declared_artifacts(payload: Mapping[str, Any], kind: str) -> list[Mapping[str, Any]]:
    if kind in {"assurance", "benchmark"}:
        raw = payload.get("artifacts")
        if not isinstance(raw, list) or not raw:
            raise DomainError("SIGNED_BUNDLE_INVALID", "signed report artifacts are required")
        records = []
        for item in raw:
            if not isinstance(item, Mapping):
                raise DomainError("SIGNED_BUNDLE_INVALID", "artifact record is invalid")
            record = {key: item[key] for key in ("path", "sha256") if key in item}
            if set(record) != DIGEST_KEYS:
                raise DomainError("SIGNED_BUNDLE_INVALID", "artifact fields are invalid")
            records.append(record)
        return records
    if kind == "deployment":
        records = []
        for name in (
            "bootstrap_manifest",
            "migration_manifest",
            "runtime_manifest",
            "rollback_manifest",
        ):
            item = payload.get(name)
            if not isinstance(item, Mapping) or set(item) != DIGEST_KEYS:
                raise DomainError("SIGNED_BUNDLE_INVALID", "deployment artifact is invalid")
            records.append(item)
        return records
    raise DomainError("SIGNED_BUNDLE_INVALID", "unknown bundle kind")


def stage_bundle(
    source: str | Path,
    destination: str | Path,
    *,
    manifest_name: str,
    kind: str,
) -> tuple[Path, ...]:
    source_path = Path(source)
    if source_path.is_symlink():
        raise DomainError("SIGNED_BUNDLE_INVALID", "bundle directory is a symlink")
    source_root = source_path.resolve(strict=True)
    if not source_root.is_dir():
        raise DomainError("SIGNED_BUNDLE_INVALID", "bundle directory is missing")
    manifest = _inside(source_root, manifest_name, code="SIGNED_BUNDLE_INVALID")
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise DomainError("SIGNED_BUNDLE_INVALID", "bundle manifest is invalid JSON") from error
    if not isinstance(payload, Mapping):
        raise DomainError("SIGNED_BUNDLE_INVALID", "bundle manifest must be an object")
    destination_root = Path(destination).resolve()
    if ROOT.resolve() not in destination_root.parents:
        raise DomainError("SIGNED_BUNDLE_INVALID", "bundle destination is outside repository")
    if (
        source_root == destination_root
        or source_root in destination_root.parents
        or destination_root in source_root.parents
        or destination_root.exists()
    ):
        raise DomainError(
            "SIGNED_BUNDLE_INVALID",
            "source and destination must be disjoint and destination must be fresh",
        )
    records = _declared_artifacts(payload, kind)
    sources: list[tuple[Path, Path]] = []
    seen_targets: set[Path] = set()
    for record in records:
        declared = Path(str(record["path"]))
        try:
            target_relative = declared.relative_to(destination_root.relative_to(ROOT))
        except ValueError as error:
            raise DomainError(
                "SIGNED_BUNDLE_INVALID", "declared artifact is outside its evidence directory"
            ) from error
        source_file = _inside(source_root, target_relative.as_posix(), code="SIGNED_BUNDLE_INVALID")
        expected = str(record["sha256"])
        if hashlib.sha256(source_file.read_bytes()).hexdigest() != expected:
            raise DomainError("SIGNED_BUNDLE_INVALID", "declared artifact digest mismatch")
        target = destination_root / target_relative
        if target in seen_targets:
            raise DomainError("SIGNED_BUNDLE_INVALID", "duplicate bundle target")
        seen_targets.add(target)
        sources.append((source_file, target))
    manifest_target = destination_root / manifest_name
    if manifest_target in seen_targets:
        raise DomainError("SIGNED_BUNDLE_INVALID", "manifest cannot also be an artifact")
    sources.append((manifest, manifest_target))
    copied: list[Path] = []
    for source_file, target in sources:
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".bundle-", dir=target.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle, source_file.open("rb") as input_file:
                shutil.copyfileobj(input_file, handle, length=1024 * 1024)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o444)
            os.replace(temporary, target)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        copied.append(target)
    allowed = {path.resolve() for path in copied}
    actual = {
        path.resolve()
        for path in destination_root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual != allowed:
        raise DomainError("SIGNED_BUNDLE_INVALID", "destination contains undeclared files")
    return tuple(copied)


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage only digest-declared signed evidence")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--kind", choices=("assurance", "benchmark", "deployment"), required=True)
    args = parser.parse_args()
    copied = stage_bundle(
        args.source,
        args.destination,
        manifest_name=args.manifest,
        kind=args.kind,
    )
    print(canonical_json({"staged": len(copied)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
