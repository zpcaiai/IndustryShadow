from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from .source_integrity import source_digest, source_manifest
except ImportError:  # pragma: no cover - direct script execution
    from source_integrity import source_digest, source_manifest

ROOT = Path(__file__).resolve().parents[1]
BINDING_FILENAME = "evidence-refresh-binding.json"
BINDING_SCHEMA = "industrial-shadow/evidence-refresh-binding/v1"
FORBIDDEN_FILENAME = "production-closure-input.json"
MANIFEST_KEYS = {
    "batch",
    "status",
    "generated_at_epoch",
    "source_digest",
    "source_file_count",
    "commands",
    "artifacts",
    "tests",
    "safety_assertions",
    "known_limits",
}
MAXIMUM_MANIFEST_BYTES = 2 * 1024 * 1024
MAXIMUM_ARTIFACT_BYTES = 512 * 1024 * 1024
MAXIMUM_TOTAL_BYTES = 4 * 1024 * 1024 * 1024

DIGEST = re.compile(r"[0-9a-f]{64}")
HEAD_SHA = re.compile(r"[0-9a-f]{40}")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}")
RUN_ATTEMPT = re.compile(r"[1-9][0-9]{0,5}")
REPOSITORY = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})"
)
WORKFLOW_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.(?:yml|yaml)")
GIT_REF = re.compile(r"refs/(?:heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]{0,254}")


class EvidenceStageError(ValueError):
    """Raised when evidence is unsafe, stale, or ambiguously bound."""


def _required_environment(environ: Mapping[str, str]) -> dict[str, str]:
    names = (
        "GITHUB_REPOSITORY",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_SHA",
    )
    values = {name: environ.get(name, "") for name in names}
    if any(not value or value != value.strip() for value in values.values()):
        raise EvidenceStageError(
            "required GitHub execution coordinates are missing or padded"
        )

    repository = values["GITHUB_REPOSITORY"]
    workflow_ref = values["GITHUB_WORKFLOW_REF"]
    workflow_prefix = f"{repository}/.github/workflows/"
    if not REPOSITORY.fullmatch(repository):
        raise EvidenceStageError("GITHUB_REPOSITORY is not canonical owner/repository")
    if not workflow_ref.startswith(workflow_prefix) or "@" not in workflow_ref:
        raise EvidenceStageError(
            "GITHUB_WORKFLOW_REF is not bound to GITHUB_REPOSITORY"
        )
    workflow_file, git_ref = workflow_ref[len(workflow_prefix) :].rsplit("@", 1)
    if not WORKFLOW_FILE.fullmatch(workflow_file) or not GIT_REF.fullmatch(git_ref):
        raise EvidenceStageError("GITHUB_WORKFLOW_REF is not a canonical workflow ref")
    if (
        ".." in git_ref
        or "//" in git_ref
        or "@{" in git_ref
        or git_ref.endswith(("/", "."))
    ):
        raise EvidenceStageError("GITHUB_WORKFLOW_REF contains an unsafe Git ref")
    if not RUN_ID.fullmatch(values["GITHUB_RUN_ID"]):
        raise EvidenceStageError("GITHUB_RUN_ID must be a positive canonical integer")
    if not RUN_ATTEMPT.fullmatch(values["GITHUB_RUN_ATTEMPT"]):
        raise EvidenceStageError(
            "GITHUB_RUN_ATTEMPT must be a positive canonical integer"
        )
    if not HEAD_SHA.fullmatch(values["GITHUB_SHA"]):
        raise EvidenceStageError(
            "GITHUB_SHA must be a lowercase 40-character commit SHA"
        )
    return values


def _safe_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise EvidenceStageError("no-follow file reads are unavailable on this runner")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceStageError(
            f"evidence input is missing or unsafe: {path}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum_bytes
        ):
            raise EvidenceStageError(
                f"evidence input is not a bounded single-link file: {path}"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if len(payload) != before.st_size or any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            raise EvidenceStageError(
                f"evidence input changed while it was read: {path}"
            )
        return payload
    finally:
        os.close(descriptor)


def _safe_json(path: Path, *, label: str = "manifest") -> tuple[dict[str, Any], bytes]:
    payload = _safe_bytes(path, maximum_bytes=MAXIMUM_MANIFEST_BYTES)

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceStageError(
                    f"{label} contains a duplicate JSON key: {key}"
                )
            result[key] = value
        return result

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceStageError(f"{label} is not valid UTF-8 JSON: {path}") from error
    if not isinstance(value, dict):
        raise EvidenceStageError(f"{label} must be a JSON object: {path}")
    return value, payload


def _canonical_artifact_path(value: Any, *, batch: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise EvidenceStageError(
            f"batch {batch} artifact path is not canonical POSIX text"
        )
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise EvidenceStageError(
            f"batch {batch} artifact path is absolute or traverses parents"
        )
    expected_prefix = ("docs", "evidence", f"batch-{batch}")
    if path.parts[:3] != expected_prefix or len(path.parts) < 4:
        raise EvidenceStageError(
            f"batch {batch} artifact is outside its evidence directory"
        )
    if path.name == FORBIDDEN_FILENAME:
        raise EvidenceStageError(
            "production closure input must never enter refresh staging"
        )
    return path


def _reject_symlink_components(root: Path, relative: PurePosixPath) -> Path:
    candidate = root
    if root.is_symlink():
        raise EvidenceStageError("repository root must not be a symlink")
    for part in relative.parts:
        candidate /= part
        if candidate.is_symlink():
            raise EvidenceStageError(
                f"evidence path contains a symlink: {relative.as_posix()}"
            )
    return candidate


def _read_evidence(
    root: Path, *, expected_digest: str, expected_file_count: int
) -> list[tuple[str, bytes, str]]:
    files: list[tuple[str, bytes, str]] = []
    seen: set[str] = set()
    total_bytes = 0
    for number in range(1, 25):
        batch = f"{number:02d}"
        batch_relative = PurePosixPath(f"docs/evidence/batch-{batch}")
        manifest_relative = batch_relative / "manifest.json"
        manifest_path = _reject_symlink_components(root, manifest_relative)
        manifest, manifest_payload = _safe_json(manifest_path)
        if set(manifest) != MANIFEST_KEYS:
            raise EvidenceStageError(f"batch {batch} manifest fields are invalid")
        if manifest.get("batch") != batch or manifest.get("status") != "partial":
            raise EvidenceStageError(f"batch {batch} manifest batch/status is invalid")
        if manifest.get("source_digest") != expected_digest:
            raise EvidenceStageError(f"batch {batch} manifest source_digest is stale")
        if (
            type(manifest.get("source_file_count")) is not int
            or manifest["source_file_count"] != expected_file_count
        ):
            raise EvidenceStageError(
                f"batch {batch} manifest source_file_count is stale"
            )
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, list):
            raise EvidenceStageError(f"batch {batch} manifest artifacts must be a list")
        commands = manifest.get("commands")
        if (
            not isinstance(commands, list)
            or not commands
            or any(
                not isinstance(command, dict)
                or type(command.get("exit_code")) is not int
                or command["exit_code"] != 0
                for command in commands
            )
        ):
            raise EvidenceStageError(
                f"batch {batch} manifest commands are not all successful"
            )

        manifest_name = manifest_relative.as_posix()
        manifest_sha = hashlib.sha256(manifest_payload).hexdigest()
        files.append((manifest_name, manifest_payload, manifest_sha))
        seen.add(manifest_name)
        total_bytes += len(manifest_payload)

        batch_resolved = _reject_symlink_components(root, batch_relative).resolve(
            strict=True
        )
        for artifact in artifacts:
            if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
                raise EvidenceStageError(
                    f"batch {batch} artifact declaration is invalid"
                )
            relative = _canonical_artifact_path(artifact["path"], batch=batch)
            relative_name = relative.as_posix()
            claimed_digest = artifact["sha256"]
            if not isinstance(claimed_digest, str) or not DIGEST.fullmatch(
                claimed_digest
            ):
                raise EvidenceStageError(f"batch {batch} artifact SHA-256 is invalid")
            if relative_name in seen:
                raise EvidenceStageError(
                    f"duplicate evidence file declaration: {relative_name}"
                )
            path = _reject_symlink_components(root, relative)
            try:
                resolved = path.resolve(strict=True)
            except OSError as error:
                raise EvidenceStageError(
                    f"evidence artifact is missing: {relative_name}"
                ) from error
            if (
                not resolved.is_relative_to(batch_resolved)
                or resolved == batch_resolved
            ):
                raise EvidenceStageError(
                    f"batch {batch} artifact resolves outside its directory"
                )
            payload = _safe_bytes(path, maximum_bytes=MAXIMUM_ARTIFACT_BYTES)
            actual_digest = hashlib.sha256(payload).hexdigest()
            if actual_digest != claimed_digest:
                raise EvidenceStageError(f"artifact digest mismatch: {relative_name}")
            files.append((relative_name, payload, actual_digest))
            seen.add(relative_name)
            total_bytes += len(payload)
            if total_bytes > MAXIMUM_TOTAL_BYTES:
                raise EvidenceStageError(
                    "evidence refresh input exceeds the aggregate size limit"
                )
    return sorted(files, key=lambda item: item[0])


def _reject_symlink_ancestors(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise EvidenceStageError(f"output path contains a symlink: {current}")


def _write_file(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o400)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise EvidenceStageError(f"failed to stage evidence file: {path}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _directory_inventory(root: Path) -> tuple[set[str], set[str]]:
    if root.is_symlink() or not root.is_dir():
        raise EvidenceStageError(
            "staging root must be an existing non-symlink directory"
        )
    files: set[str] = set()
    directories = {""}
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            raise EvidenceStageError(
                f"could not inventory staging directory: {directory}"
            ) from error
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise EvidenceStageError(
                    f"could not inspect staged path: {relative}"
                ) from error
            if entry.is_symlink():
                raise EvidenceStageError(f"staged path is a symlink: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                directories.add(relative)
                pending.append(path)
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                files.add(relative)
            else:
                raise EvidenceStageError(
                    f"staged path is not a regular single-link file or directory: {relative}"
                )
    return files, directories


def _expected_directories(files: set[str]) -> set[str]:
    directories = {""}
    for value in files:
        parent = PurePosixPath(value).parent
        while parent.as_posix() != ".":
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def verify_evidence_refresh(
    staging_dir: Path,
    *,
    repository: str,
    workflow_ref: str,
    run_id: str,
    run_attempt: str,
    head_sha: str,
) -> Path:
    coordinates = _required_environment(
        {
            "GITHUB_REPOSITORY": repository,
            "GITHUB_WORKFLOW_REF": workflow_ref,
            "GITHUB_RUN_ID": run_id,
            "GITHUB_RUN_ATTEMPT": run_attempt,
            "GITHUB_SHA": head_sha,
        }
    )
    staging = staging_dir.absolute()
    _reject_symlink_ancestors(staging)
    before_inventory = _directory_inventory(staging)
    binding_path = staging / BINDING_FILENAME
    binding, _binding_payload = _safe_json(
        binding_path, label="evidence refresh binding"
    )
    expected_binding_keys = {
        "schema",
        "repository",
        "workflow_ref",
        "run_id",
        "run_attempt",
        "head_sha",
        "source_digest",
        "files",
    }
    if set(binding) != expected_binding_keys or binding.get("schema") != BINDING_SCHEMA:
        raise EvidenceStageError(
            "evidence refresh binding schema or fields are invalid"
        )
    expected_coordinates = {
        "repository": coordinates["GITHUB_REPOSITORY"],
        "workflow_ref": coordinates["GITHUB_WORKFLOW_REF"],
        "run_id": coordinates["GITHUB_RUN_ID"],
        "run_attempt": coordinates["GITHUB_RUN_ATTEMPT"],
        "head_sha": coordinates["GITHUB_SHA"],
    }
    if any(binding.get(name) != value for name, value in expected_coordinates.items()):
        raise EvidenceStageError(
            "evidence refresh binding GitHub coordinates do not match"
        )

    initial_source_manifest = source_manifest()
    current_digest = source_digest(initial_source_manifest)
    if binding.get("source_digest") != current_digest:
        raise EvidenceStageError("evidence refresh binding source_digest is stale")
    files = _read_evidence(
        staging,
        expected_digest=current_digest,
        expected_file_count=len(initial_source_manifest),
    )
    expected_entries = [
        {"path": path, "sha256": digest} for path, _payload, digest in files
    ]
    binding_entries = binding.get("files")
    if not isinstance(binding_entries, list) or binding_entries != expected_entries:
        raise EvidenceStageError(
            "evidence refresh binding files must be unique, sorted, exact, and digest-bound"
        )
    expected_files = {entry["path"] for entry in expected_entries} | {BINDING_FILENAME}
    if before_inventory[0] != expected_files:
        raise EvidenceStageError("staging directory contains missing or extra files")
    if before_inventory[1] != _expected_directories(expected_files):
        raise EvidenceStageError(
            "staging directory contains missing or extra directories"
        )
    if _directory_inventory(staging) != before_inventory:
        raise EvidenceStageError("staging directory changed while it was verified")
    if source_manifest() != initial_source_manifest:
        raise EvidenceStageError("source tree changed while evidence was verified")
    return staging


def stage_evidence_refresh(
    output_dir: Path,
    *,
    root: Path = ROOT,
    environ: Mapping[str, str] | None = None,
) -> Path:
    coordinates = _required_environment(os.environ if environ is None else environ)
    _reject_symlink_ancestors(root)
    if ".." in output_dir.parts:
        raise EvidenceStageError("output directory must not traverse parents")
    output = output_dir.absolute()
    if output.name in {"", ".", ".."}:
        raise EvidenceStageError("an explicit output directory is required")
    if output.exists() or output.is_symlink():
        raise EvidenceStageError("output directory must not already exist")
    parent = output.parent
    _reject_symlink_ancestors(parent)
    if not parent.is_dir() or parent.is_symlink():
        raise EvidenceStageError(
            "output parent must be an existing non-symlink directory"
        )

    initial_source_manifest = source_manifest()
    current_digest = source_digest(initial_source_manifest)
    files = _read_evidence(
        root,
        expected_digest=current_digest,
        expected_file_count=len(initial_source_manifest),
    )
    binding = {
        "schema": BINDING_SCHEMA,
        "repository": coordinates["GITHUB_REPOSITORY"],
        "workflow_ref": coordinates["GITHUB_WORKFLOW_REF"],
        "run_id": coordinates["GITHUB_RUN_ID"],
        "run_attempt": coordinates["GITHUB_RUN_ATTEMPT"],
        "head_sha": coordinates["GITHUB_SHA"],
        "source_digest": current_digest,
        "files": [{"path": path, "sha256": digest} for path, _payload, digest in files],
    }
    binding_payload = (
        json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")

    lock = parent / f".{output.name}.evidence-refresh.lock"
    lock_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    try:
        lock_descriptor = os.open(lock, lock_flags, 0o600)
    except OSError as error:
        raise EvidenceStageError(
            "could not acquire the exclusive staging lock"
        ) from error
    try:
        temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.tmp-", dir=parent))
    except Exception:
        os.close(lock_descriptor)
        try:
            lock.unlink()
        except FileNotFoundError:
            pass
        raise
    published = False
    try:
        os.write(lock_descriptor, f"{os.getpid()}\n".encode("ascii"))
        os.fsync(lock_descriptor)
        for relative, payload, _digest in files:
            _write_file(temporary / PurePosixPath(relative), payload)
        _write_file(temporary / BINDING_FILENAME, binding_payload)
        for directory in sorted(
            (path for path in temporary.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            _fsync_directory(directory)
        _fsync_directory(temporary)
        if source_manifest() != initial_source_manifest:
            raise EvidenceStageError("source tree changed while evidence was staged")
        if output.exists() or output.is_symlink():
            raise EvidenceStageError(
                "output directory appeared while evidence was staged"
            )
        os.rename(temporary, output)
        published = True
        _fsync_directory(parent)
        return output
    finally:
        os.close(lock_descriptor)
        try:
            lock.unlink()
        except FileNotFoundError:
            pass
        if not published:
            shutil.rmtree(temporary, ignore_errors=True)
        try:
            _fsync_directory(parent)
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate and atomically stage partial evidence for a GitHub refresh artifact"
    )
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument(
        "--output-dir",
        type=Path,
        help="new output directory; it and its final path must not already exist",
    )
    operation.add_argument(
        "--verify-dir",
        type=Path,
        help="downloaded staging directory to verify without modifying it",
    )
    parser.add_argument("--expected-repository")
    parser.add_argument("--expected-workflow-ref")
    parser.add_argument("--expected-run-id")
    parser.add_argument("--expected-run-attempt")
    parser.add_argument("--expected-head-sha")
    args = parser.parse_args()
    try:
        if args.output_dir is not None:
            if any(
                value is not None
                for value in (
                    args.expected_repository,
                    args.expected_workflow_ref,
                    args.expected_run_id,
                    args.expected_run_attempt,
                    args.expected_head_sha,
                )
            ):
                raise EvidenceStageError(
                    "expected coordinates are only valid with --verify-dir"
                )
            output = stage_evidence_refresh(args.output_dir)
        else:
            expected = (
                args.expected_repository,
                args.expected_workflow_ref,
                args.expected_run_id,
                args.expected_run_attempt,
                args.expected_head_sha,
            )
            if any(value is None for value in expected):
                raise EvidenceStageError(
                    "--verify-dir requires all five --expected-* GitHub coordinates"
                )
            output = verify_evidence_refresh(
                args.verify_dir,
                repository=args.expected_repository,
                workflow_ref=args.expected_workflow_ref,
                run_id=args.expected_run_id,
                run_attempt=args.expected_run_attempt,
                head_sha=args.expected_head_sha,
            )
    except EvidenceStageError as error:
        print(f"EVIDENCE_REFRESH_STAGE_BLOCKED: {error}")
        return 1
    result = "VERIFIED" if args.verify_dir is not None else "STAGED"
    print(f"EVIDENCE_REFRESH_{result}: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
