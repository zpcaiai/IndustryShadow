from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

import tools.source_integrity as source_integrity_module
import tools.stage_evidence_refresh as stage_module
from tools.source_integrity import source_digest
from tools.stage_evidence_refresh import (
    BINDING_FILENAME,
    BINDING_SCHEMA,
    EvidenceStageError,
    stage_evidence_refresh,
    verify_evidence_refresh,
)

SOURCE_FILES = {
    "backend/src/example.py": "a" * 64,
    "web/src/example.ts": "b" * 64,
}
GITHUB_ENV = {
    "GITHUB_REPOSITORY": "zpcaiai/IndustryShadow",
    "GITHUB_WORKFLOW_REF": (
        "zpcaiai/IndustryShadow/.github/workflows/ci.yml@refs/heads/main"
    ),
    "GITHUB_RUN_ID": "32345678901",
    "GITHUB_RUN_ATTEMPT": "2",
    "GITHUB_SHA": "c" * 40,
}


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=False) + "\n").encode("utf-8")


def _write_repository(root: Path) -> None:
    digest = source_digest(SOURCE_FILES)
    for number in range(1, 25):
        batch = f"{number:02d}"
        directory = root / f"docs/evidence/batch-{batch}"
        directory.mkdir(parents=True, exist_ok=True)
        artifact = directory / "smoke.log"
        if artifact.is_symlink():
            artifact.unlink()
        artifact.write_bytes(f"batch {batch} passed\n".encode())
        manifest = {
            "batch": batch,
            "status": "partial",
            "generated_at_epoch": 1.0,
            "source_digest": digest,
            "source_file_count": len(SOURCE_FILES),
            "commands": [
                {
                    "command": "smoke",
                    "exit_code": 0,
                    "log": f"docs/evidence/batch-{batch}/smoke.log",
                }
            ],
            "artifacts": [
                {
                    "path": f"docs/evidence/batch-{batch}/smoke.log",
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }
            ],
            "tests": [],
            "safety_assertions": [],
            "known_limits": ["production acceptance is NOT_RUN"],
        }
        (directory / "manifest.json").write_bytes(_json_bytes(manifest))


def _manifest(root: Path, batch: str = "01") -> tuple[Path, dict[str, Any]]:
    path = root / f"docs/evidence/batch-{batch}/manifest.json"
    return path, json.loads(path.read_text(encoding="utf-8"))


def _rewrite_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.write_bytes(_json_bytes(manifest))


@pytest.fixture
def evidence_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repository"
    _write_repository(root)
    monkeypatch.setattr(stage_module, "source_manifest", lambda: dict(SOURCE_FILES))
    return root


def _stage(root: Path, output: Path) -> Path:
    return stage_evidence_refresh(output, root=root, environ=GITHUB_ENV)


def _verify(staging: Path) -> Path:
    return verify_evidence_refresh(
        staging,
        repository=GITHUB_ENV["GITHUB_REPOSITORY"],
        workflow_ref=GITHUB_ENV["GITHUB_WORKFLOW_REF"],
        run_id=GITHUB_ENV["GITHUB_RUN_ID"],
        run_attempt=GITHUB_ENV["GITHUB_RUN_ATTEMPT"],
        head_sha=GITHUB_ENV["GITHUB_SHA"],
    )


def test_source_manifest_ignores_generated_metadata_but_detects_source_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "backend/src"
    source_root.mkdir(parents=True)
    source = source_root / "example.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.setattr(source_integrity_module, "ROOT", tmp_path)
    monkeypatch.setattr(source_integrity_module, "SOURCE_PATHS", ("backend/src",))

    baseline_manifest = source_integrity_module.source_manifest()
    baseline_digest = source_integrity_module.source_digest(baseline_manifest)
    generated_files = (
        source_root / "example.egg-info/PKG-INFO",
        source_root / "example.dist-info/METADATA",
        source_root / "__pycache__/example.cpython-312.pyc",
        source_root / ".pytest_cache/v/cache/nodeids",
        source_root / ".ruff_cache/content",
        source_root / ".mypy_cache/content",
        source_root / ".pyright/content",
        source_root / ".runtime/state.json",
        source_root / ".venv/pyvenv.cfg",
        source_root / "legacy.pyc",
        source_root / ".coverage",
    )
    for generated in generated_files:
        generated.parent.mkdir(parents=True, exist_ok=True)
        generated.write_bytes(b"generated environment metadata")

    generated_manifest = source_integrity_module.source_manifest()
    assert generated_manifest == baseline_manifest
    assert source_integrity_module.source_digest(generated_manifest) == baseline_digest

    source.write_text("VALUE = 2\n", encoding="utf-8")
    changed_manifest = source_integrity_module.source_manifest()
    assert changed_manifest.keys() == baseline_manifest.keys()
    assert (
        changed_manifest["backend/src/example.py"]
        != baseline_manifest["backend/src/example.py"]
    )
    assert source_integrity_module.source_digest(changed_manifest) != baseline_digest


def test_stages_exact_sorted_digest_bound_files_and_verifies_read_only(
    evidence_repository: Path, tmp_path: Path
) -> None:
    output = tmp_path / "evidence-refresh"
    assert _stage(evidence_repository, output) == output

    binding = json.loads((output / BINDING_FILENAME).read_text(encoding="utf-8"))
    assert binding == {
        "schema": BINDING_SCHEMA,
        "repository": GITHUB_ENV["GITHUB_REPOSITORY"],
        "workflow_ref": GITHUB_ENV["GITHUB_WORKFLOW_REF"],
        "run_id": GITHUB_ENV["GITHUB_RUN_ID"],
        "run_attempt": GITHUB_ENV["GITHUB_RUN_ATTEMPT"],
        "head_sha": GITHUB_ENV["GITHUB_SHA"],
        "source_digest": source_digest(SOURCE_FILES),
        "files": binding["files"],
    }
    paths = [entry["path"] for entry in binding["files"]]
    assert paths == sorted(paths)
    assert len(paths) == len(set(paths)) == 48
    assert all(set(entry) == {"path", "sha256"} for entry in binding["files"])
    actual_files = {
        path.relative_to(output).as_posix()
        for path in output.rglob("*")
        if path.is_file()
    }
    assert actual_files == set(paths) | {BINDING_FILENAME}
    assert not any(
        path.endswith("production-closure-input.json") for path in actual_files
    )

    before = {
        path.relative_to(output).as_posix(): path.read_bytes()
        for path in output.rglob("*")
        if path.is_file()
    }
    assert _verify(output) == output
    after = {
        path.relative_to(output).as_posix(): path.read_bytes()
        for path in output.rglob("*")
        if path.is_file()
    }
    assert after == before


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("status", "pass", "batch/status"),
        ("source_digest", "d" * 64, "source_digest"),
        ("source_file_count", 3, "source_file_count"),
    ],
)
def test_rejects_non_partial_or_stale_manifest(
    evidence_repository: Path,
    tmp_path: Path,
    field: str,
    value: Any,
    message: str,
) -> None:
    path, manifest = _manifest(evidence_repository)
    manifest[field] = value
    _rewrite_manifest(path, manifest)

    with pytest.raises(EvidenceStageError, match=message):
        _stage(evidence_repository, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_rejects_duplicate_json_keys_and_failed_commands(
    evidence_repository: Path, tmp_path: Path
) -> None:
    path, _manifest_value = _manifest(evidence_repository)
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace(
            '  "status": "partial",', '  "status": "partial",\n  "status": "partial",'
        ),
        encoding="utf-8",
    )
    with pytest.raises(EvidenceStageError, match="duplicate JSON key"):
        _stage(evidence_repository, tmp_path / "duplicate-output")

    _write_repository(evidence_repository)
    path, manifest = _manifest(evidence_repository)
    manifest["commands"][0]["exit_code"] = 1
    _rewrite_manifest(path, manifest)
    with pytest.raises(EvidenceStageError, match="not all successful"):
        _stage(evidence_repository, tmp_path / "failed-command-output")


@pytest.mark.parametrize(
    "artifact_path",
    [
        "/etc/passwd",
        "docs/evidence/batch-01/../batch-02/smoke.log",
        "docs/evidence/batch-02/smoke.log",
        "docs/evidence/batch-01/production-closure-input.json",
    ],
)
def test_rejects_escaping_cross_batch_and_closure_paths(
    evidence_repository: Path, tmp_path: Path, artifact_path: str
) -> None:
    path, manifest = _manifest(evidence_repository)
    manifest["artifacts"][0]["path"] = artifact_path
    _rewrite_manifest(path, manifest)

    with pytest.raises(EvidenceStageError):
        _stage(evidence_repository, tmp_path / "output")


def test_rejects_artifact_digest_mismatch_and_hardlink(
    evidence_repository: Path, tmp_path: Path
) -> None:
    path, manifest = _manifest(evidence_repository)
    manifest["artifacts"][0]["sha256"] = "f" * 64
    _rewrite_manifest(path, manifest)
    with pytest.raises(EvidenceStageError, match="digest mismatch"):
        _stage(evidence_repository, tmp_path / "digest-output")

    _write_repository(evidence_repository)
    artifact = evidence_repository / "docs/evidence/batch-01/smoke.log"
    os.link(artifact, tmp_path / "hardlink.log")
    with pytest.raises(EvidenceStageError, match="single-link"):
        _stage(evidence_repository, tmp_path / "hardlink-output")


def test_rejects_symlink_input_output_parent_and_preexisting_output(
    evidence_repository: Path, tmp_path: Path
) -> None:
    artifact = evidence_repository / "docs/evidence/batch-01/smoke.log"
    target = tmp_path / "target.log"
    target.write_bytes(artifact.read_bytes())
    artifact.unlink()
    artifact.symlink_to(target)
    with pytest.raises(EvidenceStageError, match="symlink"):
        _stage(evidence_repository, tmp_path / "input-link-output")

    _write_repository(evidence_repository)
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(EvidenceStageError, match="symlink"):
        _stage(evidence_repository, linked_parent / "output")

    existing = tmp_path / "existing"
    existing.mkdir()
    marker = existing / "preserved"
    marker.write_text("do not overwrite", encoding="utf-8")
    with pytest.raises(EvidenceStageError, match="already exist"):
        _stage(evidence_repository, existing)
    assert marker.read_text(encoding="utf-8") == "do not overwrite"

    root_link = tmp_path / "repository-link"
    root_link.symlink_to(evidence_repository, target_is_directory=True)
    with pytest.raises(EvidenceStageError, match="symlink"):
        _stage(root_link, tmp_path / "root-link-output")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("GITHUB_REPOSITORY", "zpcaiai/IndustryShadow "),
        ("GITHUB_WORKFLOW_REF", "other/repo/.github/workflows/ci.yml@refs/heads/main"),
        ("GITHUB_RUN_ID", "0"),
        ("GITHUB_RUN_ATTEMPT", "01"),
        ("GITHUB_SHA", "A" * 40),
    ],
)
def test_rejects_noncanonical_github_coordinates(
    evidence_repository: Path, tmp_path: Path, name: str, value: str
) -> None:
    environ = {**GITHUB_ENV, name: value}
    with pytest.raises(EvidenceStageError):
        stage_evidence_refresh(
            tmp_path / "output", root=evidence_repository, environ=environ
        )


def test_verifier_rejects_tampering_extra_files_and_coordinate_mismatch(
    evidence_repository: Path, tmp_path: Path
) -> None:
    tampered = _stage(evidence_repository, tmp_path / "tampered")
    tampered_artifact = tampered / "docs/evidence/batch-01/smoke.log"
    tampered_artifact.chmod(0o600)
    tampered_artifact.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(EvidenceStageError, match="digest mismatch"):
        _verify(tampered)

    extra = _stage(evidence_repository, tmp_path / "extra")
    (extra / "unexpected.txt").write_text("extra", encoding="utf-8")
    with pytest.raises(EvidenceStageError, match="extra files"):
        _verify(extra)

    mismatch = _stage(evidence_repository, tmp_path / "mismatch")
    with pytest.raises(EvidenceStageError, match="coordinates do not match"):
        verify_evidence_refresh(
            mismatch,
            repository=GITHUB_ENV["GITHUB_REPOSITORY"],
            workflow_ref=GITHUB_ENV["GITHUB_WORKFLOW_REF"],
            run_id="999",
            run_attempt=GITHUB_ENV["GITHUB_RUN_ATTEMPT"],
            head_sha=GITHUB_ENV["GITHUB_SHA"],
        )


def test_verifier_rejects_duplicate_binding_keys(
    evidence_repository: Path, tmp_path: Path
) -> None:
    staging = _stage(evidence_repository, tmp_path / "duplicate-binding")
    binding = staging / BINDING_FILENAME
    binding.chmod(0o600)
    text = binding.read_text(encoding="utf-8")
    binding.write_text(
        text.replace(
            f'"schema":"{BINDING_SCHEMA}"',
            f'"schema":"{BINDING_SCHEMA}","schema":"{BINDING_SCHEMA}"',
        ),
        encoding="utf-8",
    )
    with pytest.raises(EvidenceStageError, match="duplicate JSON key"):
        _verify(staging)
