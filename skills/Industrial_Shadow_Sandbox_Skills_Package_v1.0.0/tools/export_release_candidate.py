from __future__ import annotations

import argparse
import os
import shutil
import stat
import tempfile
from pathlib import Path

from shadow_sandbox.common.models import canonical_json
from shadow_sandbox.operations.supply_chain import ReleaseCandidate


def _stage(candidate: ReleaseCandidate, destination: Path) -> ReleaseCandidate:
    parent = candidate.path.parent
    destination = destination.resolve()
    if destination == parent or parent in destination.parents or destination in parent.parents:
        raise ValueError("candidate source and staging directories must be disjoint")
    bundle = parent / "candidate-manifest.attestation.json"
    if (
        bundle.is_symlink()
        or not bundle.is_file()
        or not stat.S_ISREG(bundle.stat().st_mode)
        or bundle.stat().st_nlink != 1
        or not 1 <= bundle.stat().st_size <= 16 * 1024 * 1024
    ):
        raise ValueError("candidate manifest attestation is missing or unsafe")
    paths = {
        candidate.path,
        candidate.backend_sbom.path,
        candidate.web_sbom.path,
        candidate.postgresql_migration_manifest.path,
        bundle.resolve(strict=True),
        *(item.path for item in candidate.attestations.values()),
    }
    destination.mkdir(parents=True, exist_ok=False)
    copied: list[Path] = []
    for source in sorted(paths):
        relative = source.relative_to(parent)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".candidate-", dir=target.parent)
        try:
            with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_file:
                shutil.copyfileobj(input_file, output, length=1024 * 1024)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, 0o444)
            os.replace(temporary, target)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        copied.append(target.resolve())
    actual = {
        path.resolve()
        for path in destination.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual != set(copied):
        raise ValueError("candidate staging directory contains undeclared files")
    return ReleaseCandidate.load(
        destination / candidate.path.name,
        expected_repository=candidate.repository,
        expected_run_id=candidate.release_run_id,
        expected_run_attempt=candidate.release_run_attempt,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and export immutable release coordinates")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--github-env", type=Path)
    parser.add_argument("--stage-dir", type=Path)
    args = parser.parse_args()
    candidate = ReleaseCandidate.load(
        args.manifest,
        expected_repository=args.repository,
        expected_run_id=args.run_id,
        expected_run_attempt=args.run_attempt,
    )
    if args.stage_dir:
        candidate = _stage(candidate, args.stage_dir)
    values = {
        "SHADOW_RELEASE_CANDIDATE_MANIFEST": str(candidate.path),
        "SHADOW_RELEASE_CANDIDATE_BUNDLE": str(
            candidate.path.parent / "candidate-manifest.attestation.json"
        ),
        "SHADOW_CANDIDATE_IMAGE": candidate.backend_image,
        "SHADOW_WEB_CANDIDATE_IMAGE": candidate.web_image,
        "SHADOW_BUILD_DIGEST": candidate.source_digest,
        "SHADOW_SIMULATOR_BUILD_DIGEST": candidate.source_digest,
        "SHADOW_RELEASE_SOURCE_REVISION": candidate.source_revision,
        "SHADOW_RELEASE_REPOSITORY": candidate.repository,
        "SHADOW_RELEASE_RUN_ID": candidate.release_run_id,
        "SHADOW_RELEASE_RUN_ATTEMPT": str(candidate.release_run_attempt),
        "SHADOW_POSTGRESQL_MIGRATION_MANIFEST": str(
            candidate.postgresql_migration_manifest.path
        ),
    }
    if args.github_env:
        descriptor = os.open(args.github_env, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            for name, value in values.items():
                if "\n" in value or "\r" in value:
                    raise ValueError("release coordinate contains a line break")
                handle.write(f"{name}={value}\n")
    print(canonical_json(values))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
