from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now

from .evidence import GateCheck, GateEvidence, complete

IMAGE_DIGEST = re.compile(r"^[^@\s]+@sha256:[a-f0-9]{64}$")
SOURCE_REVISION = re.compile(r"^[a-f0-9]{40}$")
DIGEST = re.compile(r"^[a-f0-9]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REGISTRY = re.compile(r"^(?:localhost|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::[0-9]{1,5})?$")
MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "repository",
        "release_run_id",
        "release_run_attempt",
        "source_revision",
        "source_digest",
        "backend_image",
        "web_image",
        "backend_sbom",
        "web_sbom",
        "postgresql_migration_manifest",
        "attestations",
        "manifest_digest",
    }
)
FILE_KEYS = frozenset({"path", "sha256"})
ATTESTATION_KEYS = frozenset({"path", "sha256", "predicate_type"})
ATTESTATION_NAMES = frozenset(
    {"backend_provenance", "backend_sbom", "web_provenance", "web_sbom"}
)
PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1"
SBOM_PREDICATE = "https://spdx.dev/Document/v2.3"

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def _image_registry(image: str) -> str:
    first = image.split("@", 1)[0].split("/", 1)[0].lower()
    return first if "." in first or ":" in first or first == "localhost" else "docker.io"


def _secure_file(parent: Path, relative: str, expected_sha256: str) -> Path:
    raw = Path(relative)
    if raw.is_absolute() or any(part in {"", ".", ".."} for part in raw.parts):
        raise DomainError("RELEASE_CANDIDATE_INVALID", "candidate artifact path is invalid")
    cursor = parent
    for part in raw.parts:
        cursor /= part
        if cursor.is_symlink():
            raise DomainError(
                "RELEASE_CANDIDATE_INVALID",
                "candidate artifact paths must not contain symlinks",
            )
    candidate = parent / raw
    resolved = candidate.resolve(strict=True)
    if (
        parent.resolve() not in resolved.parents
        or not resolved.is_file()
        or resolved.stat().st_nlink != 1
        or not 1 <= resolved.stat().st_size <= 64 * 1024 * 1024
    ):
        raise DomainError("RELEASE_CANDIDATE_INVALID", "candidate artifact escaped its bundle")
    if not DIGEST.fullmatch(expected_sha256):
        raise DomainError("RELEASE_CANDIDATE_INVALID", "candidate artifact digest is invalid")
    if hashlib.sha256(resolved.read_bytes()).hexdigest() != expected_sha256:
        raise DomainError("RELEASE_CANDIDATE_INVALID", "candidate artifact digest mismatch")
    return resolved


@dataclass(frozen=True, slots=True)
class CandidateArtifact:
    path: Path
    sha256: str
    predicate_type: str | None = None


@dataclass(frozen=True, slots=True)
class ReleaseCandidate:
    path: Path
    repository: str
    release_run_id: str
    release_run_attempt: int
    source_revision: str
    source_digest: str
    backend_image: str
    web_image: str
    backend_sbom: CandidateArtifact
    web_sbom: CandidateArtifact
    postgresql_migration_manifest: CandidateArtifact
    attestations: Mapping[str, CandidateArtifact]
    manifest_digest: str

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        expected_repository: str | None = None,
        expected_run_id: str | None = None,
        expected_run_attempt: int | None = None,
    ) -> ReleaseCandidate:
        candidate_path = Path(path)
        if candidate_path.is_symlink():
            raise DomainError("RELEASE_CANDIDATE_INVALID", "candidate manifest is a symlink")
        resolved = candidate_path.resolve(strict=True)
        if (
            not resolved.is_file()
            or resolved.stat().st_nlink != 1
            or not 1 <= resolved.stat().st_size <= 1024 * 1024
        ):
            raise DomainError("RELEASE_CANDIDATE_INVALID", "candidate manifest is unsafe")
        try:
            value = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise DomainError("RELEASE_CANDIDATE_INVALID", "candidate manifest is invalid") from error
        if (
            not isinstance(value, Mapping)
            or set(value) != MANIFEST_KEYS
            or value.get("schema_version") != 2
        ):
            raise DomainError("RELEASE_CANDIDATE_INVALID", "candidate manifest fields are invalid")
        claimed = str(value.get("manifest_digest", ""))
        if claimed != canonical_digest({**value, "manifest_digest": ""}):
            raise DomainError("RELEASE_CANDIDATE_INVALID", "candidate manifest digest mismatch")
        repository = str(value.get("repository", ""))
        run_id = str(value.get("release_run_id", ""))
        run_attempt = value.get("release_run_attempt")
        source_revision = str(value.get("source_revision", ""))
        source_digest = str(value.get("source_digest", ""))
        backend_image = str(value.get("backend_image", ""))
        web_image = str(value.get("web_image", ""))
        if (
            not REPOSITORY.fullmatch(repository)
            or not re.fullmatch(r"[1-9][0-9]*", run_id)
            or isinstance(run_attempt, bool)
            or not isinstance(run_attempt, int)
            or run_attempt < 1
            or not SOURCE_REVISION.fullmatch(source_revision)
            or not DIGEST.fullmatch(source_digest)
            or not IMAGE_DIGEST.fullmatch(backend_image)
            or not IMAGE_DIGEST.fullmatch(web_image)
            or _image_registry(backend_image) != _image_registry(web_image)
            or (expected_repository is not None and repository != expected_repository)
            or (expected_run_id is not None and run_id != expected_run_id)
            or (expected_run_attempt is not None and run_attempt != expected_run_attempt)
        ):
            raise DomainError("RELEASE_CANDIDATE_INVALID", "candidate coordinates are invalid")
        parent = resolved.parent

        def file_artifact(raw: Any) -> CandidateArtifact:
            if not isinstance(raw, Mapping) or set(raw) != FILE_KEYS:
                raise DomainError("RELEASE_CANDIDATE_INVALID", "candidate file fields are invalid")
            sha256 = str(raw.get("sha256", ""))
            artifact_path = _secure_file(parent, str(raw.get("path", "")), sha256)
            return CandidateArtifact(artifact_path, sha256)

        backend_sbom = file_artifact(value.get("backend_sbom"))
        web_sbom = file_artifact(value.get("web_sbom"))
        postgresql_migration_manifest = file_artifact(
            value.get("postgresql_migration_manifest")
        )
        raw_attestations = value.get("attestations")
        if not isinstance(raw_attestations, Mapping) or set(raw_attestations) != ATTESTATION_NAMES:
            raise DomainError("RELEASE_CANDIDATE_INVALID", "candidate attestations are incomplete")
        attestations: dict[str, CandidateArtifact] = {}
        for name, raw in raw_attestations.items():
            if not isinstance(raw, Mapping) or set(raw) != ATTESTATION_KEYS:
                raise DomainError("RELEASE_CANDIDATE_INVALID", "attestation fields are invalid")
            predicate = str(raw.get("predicate_type", ""))
            expected_predicate = SBOM_PREDICATE if name.endswith("_sbom") else PROVENANCE_PREDICATE
            if predicate != expected_predicate:
                raise DomainError("RELEASE_CANDIDATE_INVALID", "attestation predicate is invalid")
            sha256 = str(raw.get("sha256", ""))
            attestations[str(name)] = CandidateArtifact(
                _secure_file(parent, str(raw.get("path", "")), sha256),
                sha256,
                predicate,
            )
        artifact_paths = {
            backend_sbom.path,
            web_sbom.path,
            postgresql_migration_manifest.path,
            *(artifact.path for artifact in attestations.values()),
        }
        if len(artifact_paths) != 7:
            raise DomainError(
                "RELEASE_CANDIDATE_INVALID",
                "candidate artifacts must use distinct files",
            )
        return cls(
            resolved,
            repository,
            run_id,
            int(run_attempt),
            source_revision,
            source_digest,
            backend_image,
            web_image,
            backend_sbom,
            web_sbom,
            postgresql_migration_manifest,
            attestations,
            claimed,
        )


class SupplyChainAttestationProbe:
    """Verify release-manifest, provenance, and SBOM Sigstore bundles for both images."""

    def __init__(
        self,
        candidate: ReleaseCandidate,
        *,
        candidate_attestation_bundle: str | Path,
        registry_credentials_file: str | Path,
        run_command: CommandRunner = subprocess.run,
    ) -> None:
        self.candidate = candidate
        bundle = Path(candidate_attestation_bundle)
        if bundle.is_symlink():
            raise DomainError("SUPPLY_CHAIN_BUNDLE_INVALID", "candidate attestation is a symlink")
        self.candidate_bundle = bundle.resolve(strict=True)
        if (
            self.candidate_bundle.parent != candidate.path.parent
            or not self.candidate_bundle.is_file()
            or self.candidate_bundle.stat().st_nlink != 1
            or not 1 <= self.candidate_bundle.stat().st_size <= 16 * 1024 * 1024
        ):
            raise DomainError(
                "SUPPLY_CHAIN_BUNDLE_INVALID",
                "candidate attestation must be a safe file in its release bundle",
            )
        credential_path = Path(registry_credentials_file)
        if credential_path.is_symlink():
            raise DomainError(
                "SUPPLY_CHAIN_CREDENTIAL_INVALID",
                "registry credentials must not be a symlink",
            )
        self.registry_credentials_file = credential_path.resolve(strict=True)
        if (
            not self.registry_credentials_file.is_file()
            or self.registry_credentials_file.stat().st_nlink != 1
            or not 1 <= self.registry_credentials_file.stat().st_size <= 1024 * 1024
        ):
            raise DomainError(
                "SUPPLY_CHAIN_CREDENTIAL_INVALID",
                "registry credentials must be a regular single-link file",
            )
        self.run_command = run_command

    @staticmethod
    def _subject_matches(statement: Mapping[str, Any], subject: str) -> bool:
        values = statement.get("subject")
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], Mapping):
            return False
        item = values[0]
        digest = item.get("digest")
        if not isinstance(digest, Mapping) or set(digest) != {"sha256"}:
            return False
        if subject.startswith("oci://"):
            expected_name, expected_digest = subject.removeprefix("oci://").rsplit("@sha256:", 1)
            return item.get("name") == expected_name and digest.get("sha256") == expected_digest
        return (
            item.get("name") == Path(subject).name
            and digest.get("sha256") == hashlib.sha256(Path(subject).read_bytes()).hexdigest()
        )

    def _credentials(self) -> tuple[str, str, str]:
        if stat.S_IMODE(self.registry_credentials_file.stat().st_mode) & 0o077:
            raise DomainError(
                "SUPPLY_CHAIN_CREDENTIAL_PERMISSIONS",
                "registry credentials must not be readable by group or other users",
            )
        try:
            value = json.loads(
                self.registry_credentials_file.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as error:
            raise DomainError(
                "SUPPLY_CHAIN_CREDENTIAL_INVALID",
                "registry credentials are invalid",
            ) from error
        if not isinstance(value, Mapping) or set(value) != {
            "registry",
            "username",
            "access_token",
        }:
            raise DomainError(
                "SUPPLY_CHAIN_CREDENTIAL_INVALID", "registry credential fields are invalid"
            )
        registry = str(value.get("registry", "")).strip().lower()
        username = str(value.get("username", "")).strip()
        token = str(value.get("access_token", ""))
        if (
            not REGISTRY.fullmatch(registry)
            or registry != _image_registry(self.candidate.backend_image)
            or not username
            or not token
            or any("\n" in item or "\r" in item for item in (registry, username, token))
        ):
            raise DomainError(
                "SUPPLY_CHAIN_CREDENTIAL_INVALID", "registry credential values are invalid"
            )
        return registry, username, token

    def _verify(
        self,
        subject: str,
        bundle: Path,
        predicate_type: str,
        environment: Mapping[str, str],
        *,
        expected_predicate_path: Path | None = None,
    ) -> None:
        result = self.run_command(
            [
                "gh",
                "attestation",
                "verify",
                subject,
                "--repo",
                self.candidate.repository,
                "--bundle",
                str(bundle),
                "--signer-workflow",
                f"{self.candidate.repository}/.github/workflows/release.yml",
                "--source-digest",
                self.candidate.source_revision,
                "--predicate-type",
                predicate_type,
                "--deny-self-hosted-runners",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=300,
            env=dict(environment),
            check=False,
        )
        try:
            verified = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise DomainError(
                "SUPPLY_CHAIN_ATTESTATION_INVALID", "attestation verifier output is invalid"
            ) from error
        if result.returncode != 0 or not isinstance(verified, list) or len(verified) != 1:
            raise DomainError(
                "SUPPLY_CHAIN_ATTESTATION_INVALID",
                "release artifact attestation verification failed",
            )
        verification = verified[0]
        statement = (
            verification.get("verificationResult", {}).get("statement", {})
            if isinstance(verification, Mapping)
            else {}
        )
        if not isinstance(statement, Mapping):
            raise DomainError(
                "SUPPLY_CHAIN_ATTESTATION_INVALID",
                "verified attestation statement is not an object",
            )
        predicate_matches = True
        if expected_predicate_path is not None:
            try:
                expected_predicate = json.loads(
                    expected_predicate_path.read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError) as error:
                raise DomainError(
                    "SUPPLY_CHAIN_ATTESTATION_INVALID",
                    "local attested predicate is invalid",
                ) from error
            predicate_matches = statement.get("predicate") == expected_predicate
        if (
            not isinstance(statement, Mapping)
            or statement.get("predicateType") != predicate_type
            or not self._subject_matches(statement, subject)
            or not predicate_matches
        ):
            raise DomainError(
                "SUPPLY_CHAIN_ATTESTATION_INVALID",
                "verified attestation statement is not exact",
            )

    def run(self) -> GateEvidence:
        started = utc_now()
        registry, username, token = self._credentials()
        with tempfile.TemporaryDirectory(prefix="industrial-shadow-supply-chain-") as directory:
            os.chmod(directory, 0o700)
            environment = {**os.environ, "DOCKER_CONFIG": directory}
            login = self.run_command(
                ["docker", "login", registry, "--username", username, "--password-stdin"],
                input=token + "\n",
                capture_output=True,
                text=True,
                timeout=60,
                env=environment,
                check=False,
            )
            if login.returncode != 0:
                raise DomainError(
                    "SUPPLY_CHAIN_REGISTRY_AUTH_FAILED",
                    "release registry authentication failed",
                )
            self._verify(
                str(self.candidate.path),
                self.candidate_bundle,
                PROVENANCE_PREDICATE,
                environment,
            )
            for component, image in (
                ("backend", self.candidate.backend_image),
                ("web", self.candidate.web_image),
            ):
                self._verify(
                    "oci://" + image,
                    self.candidate.attestations[f"{component}_provenance"].path,
                    PROVENANCE_PREDICATE,
                    environment,
                )
                self._verify(
                    "oci://" + image,
                    self.candidate.attestations[f"{component}_sbom"].path,
                    SBOM_PREDICATE,
                    environment,
                    expected_predicate_path=(
                        self.candidate.backend_sbom.path
                        if component == "backend"
                        else self.candidate.web_sbom.path
                    ),
                )
        bundle_hashes = {
            name: artifact.sha256 for name, artifact in sorted(self.candidate.attestations.items())
        }
        candidate_bundle_sha = hashlib.sha256(self.candidate_bundle.read_bytes()).hexdigest()
        return complete(
            "supply_chain",
            started_at=started,
            coordinates={
                "repository": self.candidate.repository,
                "release_run_id": self.candidate.release_run_id,
                "release_run_attempt": self.candidate.release_run_attempt,
                "source_revision": self.candidate.source_revision,
                "source_digest": self.candidate.source_digest,
                "backend_image": self.candidate.backend_image,
                "web_image": self.candidate.web_image,
                "candidate_manifest_digest": self.candidate.manifest_digest,
                "signer_workflow": f"{self.candidate.repository}/.github/workflows/release.yml",
            },
            checks=(
                GateCheck("candidate_manifest_attested", True),
                GateCheck("backend_provenance_attested", True),
                GateCheck("backend_sbom_attested", True),
                GateCheck("web_provenance_attested", True),
                GateCheck("web_sbom_attested", True),
                GateCheck("hosted_release_builder", True),
            ),
            metrics={
                "attestations_verified": 5,
                "candidate_bundle_sha256": candidate_bundle_sha,
                "backend_sbom_sha256": self.candidate.backend_sbom.sha256,
                "web_sbom_sha256": self.candidate.web_sbom.sha256,
                "postgresql_migration_manifest_sha256": (
                    self.candidate.postgresql_migration_manifest.sha256
                ),
                "release_run_attempt": self.candidate.release_run_attempt,
                "candidate_manifest_digest": self.candidate.manifest_digest,
                **{f"{name}_bundle_sha256": digest for name, digest in bundle_hashes.items()},
            },
        )
