from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import re
import tempfile
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json
from shadow_sandbox.common.object_storage import (
    LocalObjectStorage,
    ObjectRef,
    ObjectRetention,
)
from shadow_sandbox.operations.backup_job import create_backup
from shadow_sandbox.operations.evidence import write_evidence
from shadow_sandbox.operations.restore_drill import PostgreSqlRestoreDrill


class _LocalImmutableTestStorage:
    """Process-local version/KMS/retention simulation for the disposable smoke only."""

    def __init__(
        self,
        root: Path,
        *,
        kms_key_id: str,
        region: str,
        account_id: str,
    ) -> None:
        self._storage = LocalObjectStorage(root)
        self._objects: dict[str, ObjectRef] = {}
        self._ordinal = 0
        self.kms_key_id = kms_key_id
        self.region = region
        self.expected_bucket_owner = account_id

    def _versioned(self, reference: ObjectRef) -> ObjectRef:
        self._ordinal += 1
        version_id = canonical_digest(
            {
                "local_smoke_key": reference.key,
                "sha256": reference.sha256,
                "ordinal": self._ordinal,
            }
        )
        value = replace(
            reference,
            version_id=version_id,
            encryption="aws:kms",
        )
        self._objects[value.key] = value
        return value

    def _reference(self, key: str, version_id: str) -> ObjectRef:
        reference = self._objects.get(key)
        if reference is None or reference.version_id != version_id:
            raise DomainError(
                "LOCAL_RESTORE_OBJECT_VERSION_INVALID",
                "local restore smoke requested an unknown object version",
            )
        return reference

    def put_bytes(self, key: str, data: bytes, *, content_type: str) -> ObjectRef:
        return self._versioned(
            self._storage.put_bytes(key, data, content_type=content_type)
        )

    def put_file(self, key: str, source: str | Path, *, content_type: str) -> ObjectRef:
        return self._versioned(
            self._storage.put_file(key, source, content_type=content_type)
        )

    def get_bytes(self, key: str, *, maximum_bytes: int = 64 * 1024 * 1024) -> bytes:
        return self._storage.get_bytes(key, maximum_bytes=maximum_bytes)

    def get_version_bytes(
        self,
        key: str,
        *,
        version_id: str,
        maximum_bytes: int = 64 * 1024 * 1024,
        expected_sha256: str | None = None,
    ) -> bytes:
        reference = self._reference(key, version_id)
        payload = self._storage.get_bytes(key, maximum_bytes=maximum_bytes)
        digest = hashlib.sha256(payload).hexdigest()
        if digest != reference.sha256 or (
            expected_sha256 is not None and digest != expected_sha256
        ):
            raise DomainError(
                "LOCAL_RESTORE_OBJECT_INTEGRITY_INVALID",
                "local restore smoke object checksum changed",
            )
        return payload

    def get_file(
        self,
        key: str,
        destination: str | Path,
        *,
        maximum_bytes: int,
        expected_sha256: str | None = None,
        version_id: str | None = None,
    ) -> ObjectRef:
        if version_id is None:
            raise DomainError(
                "LOCAL_RESTORE_OBJECT_VERSION_INVALID",
                "local restore smoke requires an exact object version",
            )
        reference = self._reference(key, version_id)
        downloaded = self._storage.get_file(
            key,
            destination,
            maximum_bytes=maximum_bytes,
            expected_sha256=expected_sha256,
        )
        if downloaded.size != reference.size or downloaded.sha256 != reference.sha256:
            raise DomainError(
                "LOCAL_RESTORE_OBJECT_INTEGRITY_INVALID",
                "local restore smoke download changed",
            )
        return reference

    def get_version_retention(self, key: str, *, version_id: str) -> ObjectRetention:
        self._reference(key, version_id)
        return ObjectRetention(
            "COMPLIANCE",
            (dt.datetime.now(dt.UTC) + dt.timedelta(days=1)).isoformat(),
        )

    def delete(self, key: str) -> None:
        self._objects.pop(key, None)
        self._storage.delete(key)


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise DomainError("LOCAL_RESTORE_CONFIG_MISSING", f"{name} is required")
    return value


def _local_database_url(name: str) -> str:
    value = _required(name)
    hostname = urlsplit(value.replace("postgresql+psycopg://", "postgresql://", 1)).hostname
    if hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise DomainError(
            "LOCAL_RESTORE_TARGET_FORBIDDEN",
            f"{name} must identify a loopback PostgreSQL endpoint",
        )
    return value


def _positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise DomainError("LOCAL_RESTORE_CONFIG_INVALID", f"{name} must be an integer") from error
    if value < 1:
        raise DomainError("LOCAL_RESTORE_CONFIG_INVALID", f"{name} must be positive")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a destructive restore only against an explicitly disposable local target"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/local-postgresql-restore-evidence.json"),
    )
    args = parser.parse_args()
    source_url = _local_database_url("SHADOW_TEST_POSTGRESQL_URL")
    target_url = _local_database_url("SHADOW_TEST_RESTORE_POSTGRESQL_URL")
    region_value = os.environ.get("SHADOW_OBJECT_STORAGE_REGION", "").strip()
    region = (
        region_value
        if re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*", region_value)
        else "us-east-1"
    )
    account_value = os.environ.get("SHADOW_AWS_ACCOUNT_ID", "").strip()
    account_id = account_value if re.fullmatch(r"\d{12}", account_value) else "000000000000"
    partition = (
        "aws-cn"
        if region.startswith("cn-")
        else "aws-us-gov"
        if region.startswith("us-gov-")
        else "aws"
    )
    kms_key_id = (
        f"arn:{partition}:kms:{region}:{account_id}:key/local-restore-smoke"
    )
    with tempfile.TemporaryDirectory(prefix="shadow-local-restore-") as directory:
        root = Path(directory)
        storage = _LocalImmutableTestStorage(
            root / "object-storage",
            kms_key_id=kms_key_id,
            region=region,
            account_id=account_id,
        )
        receipt = create_backup(
            database_url_override=source_url,
            kms_key_id_override=kms_key_id,
            storage_override=storage,
        )
        receipt_path = root / "backup-receipt.json"
        receipt_path.write_text(canonical_json(receipt) + "\n", encoding="utf-8")
        receipt_path.chmod(0o600)
        evidence = PostgreSqlRestoreDrill(
            source_url,
            target_url,
            allow_restore=os.environ.get("SHADOW_ALLOW_LOCAL_RESTORE_DRILL") == "true",
            maximum_restore_seconds=_positive_int(
                "SHADOW_LOCAL_RESTORE_MAXIMUM_SECONDS", 300
            ),
            maximum_archive_bytes=_positive_int(
                "SHADOW_LOCAL_RESTORE_MAXIMUM_ARCHIVE_BYTES", 1024**3
            ),
            managed_provider="local-disposable-postgresql",
            require_managed_coordinates=False,
            object_storage=storage,
            backup_receipt_path=receipt_path,
            kms_key_id=kms_key_id,
            maximum_rpo_seconds=_positive_int(
                "SHADOW_LOCAL_RESTORE_MAXIMUM_RPO_SECONDS", 3600
            ),
            require_immutable_backup=True,
        ).run()
    evidence = replace(
        evidence,
        limitations=(
            *evidence.limitations,
            "local_smoke_simulates_versioning_kms_and_object_lock",
        ),
        digest="",
    ).sealed()
    write_evidence(args.output, evidence)
    metrics = evidence.metrics
    print(
        "Local disposable PostgreSQL restore passed: "
        f"{metrics['tables']} tables, {metrics['rows']} rows, "
        f"{metrics['rls_policies']} RLS policies, "
        f"restore {metrics['restore_seconds']}s; local storage controls were simulated."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
