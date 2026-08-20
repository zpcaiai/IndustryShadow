from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import re
import tempfile
import uuid
from collections.abc import Sequence
from contextlib import ExitStack, closing
from dataclasses import replace
from pathlib import Path
from typing import Protocol
from urllib.parse import unquote, urlsplit

from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json
from shadow_sandbox.common.object_storage import (
    LocalObjectStorage,
    ObjectRef,
    ObjectRetention,
)
from shadow_sandbox.common.sqlalchemy_store import SqlAlchemyStore
from shadow_sandbox.operations.backup_job import create_backup
from shadow_sandbox.operations.database_roles import DatabaseRoleConfigurator
from shadow_sandbox.operations.evidence import write_evidence
from shadow_sandbox.operations.restore_drill import PostgreSqlRestoreDrill
from sqlalchemy.engine import make_url

try:
    from .postgresql_test_roles import temporary_postgresql_test_role
except ImportError:  # pragma: no cover - direct script execution
    from postgresql_test_roles import temporary_postgresql_test_role


class _QueryStore(Protocol):
    def query(
        self, sql: str, parameters: Sequence[object] = ()
    ) -> list[dict[str, object]]: ...


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
    hostname = urlsplit(
        value.replace("postgresql+psycopg://", "postgresql://", 1)
    ).hostname
    if hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise DomainError(
            "LOCAL_RESTORE_TARGET_FORBIDDEN",
            f"{name} must identify a loopback PostgreSQL endpoint",
        )
    return value


def _database_name(database_url: str) -> str:
    parsed = urlsplit(database_url.replace("postgresql+psycopg://", "postgresql://", 1))
    database = unquote(parsed.path.removeprefix("/"))
    if not database or "/" in database:
        raise DomainError(
            "LOCAL_RESTORE_CONFIG_INVALID",
            "local PostgreSQL URLs must identify one database",
        )
    return database


def _require_disposable_database_names(source_url: str, target_url: str) -> None:
    source_database = _database_name(source_url)
    target_database = _database_name(target_url)
    if re.search(r"(?:^|_)(?:test|fixture|smoke)(?:_|$)", source_database) is None:
        raise DomainError(
            "LOCAL_RESTORE_SOURCE_FORBIDDEN",
            "local restore source database must be explicitly named as test, fixture, or smoke",
        )
    if (
        re.fullmatch(r"[a-zA-Z0-9_]*restore_drill[a-zA-Z0-9_]*", target_database)
        is None
    ):
        raise DomainError(
            "LOCAL_RESTORE_TARGET_FORBIDDEN",
            "local restore target database name must contain restore_drill",
        )


def _cluster_identifier(store: _QueryStore) -> str:
    rows = store.query(
        "SELECT system_identifier::text AS identifier FROM pg_control_system()"
    )
    if (
        len(rows) != 1
        or not isinstance(rows[0].get("identifier"), str)
        or re.fullmatch(r"[0-9]+", str(rows[0]["identifier"])) is None
    ):
        raise DomainError(
            "LOCAL_RESTORE_CLUSTER_IDENTITY_INVALID",
            "local PostgreSQL cluster identity could not be verified",
        )
    return str(rows[0]["identifier"])


def _require_empty_restore_target(store: SqlAlchemyStore) -> None:
    result = store.query(
        """SELECT COUNT(*) AS count
             FROM (
                   SELECT relation.oid
                     FROM pg_class relation
                     JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
                    WHERE namespace.nspname='public'
                      AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
                   UNION ALL
                   SELECT routine.oid
                     FROM pg_proc routine
                     JOIN pg_namespace namespace ON namespace.oid=routine.pronamespace
                    WHERE namespace.nspname='public'
                   UNION ALL
                   SELECT type_object.oid
                     FROM pg_type type_object
                     JOIN pg_namespace namespace ON namespace.oid=type_object.typnamespace
                    WHERE namespace.nspname='public'
                 ) AS existing_objects"""
    )
    if len(result) != 1 or int(result[0]["count"]):
        raise DomainError(
            "LOCAL_RESTORE_TARGET_NOT_EMPTY",
            "local restore target public schema must be empty before any fixture mutation",
        )


def _positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise DomainError(
            "LOCAL_RESTORE_CONFIG_INVALID", f"{name} must be an integer"
        ) from error
    if value < 1:
        raise DomainError("LOCAL_RESTORE_CONFIG_INVALID", f"{name} must be positive")
    return value


def _database_role_url(database_url: str, *, role: str, password: str) -> str:
    return (
        make_url(database_url)
        .set(username=role, password=password)
        .render_as_string(hide_password=False)
    )


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
    if os.environ.get("SHADOW_ALLOW_LOCAL_RESTORE_DRILL") != "true":
        raise DomainError(
            "RESTORE_CONFIRMATION_REQUIRED",
            "explicit destructive local restore confirmation is required before any mutation",
        )
    _require_disposable_database_names(source_url, target_url)
    region_value = os.environ.get("SHADOW_OBJECT_STORAGE_REGION", "").strip()
    region = (
        region_value
        if re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*", region_value)
        else "us-east-1"
    )
    account_value = os.environ.get("SHADOW_AWS_ACCOUNT_ID", "").strip()
    account_id = (
        account_value if re.fullmatch(r"\d{12}", account_value) else "000000000000"
    )
    partition = (
        "aws-cn"
        if region.startswith("cn-")
        else "aws-us-gov"
        if region.startswith("us-gov-")
        else "aws"
    )
    kms_key_id = f"arn:{partition}:kms:{region}:{account_id}:key/local-restore-smoke"
    suffix = uuid.uuid4().hex
    tenant_role = f"shadow_local_api_{suffix}"
    maintenance_role = f"shadow_local_maintenance_{suffix}"
    backup_role = f"shadow_local_backup_{suffix}"
    tenant_password = uuid.uuid4().hex
    maintenance_password = uuid.uuid4().hex
    backup_password = uuid.uuid4().hex
    with ExitStack() as stack:
        source_admin = stack.enter_context(closing(SqlAlchemyStore(source_url)))
        target_admin = stack.enter_context(closing(SqlAlchemyStore(target_url)))
        if _cluster_identifier(source_admin) == _cluster_identifier(target_admin):
            raise DomainError(
                "LOCAL_RESTORE_CLUSTER_COLLISION",
                "source and restore target must use distinct disposable PostgreSQL clusters",
            )
        _require_empty_restore_target(target_admin)
        role_specs = (
            (tenant_role, tenant_password, False),
            (maintenance_role, maintenance_password, True),
            (backup_role, backup_password, True),
        )
        for admin in (source_admin, target_admin):
            for role, password, bypass_rls in role_specs:
                stack.enter_context(
                    temporary_postgresql_test_role(
                        admin,
                        role=role,
                        password=password,
                        bypass_rls=bypass_rls,
                    )
                )
        DatabaseRoleConfigurator(
            source_admin,
            tenant_roles=(tenant_role,),
            maintenance_role=maintenance_role,
            backup_role=backup_role,
        ).configure()
        source_backup_url = _database_role_url(
            source_url,
            role=backup_role,
            password=backup_password,
        )
        target_application_url = _database_role_url(
            target_url,
            role=tenant_role,
            password=tenant_password,
        )
        target_backup_url = _database_role_url(
            target_url,
            role=backup_role,
            password=backup_password,
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
                database_url_override=source_backup_url,
                kms_key_id_override=kms_key_id,
                storage_override=storage,
            )
            receipt_path = root / "backup-receipt.json"
            receipt_path.write_text(canonical_json(receipt) + "\n", encoding="utf-8")
            receipt_path.chmod(0o600)
            evidence = PostgreSqlRestoreDrill(
                source_backup_url,
                target_url,
                allow_restore=True,
                application_target_url=target_application_url,
                backup_target_url=target_backup_url,
                tenant_roles=(tenant_role,),
                maintenance_role=maintenance_role,
                backup_role=backup_role,
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
