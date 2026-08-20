from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from shadow_sandbox.common.models import (
    DomainError,
    canonical_digest,
    canonical_json,
    utc_now,
)
from shadow_sandbox.common.object_storage import (
    ObjectRef,
    ObjectRetention,
    ObjectStorage,
    create_object_storage,
    sha256_file,
)

from .aws_resource_arns import AwsResourceArn, parse_kms_key_arn
from .database_roles import role_access_matrix, role_matrix_is_exact
from .postgres_coordinates import database_coordinate_digest, postgres_environment
from .restore_drill import (
    MAXIMUM_MANIFEST_BYTES,
    _catalog_inventory,
    _catalog_with_archive_sequence_states,
    _rls_inventory,
    _sequence_names,
    _table_inventory,
)

SNAPSHOT_ID = re.compile(r"^[A-Fa-f0-9-]{5,128}$")
SEQUENCE_TOC = re.compile(r"^\d+;\s+\d+\s+\d+\s+SEQUENCE SET public\s+")
SEQUENCE_SET = re.compile(
    r"^SELECT pg_catalog\.setval\('"
    r"(?P<regclass>(?:[^']|'')+)'"
    r"(?:::(?:pg_catalog\.)?regclass)?,\s*"
    r"(?P<last_value>[+-]?\d+),\s*(?P<is_called>true|false)\);$"
)
MAXIMUM_TOC_BYTES = 16 * 1024 * 1024
MAXIMUM_SEQUENCE_SQL_BYTES = 16 * 1024 * 1024


def _run_postgresql_command(
    command: Sequence[str],
    *,
    timeout: int,
    failure_code: str,
    failure_detail: str,
    environment: Mapping[str, str] | None = None,
) -> None:
    try:
        completed = subprocess.run(
            list(command),
            env=dict(environment) if environment is not None else None,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise DomainError(
            failure_code,
            failure_detail,
            {"command": command[0], "timeout_seconds": timeout},
            status=503,
        ) from error
    except OSError as error:
        raise DomainError(
            failure_code,
            failure_detail,
            {"command": command[0]},
            status=503,
        ) from error
    if completed.returncode:
        raise DomainError(
            failure_code,
            failure_detail,
            {"command": command[0], "exit_code": completed.returncode},
            status=503,
        )


class PostgreSqlBackupSnapshot(AbstractContextManager["PostgreSqlBackupSnapshot"]):
    """Keep one exported read-only snapshot alive for pg_dump and all fingerprints."""

    def __init__(self, database_url: str) -> None:
        environment = postgres_environment(database_url)
        self.connection_parameters = {
            "host": environment["PGHOST"],
            "port": environment["PGPORT"],
            "dbname": environment["PGDATABASE"],
            "user": environment["PGUSER"],
            "password": environment["PGPASSWORD"],
            "sslmode": environment["PGSSLMODE"],
            "options": "",
            "connect_timeout": 30,
            "application_name": "industrial-shadow-backup-snapshot",
            **{
                parameter: environment[variable]
                for variable, parameter in {
                    "PGSSLROOTCERT": "sslrootcert",
                    "PGSSLCERT": "sslcert",
                    "PGSSLKEY": "sslkey",
                    "PGSSLCRL": "sslcrl",
                }.items()
                if variable in environment
            },
        }
        self.connection: Any | None = None
        self.snapshot_id = ""
        self.created_at = ""
        self._cursor_counter = 0

    def __enter__(self) -> Self:
        try:
            import psycopg
            from psycopg.rows import dict_row

            connection = psycopg.connect(
                **self.connection_parameters,
                autocommit=True,
                row_factory=dict_row,
            )
            self.connection = connection
            connection.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            connection.execute("SET LOCAL TIME ZONE 'UTC'")
            row = connection.execute("SELECT pg_export_snapshot() AS snapshot_id").fetchone()
        except Exception as error:
            self._close()
            raise DomainError(
                "DATABASE_BACKUP_SNAPSHOT_UNAVAILABLE",
                "the PostgreSQL backup snapshot could not be exported",
                status=503,
            ) from error
        snapshot_id = str(row.get("snapshot_id", "")) if isinstance(row, Mapping) else ""
        if SNAPSHOT_ID.fullmatch(snapshot_id) is None:
            self._close()
            raise DomainError(
                "DATABASE_BACKUP_SNAPSHOT_INVALID",
                "PostgreSQL returned an invalid exported snapshot identifier",
                status=503,
            )
        self.snapshot_id = snapshot_id
        self.created_at = utc_now()
        return self

    @staticmethod
    def _bind(sql: str, parameters: Sequence[Any]) -> tuple[str, tuple[Any, ...]]:
        if sql.count("?") != len(parameters):
            raise DomainError(
                "DATABASE_BACKUP_SNAPSHOT_INVALID",
                "snapshot SQL placeholder count does not match parameters",
            )
        converted = sql
        for _value in parameters:
            converted = converted.replace("?", "%s", 1)
        return converted, tuple(parameters)

    def _require_connection(self) -> Any:
        if self.connection is None:
            raise DomainError("DATABASE_BACKUP_SNAPSHOT_INVALID", "backup snapshot is not active")
        return self.connection

    def query(self, sql: str, parameters: Sequence[Any] = ()) -> list[dict[str, Any]]:
        connection = self._require_connection()
        statement, values = self._bind(sql, parameters)
        with connection.cursor() as cursor:
            cursor.execute(statement, values)
            return [dict(row) for row in cursor.fetchall()]

    def iterate(
        self,
        sql: str,
        parameters: Sequence[Any] = (),
        *,
        batch_size: int = 128,
    ) -> Iterator[dict[str, Any]]:
        if not 1 <= batch_size <= 4096:
            raise DomainError(
                "SQL_BATCH_SIZE_INVALID",
                "streaming query batch size must be between 1 and 4096",
            )
        connection = self._require_connection()
        statement, values = self._bind(sql, parameters)
        self._cursor_counter += 1
        name = f"shadow_backup_snapshot_{self._cursor_counter}"
        with connection.cursor(name=name) as cursor:
            cursor.itersize = batch_size
            cursor.execute(statement, values)
            while rows := cursor.fetchmany(batch_size):
                for row in rows:
                    yield dict(row)

    def _close(self) -> None:
        connection = self.connection
        self.connection = None
        if connection is not None:
            try:
                connection.rollback()
            finally:
                connection.close()

    def __exit__(
        self,
        _type: type[BaseException] | None,
        _value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self._close()


def _snapshot_role_binding(
    snapshot: PostgreSqlBackupSnapshot, *, expected_role: str
) -> dict[str, object]:
    state = snapshot.query(
        """SELECT current_user AS role,
                  roles.rolsuper AS superuser,
                  roles.rolcreatedb AS create_database,
                  roles.rolcreaterole AS create_role,
                  roles.rolreplication AS replication,
                  roles.rolbypassrls AS bypass,
                  roles.rolcanlogin AS can_login,
                  EXISTS (
                    SELECT 1 FROM pg_auth_members membership
                    WHERE membership.member=roles.oid
                  ) AS inherits_membership,
                  EXISTS (
                    SELECT 1 FROM pg_class relation
                    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
                    WHERE namespace.nspname='public' AND relation.relowner=roles.oid
                  ) AS owns_tables,
                  EXISTS (
                    SELECT 1 FROM pg_proc routine
                    JOIN pg_namespace namespace ON namespace.oid=routine.pronamespace
                    WHERE namespace.nspname='public' AND routine.proowner=roles.oid
                  ) AS owns_routines
             FROM pg_roles roles WHERE roles.rolname=current_user"""
    )
    if len(state) != 1:
        raise DomainError(
            "DATABASE_BACKUP_ROLE_INVALID", "backup role identity could not be determined"
        )
    role = str(state[0]["role"])
    matrix = role_access_matrix(snapshot, role)  # type: ignore[arg-type]
    binding = {
        "name": role,
        "bypass_rls": bool(state[0]["bypass"]),
        "owns_tables": bool(state[0]["owns_tables"]),
        "owns_routines": bool(state[0]["owns_routines"]),
        "matrix_exact_read_only": role_matrix_is_exact(matrix, read_write=False),
    }
    if (
        role != expected_role
        or bool(state[0]["superuser"])
        or bool(state[0]["create_database"])
        or bool(state[0]["create_role"])
        or bool(state[0]["replication"])
        or not binding["bypass_rls"]
        or not bool(state[0]["can_login"])
        or bool(state[0]["inherits_membership"])
        or binding["owns_tables"]
        or binding["owns_routines"]
        or not binding["matrix_exact_read_only"]
    ):
        raise DomainError(
            "DATABASE_BACKUP_ROLE_INVALID",
            "backup snapshot role does not match the exact read-only BYPASSRLS contract",
        )
    return binding


def _capture_snapshot_fingerprint(
    snapshot: PostgreSqlBackupSnapshot,
    *,
    expected_backup_role: str,
) -> tuple[dict[str, object], tuple[str, ...]]:
    versions = tuple(
        int(row["version"])
        for row in snapshot.query("SELECT version FROM schema_migrations ORDER BY version")
    )
    head = versions[-1] if versions else 0
    if not versions or versions != tuple(range(1, head + 1)):
        raise DomainError(
            "DATABASE_BACKUP_MIGRATION_HISTORY_INVALID",
            "backup snapshot migration history must be contiguous from version one",
        )
    sequence_names = _sequence_names(snapshot)  # type: ignore[arg-type]
    tables = _table_inventory(snapshot)  # type: ignore[arg-type]
    rls_policies = _rls_inventory(snapshot)  # type: ignore[arg-type]
    catalog = _catalog_inventory(snapshot)  # type: ignore[arg-type]
    if not tables or int(rls_policies["count"]) < 1:
        raise DomainError(
            "DATABASE_BACKUP_SNAPSHOT_INVALID",
            "backup snapshot must contain application tables and RLS policies",
        )
    return (
        {
            "schema_version": 1,
            "capture_method": "pg-export-snapshot-v1",
            "tables": tables,
            "rls_policies": rls_policies,
            "catalog": catalog,
            "migration_versions": list(versions),
            "backup_role": _snapshot_role_binding(snapshot, expected_role=expected_backup_role),
        },
        sequence_names,
    )


def _qualified_regclass(name: str) -> str:
    if re.fullmatch(r"[a-z_][a-z0-9_$]*", name):
        identifier = name
    else:
        identifier = '"' + name.replace('"', '""') + '"'
    return "public." + identifier


def _archive_sequence_states(
    archive: Path,
    *,
    toc_path: Path,
    sequence_names: Sequence[str],
) -> tuple[dict[str, object], ...]:
    if not sequence_names:
        return ()
    try:
        if toc_path.stat().st_size > MAXIMUM_TOC_BYTES:
            raise DomainError(
                "DATABASE_BACKUP_TOC_INVALID", "backup table-of-contents exceeds its size limit"
            )
        selected = [
            line
            for line in toc_path.read_text(encoding="utf-8").splitlines()
            if SEQUENCE_TOC.match(line)
        ]
    except (OSError, UnicodeError) as error:
        raise DomainError(
            "DATABASE_BACKUP_TOC_INVALID", "backup table-of-contents is unreadable"
        ) from error
    if len(selected) != len(sequence_names):
        raise DomainError(
            "DATABASE_BACKUP_SEQUENCE_STATE_INVALID",
            "the archive does not contain one SEQUENCE SET entry per public sequence",
        )
    sequence_list = archive.with_suffix(".sequence.list")
    sequence_sql = archive.with_suffix(".sequence.sql")
    sequence_list.write_text("\n".join(selected) + "\n", encoding="utf-8")
    _run_postgresql_command(
        [
            "pg_restore",
            "--use-list",
            str(sequence_list),
            "--file",
            str(sequence_sql),
            str(archive),
        ],
        timeout=300,
        failure_code="DATABASE_BACKUP_SEQUENCE_STATE_INVALID",
        failure_detail="pg_restore could not extract archive sequence states",
    )
    try:
        if sequence_sql.stat().st_size > MAXIMUM_SEQUENCE_SQL_BYTES:
            raise DomainError(
                "DATABASE_BACKUP_SEQUENCE_STATE_INVALID",
                "archive sequence state exceeds its size limit",
            )
        lines = sequence_sql.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise DomainError(
            "DATABASE_BACKUP_SEQUENCE_STATE_INVALID",
            "archive sequence state is unreadable",
        ) from error
    by_regclass = {_qualified_regclass(name): name for name in sequence_names}
    observed: dict[str, dict[str, object]] = {}
    for line in lines:
        stripped = line.strip()
        match = SEQUENCE_SET.fullmatch(stripped)
        if match is None:
            if "pg_catalog.setval" in stripped:
                raise DomainError(
                    "DATABASE_BACKUP_SEQUENCE_STATE_INVALID",
                    "archive contains an unsupported sequence state statement",
                )
            continue
        regclass = match.group("regclass").replace("''", "'")
        name = by_regclass.get(regclass)
        if name is None or name in observed:
            raise DomainError(
                "DATABASE_BACKUP_SEQUENCE_STATE_INVALID",
                "archive sequence state does not match the exported snapshot schema",
            )
        observed[name] = {
            "sequence_name": name,
            "last_value": match.group("last_value"),
            "is_called": match.group("is_called") == "true",
        }
    if set(observed) != set(sequence_names):
        raise DomainError(
            "DATABASE_BACKUP_SEQUENCE_STATE_INVALID",
            "archive sequence state is incomplete",
        )
    return tuple(observed[name] for name in sequence_names)


def _finalize_snapshot_fingerprint(
    fingerprint: Mapping[str, object],
    *,
    archive_sequence_states: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    catalog = fingerprint.get("catalog")
    if not isinstance(catalog, Mapping):
        raise DomainError("DATABASE_BACKUP_SNAPSHOT_INVALID", "catalog fingerprint is invalid")
    value = {
        **fingerprint,
        "catalog": _catalog_with_archive_sequence_states(catalog, archive_sequence_states),
    }
    value["snapshot_digest"] = canonical_digest(value)
    return value


def _object_descriptor(reference: ObjectRef) -> dict[str, object]:
    key = str(reference.key)
    size = int(reference.size)
    sha256 = str(reference.sha256)
    version_id = reference.version_id
    encryption = reference.encryption
    return {
        "key": key,
        "size": size,
        "sha256": sha256,
        "version_id": version_id,
        "encryption": encryption,
    }


def _require_exact_version_retention(
    storage: ObjectStorage,
    reference: ObjectRef,
    *,
    field: str,
) -> ObjectRetention:
    """Prove that one exact uploaded version has active S3 Object Lock retention."""

    version_id = reference.version_id
    if not isinstance(version_id, str) or not version_id.strip():
        raise DomainError(
            "DATABASE_BACKUP_RETENTION_INVALID",
            f"{field} has no exact object version for Object Lock verification",
            status=503,
        )
    try:
        retention = storage.get_version_retention(reference.key, version_id=version_id)
    except (AttributeError, DomainError) as error:
        raise DomainError(
            "DATABASE_BACKUP_RETENTION_INVALID",
            f"{field} exact version has no verifiable Object Lock retention",
            status=503,
        ) from error
    if not isinstance(retention, ObjectRetention) or not retention.active():
        raise DomainError(
            "DATABASE_BACKUP_RETENTION_INVALID",
            f"{field} exact version is not protected by active Object Lock retention",
            status=503,
        )
    return retention


def _kms_coordinates(kms_key_id: str, *, production: bool) -> AwsResourceArn | None:
    if not kms_key_id:
        if production:
            raise DomainError(
                "PRODUCTION_KMS_KEY_REQUIRED",
                "production backups require an exact KMS key ARN",
                status=503,
            )
        return None
    try:
        coordinates = parse_kms_key_arn(kms_key_id, code="PRODUCTION_KMS_KEY_REQUIRED")
    except DomainError:
        if production:
            raise
        raise DomainError(
            "BACKUP_KMS_KEY_INVALID", "backup encryption requires an exact KMS key ARN"
        ) from None
    expected_region = os.environ.get("SHADOW_OBJECT_STORAGE_REGION", "").strip()
    expected_account = os.environ.get("SHADOW_AWS_ACCOUNT_ID", "").strip()
    if (expected_region and coordinates.region != expected_region) or (
        expected_account and coordinates.account_id != expected_account
    ):
        raise DomainError(
            "BACKUP_KMS_COORDINATES_INVALID",
            "backup KMS key does not match the configured AWS region and account",
            status=503,
        )
    return coordinates


def create_backup(
    *,
    database_url_override: str | None = None,
    kms_key_id_override: str | None = None,
    storage_override: ObjectStorage | None = None,
) -> dict[str, object]:
    """Create one backup, allowing injected storage only for disposable local smoke."""
    production = os.environ.get("SHADOW_ENVIRONMENT", "").lower() == "production"
    if production and any(
        value is not None
        for value in (database_url_override, kms_key_id_override, storage_override)
    ):
        raise DomainError(
            "PRODUCTION_BACKUP_OVERRIDE_FORBIDDEN",
            "production backups cannot override runtime database, KMS, or storage bindings",
            status=503,
        )
    database_url = (
        database_url_override
        if database_url_override is not None
        else os.environ.get("SHADOW_DATABASE_URL", "")
    )
    kms_key_id = (
        kms_key_id_override
        if kms_key_id_override is not None
        else os.environ.get("SHADOW_OBJECT_STORAGE_KMS_KEY_ID", "")
    )
    kms_coordinates = _kms_coordinates(kms_key_id, production=production)
    expected_backup_role = os.environ.get("SHADOW_DATABASE_BACKUP_ROLE", "").strip()
    if production and not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", expected_backup_role):
        raise DomainError(
            "PRODUCTION_DATABASE_BACKUP_ROLE_REQUIRED",
            "production backups require the exact configured backup role",
            status=503,
        )
    if production and not os.environ.get("SHADOW_BACKUP_OBJECT_STORAGE_PREFIX", "").strip():
        raise DomainError(
            "PRODUCTION_BACKUP_PREFIX_REQUIRED",
            "production backups require a dedicated object-storage prefix",
            status=503,
        )
    pg_environment = postgres_environment(database_url)
    storage = storage_override or create_object_storage(
        os.environ.get("SHADOW_OBJECT_STORAGE_BACKEND", "s3"),
        local_root=os.environ.get("SHADOW_OBJECT_STORAGE_ROOT", ".runtime/backups"),
        bucket=os.environ.get("SHADOW_OBJECT_STORAGE_BUCKET"),
        region=os.environ.get("SHADOW_OBJECT_STORAGE_REGION"),
        endpoint_url=os.environ.get("SHADOW_OBJECT_STORAGE_ENDPOINT"),
        prefix=os.environ.get("SHADOW_BACKUP_OBJECT_STORAGE_PREFIX", "industrial-shadow/backups"),
        kms_key_id=kms_key_id or None,
        kms_encryption_context={"application": "industrial-shadow", "purpose": "backup"},
    )
    with tempfile.TemporaryDirectory(prefix="shadow-backup-") as temporary:
        directory = Path(temporary)
        path = directory / "database.dump"
        toc_path = directory / "database.toc"
        with PostgreSqlBackupSnapshot(database_url) as snapshot:
            fingerprint, sequence_names = _capture_snapshot_fingerprint(
                snapshot,
                expected_backup_role=expected_backup_role
                or str(snapshot.query("SELECT current_user AS role")[0]["role"]),
            )
            _run_postgresql_command(
                [
                    "pg_dump",
                    "--format=custom",
                    "--no-owner",
                    "--no-acl",
                    "--snapshot",
                    snapshot.snapshot_id,
                    "--file",
                    str(path),
                ],
                timeout=3600,
                failure_code="DATABASE_BACKUP_FAILED",
                failure_detail="pg_dump failed",
                environment=pg_environment,
            )
            created_at = snapshot.created_at
        _run_postgresql_command(
            ["pg_restore", "--list", "--file", str(toc_path), str(path)],
            timeout=300,
            failure_code="DATABASE_BACKUP_INVALID",
            failure_detail="pg_restore could not read the backup",
        )
        archive_sequence_states = _archive_sequence_states(
            path,
            toc_path=toc_path,
            sequence_names=sequence_names,
        )
        snapshot_fingerprint = _finalize_snapshot_fingerprint(
            fingerprint,
            archive_sequence_states=archive_sequence_states,
        )
        digest, archive_size = sha256_file(path)
        date = created_at[:10]
        key = f"postgres/{date}/{digest}.dump"
        reference = storage.put_file(
            key, path, content_type="application/vnd.postgresql.custom-backup"
        )
        if reference.sha256 != digest or reference.size != archive_size:
            raise DomainError(
                "DATABASE_BACKUP_UPLOAD_INVALID",
                "uploaded backup does not match the local archive",
                status=503,
            )
        if production and (not reference.version_id or reference.encryption != "aws:kms"):
            raise DomainError(
                "DATABASE_BACKUP_STORAGE_INVALID",
                "production backups require a versioned KMS-encrypted object",
                status=503,
            )
        if production:
            _require_exact_version_retention(storage, reference, field="backup archive")
        archive_descriptor = _object_descriptor(reference)
        manifest = {
            "schema_version": 3,
            "created_at": created_at,
            "source_database_digest": database_coordinate_digest(database_url),
            "archive": archive_descriptor,
            "kms_key_id_digest": (
                canonical_digest({"kms_key_id": kms_key_id}) if kms_key_id else "not-required"
            ),
            "kms_key_partition": (
                kms_coordinates.partition if kms_coordinates is not None else "not-required"
            ),
            "format": "postgresql-custom",
            "verified_by": "pg_restore --list + exported snapshot fingerprints",
            "backup_snapshot": snapshot_fingerprint,
        }
        manifest["manifest_digest"] = canonical_digest(manifest)
        manifest_bytes = canonical_json(manifest).encode("utf-8")
        if len(manifest_bytes) > MAXIMUM_MANIFEST_BYTES:
            raise DomainError(
                "DATABASE_BACKUP_MANIFEST_TOO_LARGE",
                "backup manifest exceeds its bounded restore contract",
                status=503,
            )
        manifest_reference = storage.put_bytes(
            key + ".manifest.json",
            manifest_bytes,
            content_type="application/json",
        )
        if production and (
            not manifest_reference.version_id or manifest_reference.encryption != "aws:kms"
        ):
            raise DomainError(
                "DATABASE_BACKUP_MANIFEST_STORAGE_INVALID",
                "production backup manifests require a versioned KMS-encrypted object",
                status=503,
            )
        if production:
            _require_exact_version_retention(
                storage,
                manifest_reference,
                field="backup manifest",
            )
            manifest_readback = storage.get_version_bytes(
                manifest_reference.key,
                version_id=str(manifest_reference.version_id),
                maximum_bytes=1024 * 1024,
                expected_sha256=manifest_reference.sha256,
            )
            if manifest_readback != manifest_bytes:
                raise DomainError(
                    "DATABASE_BACKUP_MANIFEST_READBACK_INVALID",
                    "production backup manifest immutable readback failed",
                    status=503,
                )
        sealed_receipt = {
            "schema_version": 1,
            "created_at": created_at,
            "source_database_digest": manifest["source_database_digest"],
            "archive": archive_descriptor,
            "manifest": _object_descriptor(manifest_reference),
            "manifest_digest": manifest["manifest_digest"],
            "backup_snapshot_digest": snapshot_fingerprint["snapshot_digest"],
            "kms_key_partition": manifest["kms_key_partition"],
        }
        sealed_receipt["sealed_receipt_digest"] = canonical_digest(sealed_receipt)
        sealed_receipt_bytes = canonical_json(sealed_receipt).encode("utf-8")
        receipt_reference = storage.put_bytes(
            key + ".receipt.json",
            sealed_receipt_bytes,
            content_type="application/json",
        )
        if production and (
            not receipt_reference.version_id or receipt_reference.encryption != "aws:kms"
        ):
            raise DomainError(
                "DATABASE_BACKUP_RECEIPT_STORAGE_INVALID",
                "production backup receipts require a versioned KMS-encrypted object",
                status=503,
            )
        if production:
            _require_exact_version_retention(
                storage,
                receipt_reference,
                field="sealed backup receipt",
            )
            receipt_readback = storage.get_version_bytes(
                receipt_reference.key,
                version_id=str(receipt_reference.version_id),
                maximum_bytes=MAXIMUM_MANIFEST_BYTES,
                expected_sha256=receipt_reference.sha256,
            )
            if receipt_readback != sealed_receipt_bytes:
                raise DomainError(
                    "DATABASE_BACKUP_RECEIPT_READBACK_INVALID",
                    "production backup receipt immutable readback failed",
                    status=503,
                )
        receipt = {
            "schema_version": 2,
            "created_at": created_at,
            "source_database_digest": manifest["source_database_digest"],
            "archive": archive_descriptor,
            "manifest": _object_descriptor(manifest_reference),
            "manifest_digest": manifest["manifest_digest"],
            "backup_snapshot_digest": snapshot_fingerprint["snapshot_digest"],
            "kms_key_partition": manifest["kms_key_partition"],
            "sealed_receipt": _object_descriptor(receipt_reference),
            "sealed_receipt_digest": sealed_receipt["sealed_receipt_digest"],
        }
        receipt["receipt_digest"] = canonical_digest(receipt)
        return receipt


def main() -> int:
    print(canonical_json(create_backup()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
