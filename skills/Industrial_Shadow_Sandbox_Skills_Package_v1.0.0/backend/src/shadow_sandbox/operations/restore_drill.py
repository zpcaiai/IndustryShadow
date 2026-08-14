from __future__ import annotations

import datetime as dt
import json
import re
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from shadow_sandbox.common.models import (
    DomainError,
    canonical_digest,
    canonical_json,
    utc_now,
)
from shadow_sandbox.common.object_storage import ObjectRef, ObjectStorage
from shadow_sandbox.common.sqlalchemy_store import SqlAlchemyStore
from shadow_sandbox.common.tenant_scope import workspace_scope

from .backup_job import postgres_environment
from .database_roles import DatabaseRoleConfigurator
from .evidence import GateCheck, GateEvidence, complete

DIGEST = re.compile(r"^[a-f0-9]{64}$")
MAXIMUM_MANIFEST_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class BackupObjectVersion:
    key: str
    size: int
    sha256: str
    version_id: str
    encryption: str

    @classmethod
    def parse(cls, value: object, *, field: str) -> BackupObjectVersion:
        if not isinstance(value, Mapping) or set(value) != {
            "key",
            "size",
            "sha256",
            "version_id",
            "encryption",
        }:
            raise DomainError("BACKUP_RECEIPT_INVALID", f"{field} object descriptor is invalid")
        key = value.get("key")
        size = value.get("size")
        sha256 = value.get("sha256")
        version_id = value.get("version_id")
        encryption = value.get("encryption")
        if (
            not isinstance(key, str)
            or not key.startswith("postgres/")
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 1
            or not isinstance(sha256, str)
            or not DIGEST.fullmatch(sha256)
            or not isinstance(version_id, str)
            or not version_id.strip()
            or len(version_id) > 1024
            or encryption != "aws:kms"
        ):
            raise DomainError(
                "BACKUP_RECEIPT_INVALID",
                f"{field} must identify one versioned KMS-encrypted backup object",
            )
        return cls(key, size, sha256, version_id, encryption)

    def matches(self, reference: ObjectRef) -> bool:
        return (
            reference.key == self.key
            and reference.size == self.size
            and reference.sha256 == self.sha256
            and reference.version_id == self.version_id
            and reference.encryption == self.encryption
        )


@dataclass(frozen=True, slots=True)
class BackupRestoreReceipt:
    created_at: str
    source_database_digest: str
    archive: BackupObjectVersion
    manifest: BackupObjectVersion
    manifest_digest: str
    receipt_digest: str

    @classmethod
    def load(
        cls, path_value: str | Path, *, expected_source_database_digest: str
    ) -> BackupRestoreReceipt:
        path = Path(path_value)
        try:
            if (
                path.is_symlink()
                or not path.is_file()
                or path.stat().st_size > MAXIMUM_MANIFEST_BYTES
            ):
                raise DomainError(
                    "BACKUP_RECEIPT_INVALID", "backup receipt must be a bounded regular file"
                )
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise DomainError(
                "BACKUP_RECEIPT_INVALID", "backup receipt could not be read"
            ) from error
        if not isinstance(raw, Mapping) or set(raw) != {
            "schema_version",
            "created_at",
            "source_database_digest",
            "archive",
            "manifest",
            "manifest_digest",
            "receipt_digest",
        }:
            raise DomainError("BACKUP_RECEIPT_INVALID", "backup receipt fields are invalid")
        payload = {key: raw[key] for key in raw if key != "receipt_digest"}
        if raw.get("schema_version") != 1 or raw.get("receipt_digest") != canonical_digest(payload):
            raise DomainError("BACKUP_RECEIPT_INVALID", "backup receipt digest is invalid")
        created_at = raw.get("created_at")
        try:
            created = dt.datetime.fromisoformat(str(created_at))
        except ValueError as error:
            raise DomainError("BACKUP_RECEIPT_INVALID", "backup timestamp is invalid") from error
        if created.tzinfo is None or created.utcoffset() != dt.timedelta(0):
            raise DomainError("BACKUP_RECEIPT_INVALID", "backup timestamp must be UTC")
        source_digest = raw.get("source_database_digest")
        manifest_digest = raw.get("manifest_digest")
        receipt_digest = raw.get("receipt_digest")
        if (
            source_digest != expected_source_database_digest
            or not isinstance(manifest_digest, str)
            or not DIGEST.fullmatch(manifest_digest)
            or not isinstance(receipt_digest, str)
            or not DIGEST.fullmatch(receipt_digest)
        ):
            raise DomainError(
                "BACKUP_RECEIPT_INVALID", "backup receipt is not bound to the source database"
            )
        archive = BackupObjectVersion.parse(raw.get("archive"), field="archive")
        manifest = BackupObjectVersion.parse(raw.get("manifest"), field="manifest")
        if manifest.key != archive.key + ".manifest.json":
            raise DomainError(
                "BACKUP_RECEIPT_INVALID", "backup manifest key is not bound to its archive"
            )
        return cls(
            str(created_at),
            str(source_digest),
            archive,
            manifest,
            manifest_digest,
            receipt_digest,
        )

    def age_seconds(self) -> float:
        created = dt.datetime.fromisoformat(self.created_at)
        return (dt.datetime.now(dt.UTC) - created).total_seconds()


def _load_immutable_manifest(
    path: Path,
    *,
    receipt: BackupRestoreReceipt,
    expected_kms_key_digest: str,
) -> Mapping[str, object]:
    try:
        encoded = path.read_bytes()
        value = json.loads(encoded)
    except (OSError, json.JSONDecodeError, UnicodeError) as error:
        raise DomainError("BACKUP_MANIFEST_INVALID", "backup manifest is unreadable") from error
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "created_at",
        "source_database_digest",
        "archive",
        "kms_key_id_digest",
        "format",
        "verified_by",
        "manifest_digest",
    }:
        raise DomainError("BACKUP_MANIFEST_INVALID", "backup manifest fields are invalid")
    if canonical_json(value).encode("utf-8") != encoded:
        raise DomainError("BACKUP_MANIFEST_INVALID", "backup manifest is not canonical JSON")
    payload = {key: value[key] for key in value if key != "manifest_digest"}
    if (
        value.get("schema_version") != 2
        or value.get("manifest_digest") != canonical_digest(payload)
        or value.get("manifest_digest") != receipt.manifest_digest
        or value.get("created_at") != receipt.created_at
        or value.get("source_database_digest") != receipt.source_database_digest
        or value.get("archive")
        != {
            "key": receipt.archive.key,
            "size": receipt.archive.size,
            "sha256": receipt.archive.sha256,
            "version_id": receipt.archive.version_id,
            "encryption": receipt.archive.encryption,
        }
        or value.get("kms_key_id_digest") != expected_kms_key_digest
        or value.get("format") != "postgresql-custom"
        or value.get("verified_by") != "pg_restore --list"
    ):
        raise DomainError(
            "BACKUP_MANIFEST_INVALID", "backup manifest does not match the restore receipt"
        )
    return value


@dataclass(frozen=True, slots=True)
class _DatabaseCoordinate:
    host: str
    port: int
    database: str

    @property
    def digest(self) -> str:
        return canonical_digest({"host": self.host, "port": self.port, "database": self.database})


def _database_url_parts(url: str) -> tuple[_DatabaseCoordinate, str, Mapping[str, list[str]]]:
    try:
        parsed = urlsplit(url.replace("postgresql+psycopg://", "postgresql://", 1))
        port = parsed.port or 5432
    except ValueError as error:
        raise DomainError("DATABASE_URL_INVALID", "PostgreSQL URL is malformed") from error
    database = unquote(parsed.path.removeprefix("/"))
    if (
        parsed.scheme != "postgresql"
        or not parsed.hostname
        or not database
        or "/" in database
        or parsed.fragment
    ):
        raise DomainError("DATABASE_URL_INVALID", "PostgreSQL URL coordinate is invalid")
    query = parse_qs(parsed.query, keep_blank_values=True)
    coordinate = _DatabaseCoordinate(parsed.hostname.lower().rstrip("."), port, database)
    return coordinate, unquote(parsed.username or ""), query


def _verify_full(url: str) -> bool:
    _coordinate, _user, query = _database_url_parts(url)
    roots = query.get("sslrootcert", ())
    return (
        query.get("sslmode") == ["verify-full"]
        and len(roots) == 1
        and bool(unquote(roots[0]).strip())
    )


def _table_inventory(store: SqlAlchemyStore) -> dict[str, dict[str, int | str]]:
    tables = [
        str(row["tablename"])
        for row in store.query(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
        )
    ]
    inventory: dict[str, dict[str, int | str]] = {}
    for table in tables:
        quoted = '"' + table.replace('"', '""') + '"'
        row = store.query(
            f"""SELECT COUNT(*) AS count,
                       COALESCE(SUM((('x' || SUBSTR(MD5(TO_JSONB(item)::text), 1, 16))::bit(64)::bigint)::numeric), 0)::text AS digest_a,
                       COALESCE(SUM((('x' || SUBSTR(MD5(TO_JSONB(item)::text), 17, 16))::bit(64)::bigint)::numeric), 0)::text AS digest_b
                  FROM {quoted} AS item"""
        )[0]
        inventory[table] = {
            "count": int(row["count"]),
            "digest_a": str(row["digest_a"]),
            "digest_b": str(row["digest_b"]),
        }
    return inventory


def _rls_inventory(store: SqlAlchemyStore) -> dict[str, int | str]:
    row = store.query(
        """SELECT COUNT(*) AS count,
                  MD5(COALESCE(STRING_AGG(MD5(TO_JSONB(policy)::text), ''
                                          ORDER BY MD5(TO_JSONB(policy)::text)), '')) AS digest
             FROM pg_policies AS policy WHERE schemaname='public'"""
    )[0]
    return {"count": int(row["count"]), "digest": str(row["digest"])}


class PostgreSqlRestoreDrill:
    """Restore one immutable, version-bound backup into a disposable managed database."""

    def __init__(
        self,
        source_url: str,
        target_url: str,
        *,
        allow_restore: bool,
        application_target_url: str | None = None,
        backup_target_url: str | None = None,
        tenant_roles: Sequence[str] = (),
        maintenance_role: str | None = None,
        backup_role: str | None = None,
        maximum_restore_seconds: int = 1800,
        maximum_archive_bytes: int = 100 * 1024 * 1024 * 1024,
        managed_provider: str | None = None,
        managed_instance_digest: str | None = None,
        require_managed_coordinates: bool = False,
        object_storage: ObjectStorage | None = None,
        backup_receipt_path: str | Path | None = None,
        kms_key_id: str | None = None,
        maximum_rpo_seconds: int = 86400,
        require_immutable_backup: bool = False,
    ) -> None:
        source_coordinate, source_user, _source_query = _database_url_parts(source_url)
        target_coordinate, target_user, _target_query = _database_url_parts(target_url)
        source_name = source_coordinate.database
        target_name = target_coordinate.database
        if source_coordinate == target_coordinate:
            raise DomainError("RESTORE_TARGET_INVALID", "source and restore target must differ")
        if not re.fullmatch(r"[a-zA-Z0-9_]*restore_drill[a-zA-Z0-9_]*", target_name):
            raise DomainError(
                "RESTORE_TARGET_INVALID", "target database name must contain restore_drill"
            )
        if not allow_restore:
            raise DomainError(
                "RESTORE_CONFIRMATION_REQUIRED",
                "explicit destructive restore confirmation is required",
            )
        self.source_url = source_url
        self.target_url = target_url
        self.source_name = source_name
        self.target_name = target_name
        self.source_coordinate = source_coordinate
        self.target_coordinate = target_coordinate
        self.application_target_url = application_target_url
        self.backup_target_url = backup_target_url
        self.tenant_roles = tuple(tenant_roles)
        self.maintenance_role = maintenance_role
        self.backup_role = backup_role
        self.maximum_restore_seconds = maximum_restore_seconds
        self.maximum_archive_bytes = maximum_archive_bytes
        self.managed_provider = managed_provider
        self.managed_instance_digest = managed_instance_digest
        self.object_storage = object_storage
        self.backup_receipt_path = backup_receipt_path
        self.kms_key_id = kms_key_id
        self.maximum_rpo_seconds = maximum_rpo_seconds
        self.require_immutable_backup = require_immutable_backup
        if maximum_restore_seconds < 1 or maximum_archive_bytes < 1 or maximum_rpo_seconds < 1:
            raise DomainError("RESTORE_THRESHOLD_INVALID", "restore thresholds must be positive")
        if require_immutable_backup and (
            object_storage is None
            or backup_receipt_path is None
            or not kms_key_id
            or not kms_key_id.startswith("arn:aws:kms:")
        ):
            raise DomainError(
                "IMMUTABLE_BACKUP_REQUIRED",
                "production restore requires object storage, a backup receipt, and a KMS key ARN",
            )
        if require_managed_coordinates and (
            not managed_provider
            or managed_provider.lower() in {"local", "localhost", "self-managed"}
            or not managed_instance_digest
            or not re.fullmatch(r"[a-f0-9]{64}", managed_instance_digest)
        ):
            raise DomainError(
                "MANAGED_POSTGRESQL_COORDINATES_REQUIRED",
                "managed provider and instance digest are required",
            )
        role_configuration_supplied = any(
            (
                application_target_url,
                backup_target_url,
                tenant_roles,
                maintenance_role,
                backup_role,
            )
        )
        role_configuration_complete = bool(
            application_target_url
            and backup_target_url
            and tenant_roles
            and maintenance_role
            and backup_role
        )
        if (
            role_configuration_supplied or require_managed_coordinates
        ) and not role_configuration_complete:
            raise DomainError(
                "RESTORE_ROLE_CONFIG_INVALID",
                "application URL and all runtime role names must be supplied together",
            )
        if role_configuration_complete:
            application_coordinate, application_user, _application_query = _database_url_parts(
                str(application_target_url)
            )
            backup_coordinate, backup_user, _backup_query = _database_url_parts(
                str(backup_target_url)
            )
            if (
                application_coordinate != target_coordinate
                or backup_coordinate != target_coordinate
            ):
                raise DomainError(
                    "RESTORE_TARGET_BINDING_INVALID",
                    "application and backup checks must connect to the exact restore target",
                )
            runtime_roles = {*self.tenant_roles, str(maintenance_role), str(backup_role)}
            if (
                not target_user
                or target_user in runtime_roles
                or source_user != backup_role
                or application_user not in self.tenant_roles
                or backup_user != backup_role
            ):
                raise DomainError(
                    "RESTORE_ROLE_BINDING_INVALID",
                    "database URL users must match the migration, tenant, and backup role contract",
                )
        if require_managed_coordinates and not all(
            _verify_full(value)
            for value in (
                source_url,
                target_url,
                str(application_target_url or ""),
                str(backup_target_url or ""),
            )
        ):
            raise DomainError(
                "MANAGED_POSTGRESQL_TLS_REQUIRED",
                "managed restore connections require verify-full and an explicit CA root",
            )

    @staticmethod
    def _run(command: list[str], environment: dict[str, str], timeout: int) -> None:
        completed = subprocess.run(
            command,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode:
            raise DomainError(
                "RESTORE_COMMAND_FAILED",
                "PostgreSQL backup or restore command failed",
                {"command": command[0], "exit_code": completed.returncode},
                status=503,
            )

    def _fetch_immutable_backup(
        self,
        directory: Path,
        *,
        receipt: BackupRestoreReceipt,
        kms_key_digest: str,
    ) -> tuple[Path, ObjectRef, ObjectRef, float]:
        if self.object_storage is None:
            raise DomainError("IMMUTABLE_BACKUP_REQUIRED", "object storage is required")
        manifest_path = directory / "backup.manifest.json"
        fetch_started = time.monotonic()
        manifest_reference = self.object_storage.get_file(
            receipt.manifest.key,
            manifest_path,
            maximum_bytes=MAXIMUM_MANIFEST_BYTES,
            expected_sha256=receipt.manifest.sha256,
            version_id=receipt.manifest.version_id,
        )
        if not receipt.manifest.matches(manifest_reference):
            raise DomainError(
                "BACKUP_MANIFEST_INVALID",
                "object storage returned a different backup manifest version",
            )
        _load_immutable_manifest(
            manifest_path,
            receipt=receipt,
            expected_kms_key_digest=kms_key_digest,
        )
        archive = directory / "database.dump"
        archive_reference = self.object_storage.get_file(
            receipt.archive.key,
            archive,
            maximum_bytes=self.maximum_archive_bytes,
            expected_sha256=receipt.archive.sha256,
            version_id=receipt.archive.version_id,
        )
        if not receipt.archive.matches(archive_reference):
            raise DomainError(
                "BACKUP_ARCHIVE_INVALID",
                "object storage returned a different backup archive version",
            )
        return (
            archive,
            manifest_reference,
            archive_reference,
            time.monotonic() - fetch_started,
        )

    def run(self) -> GateEvidence:
        started = utc_now()
        restore_started = time.monotonic()
        if self.object_storage is None or self.backup_receipt_path is None or not self.kms_key_id:
            raise DomainError(
                "IMMUTABLE_BACKUP_REQUIRED",
                "restore drills require an immutable version-bound backup receipt",
            )
        receipt = BackupRestoreReceipt.load(
            self.backup_receipt_path,
            expected_source_database_digest=self.source_coordinate.digest,
        )
        backup_age_seconds = receipt.age_seconds()
        if backup_age_seconds < -300:
            raise DomainError("BACKUP_RECEIPT_INVALID", "backup timestamp is in the future")
        kms_key_digest = canonical_digest({"kms_key_id": self.kms_key_id})
        source = SqlAlchemyStore(self.source_url)
        target = SqlAlchemyStore(self.target_url)
        try:
            existing = target.query(
                "SELECT COUNT(*) AS count FROM pg_tables WHERE schemaname='public'"
            )[0]
            if int(existing["count"]):
                raise DomainError(
                    "RESTORE_TARGET_NOT_EMPTY",
                    "restore target must be an empty disposable database",
                )
            source_inventory = _table_inventory(source)
            source_policies = _rls_inventory(source)
            source_role_valid = True
            if self.backup_role:
                source_role = source.query(
                    """SELECT current_user AS role, roles.rolbypassrls AS bypass,
                              EXISTS (
                                SELECT 1 FROM pg_tables
                                WHERE schemaname='public' AND tableowner=current_user
                              ) AS owns_tables,
                              (SELECT COUNT(*) FROM pg_tables
                                WHERE schemaname='public'
                                  AND has_table_privilege(current_user,
                                      format('%I.%I', schemaname, tablename), 'INSERT'))
                                AS writable_tables
                         FROM pg_roles roles WHERE roles.rolname=current_user"""
                )[0]
                source_role_valid = (
                    source_role["role"] == self.backup_role
                    and bool(source_role["bypass"])
                    and not bool(source_role["owns_tables"])
                    and int(source_role["writable_tables"]) == 0
                )
            with tempfile.TemporaryDirectory(prefix="shadow-restore-drill-") as directory:
                directory_path = Path(directory)
                (
                    archive,
                    manifest_reference,
                    archive_reference,
                    object_fetch_seconds,
                ) = self._fetch_immutable_backup(
                    directory_path,
                    receipt=receipt,
                    kms_key_digest=kms_key_digest,
                )
                database_restore_started = time.monotonic()
                self._run(
                    ["pg_restore", "--list", str(archive)],
                    postgres_environment(self.target_url),
                    300,
                )
                self._run(
                    [
                        "pg_restore",
                        "--exit-on-error",
                        "--no-owner",
                        "--no-acl",
                        "--single-transaction",
                        "--dbname",
                        self.target_name,
                        str(archive),
                    ],
                    postgres_environment(self.target_url),
                    3600,
                )
                database_restore_seconds = time.monotonic() - database_restore_started
                archive_digest = archive_reference.sha256
                archive_bytes = archive_reference.size

            role_result: Mapping[str, object] = {}
            if self.application_target_url:
                role_result = DatabaseRoleConfigurator(
                    target,
                    tenant_roles=self.tenant_roles,
                    maintenance_role=str(self.maintenance_role),
                    backup_role=str(self.backup_role),
                ).configure()

            target_inventory = _table_inventory(target)
            target_policies = _rls_inventory(target)
            source_versions = tuple(
                int(item["version"])
                for item in source.query("SELECT version FROM schema_migrations ORDER BY version")
            )
            target_versions = tuple(
                int(item["version"])
                for item in target.query("SELECT version FROM schema_migrations ORDER BY version")
            )
            source_head = source_versions[-1] if source_versions else 0
            target_integrity = target.query(
                "SELECT NOT pg_is_in_recovery() AS writable, current_database() AS database"
            )[0]
            integrity = target.query(
                """SELECT
                       (SELECT COUNT(*) FROM pg_constraint WHERE NOT convalidated) AS invalid_constraints,
                       (SELECT COUNT(*) FROM pg_index WHERE NOT indisvalid) AS invalid_indexes"""
            )[0]
            checks_list = [
                GateCheck("immutable_backup_receipt", bool(receipt.receipt_digest)),
                GateCheck("manifest_version_bound", receipt.manifest.matches(manifest_reference)),
                GateCheck("archive_version_bound", receipt.archive.matches(archive_reference)),
                GateCheck(
                    "backup_rpo",
                    0 <= backup_age_seconds <= self.maximum_rpo_seconds,
                    {"maximum_seconds": self.maximum_rpo_seconds},
                ),
                GateCheck("source_backup_role", source_role_valid),
                GateCheck(
                    "migration_history",
                    source_versions == target_versions
                    and source_versions == tuple(range(1, source_head + 1)),
                ),
                GateCheck("table_inventory", set(source_inventory) == set(target_inventory)),
                GateCheck("row_content_fingerprints", source_inventory == target_inventory),
                GateCheck(
                    "rls_policies",
                    source_policies == target_policies and int(target_policies["count"]) > 0,
                ),
                GateCheck(
                    "restored_database_online",
                    bool(target_integrity["writable"])
                    and target_integrity["database"] == self.target_name,
                ),
                GateCheck(
                    "archive_size_bound",
                    0 < archive_bytes <= self.maximum_archive_bytes,
                    {"maximum_bytes": self.maximum_archive_bytes},
                ),
                GateCheck(
                    "catalog_integrity",
                    int(integrity["invalid_constraints"]) == 0
                    and int(integrity["invalid_indexes"]) == 0,
                ),
            ]
            if self.application_target_url:
                application = SqlAlchemyStore(self.application_target_url)
                try:
                    role = application.query(
                        """SELECT roles.rolbypassrls AS bypass,
                                  EXISTS (
                                    SELECT 1 FROM pg_tables
                                    WHERE schemaname='public' AND tableowner=current_user
                                  ) AS owns_tables
                             FROM pg_roles roles WHERE roles.rolname=current_user"""
                    )[0]
                    workspaces = target.query(
                        """SELECT workspace_id, COUNT(*) AS count FROM domain_resources
                             GROUP BY workspace_id ORDER BY workspace_id LIMIT 1"""
                    )
                    unscoped = application.query("SELECT COUNT(*) AS count FROM domain_resources")
                    scoped_count = 0
                    if workspaces:
                        with workspace_scope(str(workspaces[0]["workspace_id"])):
                            scoped_count = int(
                                application.query("SELECT COUNT(*) AS count FROM domain_resources")[
                                    0
                                ]["count"]
                            )
                    checks_list.extend(
                        (
                            GateCheck(
                                "runtime_role_least_privilege",
                                not bool(role["bypass"]) and not bool(role["owns_tables"]),
                            ),
                            GateCheck(
                                "restored_rls_unscoped_denial",
                                bool(workspaces) and int(unscoped[0]["count"]) == 0,
                            ),
                            GateCheck("restored_rls_workspace_visibility", scoped_count > 0),
                            GateCheck("runtime_grants_reapplied", bool(role_result)),
                        )
                    )
                finally:
                    application.close()
                backup = SqlAlchemyStore(str(self.backup_target_url))
                try:
                    backup_state = backup.query(
                        """SELECT current_user AS role, roles.rolbypassrls AS bypass,
                                  EXISTS (
                                    SELECT 1 FROM pg_tables
                                    WHERE schemaname='public' AND tableowner=current_user
                                  ) AS owns_tables,
                                  (SELECT COUNT(*) FROM pg_tables
                                    WHERE schemaname='public'
                                      AND has_table_privilege(current_user,
                                          format('%I.%I', schemaname, tablename), 'INSERT'))
                                    AS writable_tables
                             FROM pg_roles roles WHERE roles.rolname=current_user"""
                    )[0]
                    backup_rows = int(
                        backup.query("SELECT COUNT(*) AS count FROM domain_resources")[0]["count"]
                    )
                    expected_rows = int(
                        target.query("SELECT COUNT(*) AS count FROM domain_resources")[0]["count"]
                    )
                    checks_list.extend(
                        (
                            GateCheck(
                                "backup_role_identity",
                                backup_state["role"] == self.backup_role
                                and bool(backup_state["bypass"])
                                and not bool(backup_state["owns_tables"]),
                            ),
                            GateCheck(
                                "backup_role_read_only",
                                int(backup_state["writable_tables"]) == 0,
                            ),
                            GateCheck(
                                "backup_role_complete_visibility",
                                backup_rows == expected_rows,
                            ),
                        )
                    )
                finally:
                    backup.close()
            restore_seconds = time.monotonic() - restore_started
            checks_list.append(
                GateCheck(
                    "restore_rto",
                    restore_seconds <= self.maximum_restore_seconds,
                    {"maximum_seconds": self.maximum_restore_seconds},
                )
            )
            checks = tuple(checks_list)
            return complete(
                "backup_restore",
                started_at=started,
                coordinates={
                    "source_database_digest": self.source_coordinate.digest,
                    "target_database_digest": self.target_coordinate.digest,
                    "archive_digest": archive_digest,
                    "archive_version_digest": canonical_digest(
                        {"version_id": receipt.archive.version_id}
                    ),
                    "backup_manifest_digest": receipt.manifest_digest,
                    "backup_receipt_digest": receipt.receipt_digest,
                    "kms_key_id_digest": kms_key_digest,
                    "managed_provider": self.managed_provider or "not-required",
                    "managed_instance_digest": self.managed_instance_digest or "not-required",
                },
                checks=checks,
                metrics={
                    "tables": len(target_inventory),
                    "rows": sum(int(item["count"]) for item in target_inventory.values()),
                    "migration_head": source_head,
                    "rls_policies": int(target_policies["count"]),
                    "archive_bytes": archive_bytes,
                    "backup_age_seconds": round(max(0.0, backup_age_seconds), 3),
                    "object_fetch_seconds": round(object_fetch_seconds, 3),
                    "database_restore_seconds": round(database_restore_seconds, 3),
                    "restore_seconds": round(restore_seconds, 3),
                },
            )
        finally:
            source.close()
            target.close()
