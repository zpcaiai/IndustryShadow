from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.parse import urlsplit

from shadow_sandbox.common.models import DomainError, utc_now
from shadow_sandbox.common.sqlalchemy_store import SqlAlchemyStore
from shadow_sandbox.common.tenant_scope import workspace_scope

from .backup_job import postgres_environment
from .database_roles import DatabaseRoleConfigurator
from .evidence import GateCheck, GateEvidence, complete


def _database_name(url: str) -> str:
    return urlsplit(url.replace("postgresql+psycopg://", "postgresql://", 1)).path.strip("/")


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
    """Dump a managed source and restore into an explicitly disposable empty database."""

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
    ) -> None:
        source_name = _database_name(source_url)
        target_name = _database_name(target_url)
        if not source_name or not target_name or source_url == target_url:
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
        self.application_target_url = application_target_url
        self.backup_target_url = backup_target_url
        self.tenant_roles = tuple(tenant_roles)
        self.maintenance_role = maintenance_role
        self.backup_role = backup_role
        self.maximum_restore_seconds = maximum_restore_seconds
        self.maximum_archive_bytes = maximum_archive_bytes
        self.managed_provider = managed_provider
        self.managed_instance_digest = managed_instance_digest
        if maximum_restore_seconds < 1 or maximum_archive_bytes < 1:
            raise DomainError("RESTORE_THRESHOLD_INVALID", "restore thresholds must be positive")
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
        if bool(application_target_url and backup_target_url) != bool(
            tenant_roles and maintenance_role and backup_role
        ):
            raise DomainError(
                "RESTORE_ROLE_CONFIG_INVALID",
                "application URL and all runtime role names must be supplied together",
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

    def run(self) -> GateEvidence:
        started = utc_now()
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
                archive = Path(directory) / "source.dump"
                dump_started = time.monotonic()
                self._run(
                    [
                        "pg_dump",
                        "--format=custom",
                        "--no-owner",
                        "--no-acl",
                        "--file",
                        str(archive),
                    ],
                    postgres_environment(self.source_url),
                    3600,
                )
                dump_seconds = time.monotonic() - dump_started
                restore_started = time.monotonic()
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
                restore_seconds = time.monotonic() - restore_started
                archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                archive_bytes = archive.stat().st_size

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
                GateCheck("archive_created", bool(archive_digest)),
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
                    "restore_rto",
                    restore_seconds <= self.maximum_restore_seconds,
                    {"maximum_seconds": self.maximum_restore_seconds},
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
            checks = tuple(checks_list)
            return complete(
                "backup_restore",
                started_at=started,
                coordinates={
                    "source_database_digest": hashlib.sha256(self.source_name.encode()).hexdigest(),
                    "target_database_digest": hashlib.sha256(self.target_name.encode()).hexdigest(),
                    "archive_digest": archive_digest,
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
                    "dump_seconds": round(dump_seconds, 3),
                    "restore_seconds": round(restore_seconds, 3),
                },
            )
        finally:
            source.close()
            target.close()
