from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now
from shadow_sandbox.common.sqlalchemy_store import SqlAlchemyStore

from .evidence import GateCheck, GateEvidence, complete

DIGEST = re.compile(r"^[a-f0-9]{64}$")
REVISION = re.compile(r"^[a-f0-9]{40}$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "source_revision",
        "source_digest",
        "prior_head",
        "candidate_head",
        "protected_tables",
        "manifest_digest",
    }
)


class MigrationStore(Protocol):
    def query(self, sql: str, parameters: Sequence[Any] = ()) -> list[dict[str, Any]]: ...

    def migrate_all(self, directory: str | Path) -> int: ...

    def close(self) -> None: ...


StoreFactory = Callable[[str], MigrationStore]


def _canonical_database_coordinate(database_url: str) -> Mapping[str, Any]:
    normalized = database_url.replace("postgresql+psycopg://", "postgresql://", 1)
    parsed = urlsplit(normalized)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    database = parsed.path.lstrip("/")
    if (
        parsed.scheme != "postgresql"
        or not parsed.hostname
        or not database
        or "migration_drill" not in database
        or query.get("sslmode") != "verify-full"
    ):
        raise DomainError(
            "POSTGRESQL_MIGRATION_TARGET_INVALID",
            "migration drill databases must be disposable PostgreSQL targets using sslmode=verify-full",
        )
    safe_netloc = parsed.hostname.lower()
    if parsed.port is not None:
        safe_netloc += f":{parsed.port}"
    safe_query = urlencode(
        sorted((key, value) for key, value in query.items() if key != "password")
    )
    return {
        "server": safe_netloc,
        "database": database,
        "username": parsed.username or "",
        "tls_query": safe_query,
        "coordinate": urlunsplit(("postgresql", safe_netloc, "/" + database, safe_query, "")),
    }


@dataclass(frozen=True, slots=True)
class MigrationCompatibilityManifest:
    path: Path
    source_revision: str
    source_digest: str
    prior_head: int
    candidate_head: int
    protected_tables: tuple[str, ...]
    digest: str

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        expected_source_revision: str,
        expected_source_digest: str,
    ) -> MigrationCompatibilityManifest:
        candidate = Path(path)
        if candidate.is_symlink():
            raise DomainError(
                "POSTGRESQL_MIGRATION_MANIFEST_INVALID", "migration manifest is a symlink"
            )
        resolved = candidate.resolve(strict=True)
        try:
            value = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise DomainError(
                "POSTGRESQL_MIGRATION_MANIFEST_INVALID", "migration manifest is invalid"
            ) from error
        if not isinstance(value, Mapping) or set(value) != MANIFEST_KEYS:
            raise DomainError(
                "POSTGRESQL_MIGRATION_MANIFEST_INVALID", "migration manifest fields are invalid"
            )
        protected = value.get("protected_tables")
        prior = value.get("prior_head")
        candidate_head = value.get("candidate_head")
        claimed = str(value.get("manifest_digest", ""))
        if (
            value.get("schema_version") != 1
            or not REVISION.fullmatch(str(value.get("source_revision", "")))
            or not DIGEST.fullmatch(str(value.get("source_digest", "")))
            or value.get("source_revision") != expected_source_revision
            or value.get("source_digest") != expected_source_digest
            or isinstance(prior, bool)
            or not isinstance(prior, int)
            or isinstance(candidate_head, bool)
            or not isinstance(candidate_head, int)
            or prior < 1
            or candidate_head != prior + 1
            or not isinstance(protected, list)
            or not protected
            or len(protected) != len(set(protected))
            or any(
                not isinstance(item, str) or not IDENTIFIER.fullmatch(item) for item in protected
            )
            or claimed != canonical_digest({**value, "manifest_digest": ""})
        ):
            raise DomainError(
                "POSTGRESQL_MIGRATION_MANIFEST_INVALID", "migration manifest values are invalid"
            )
        return cls(
            resolved,
            str(value["source_revision"]),
            str(value["source_digest"]),
            prior,
            candidate_head,
            tuple(str(item) for item in protected),
            claimed,
        )


def _history(store: MigrationStore) -> list[int]:
    return [
        int(item["version"])
        for item in store.query("SELECT version FROM schema_migrations ORDER BY version")
    ]


def _identity(store: MigrationStore) -> Mapping[str, str]:
    rows = store.query(
        "SELECT current_database() AS database, current_user AS username, "
        "COALESCE(inet_server_addr()::text, '') AS server_address, "
        "inet_server_port()::text AS server_port"
    )
    if len(rows) != 1:
        raise DomainError("POSTGRESQL_MIGRATION_TARGET_INVALID", "database identity is unavailable")
    return {key: str(value or "") for key, value in rows[0].items()}


def _public_tables(store: MigrationStore) -> tuple[str, ...]:
    return tuple(
        str(item["tablename"])
        for item in store.query(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
        )
    )


def _protected_snapshot(
    store: MigrationStore, tables: Sequence[str], *, maximum_rows: int
) -> Mapping[str, Mapping[str, Any]]:
    snapshot: dict[str, Mapping[str, Any]] = {}
    observed_rows = 0
    for table in tables:
        if table not in _public_tables(store):
            raise DomainError(
                "POSTGRESQL_MIGRATION_DATA_INVALID", f"protected table is missing: {table}"
            )
        rows = store.query(
            f'SELECT to_jsonb(value)::text AS payload FROM public."{table}" AS value '
            "ORDER BY to_jsonb(value)::text"
        )
        observed_rows += len(rows)
        if observed_rows > maximum_rows:
            raise DomainError(
                "POSTGRESQL_MIGRATION_DATA_INVALID", "protected migration dataset is too large"
            )
        digest = hashlib.sha256()
        for row in rows:
            digest.update(str(row["payload"]).encode("utf-8"))
            digest.update(b"\n")
        snapshot[table] = {"rows": len(rows), "sha256": digest.hexdigest()}
    if observed_rows == 0:
        raise DomainError(
            "POSTGRESQL_MIGRATION_DATA_INVALID",
            "upgrade drill requires seeded protected rows to avoid a vacuous data check",
        )
    return snapshot


CATALOG_QUERIES = (
    (
        "SELECT table_name,column_name,ordinal_position,data_type,is_nullable,column_default "
        "FROM information_schema.columns WHERE table_schema='public' "
        "ORDER BY table_name,ordinal_position"
    ),
    (
        "SELECT conrelid::regclass::text AS table_name,conname,contype,"
        "pg_get_constraintdef(oid) AS definition FROM pg_constraint "
        "WHERE connamespace='public'::regnamespace ORDER BY 1,2"
    ),
    (
        "SELECT schemaname,tablename,indexname,indexdef FROM pg_indexes "
        "WHERE schemaname='public' ORDER BY tablename,indexname"
    ),
    (
        "SELECT schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check "
        "FROM pg_policies WHERE schemaname='public' ORDER BY tablename,policyname"
    ),
    (
        "SELECT event_object_table,trigger_name,event_manipulation,action_statement "
        "FROM information_schema.triggers WHERE trigger_schema='public' "
        "ORDER BY event_object_table,trigger_name,event_manipulation"
    ),
    (
        "SELECT sequence_name,data_type,start_value,minimum_value,maximum_value,increment,"
        "cycle_option FROM information_schema.sequences WHERE sequence_schema='public' "
        "ORDER BY sequence_name"
    ),
)


def _catalog_digest(store: MigrationStore) -> str:
    return canonical_digest([store.query(query) for query in CATALOG_QUERIES])


class PostgreSqlMigrationProbe:
    """Exercise fresh and N-1 PostgreSQL migration paths on bound disposable databases."""

    def __init__(
        self,
        fresh_database_url: str,
        upgrade_database_url: str,
        *,
        migration_directory: str | Path,
        compatibility_manifest: MigrationCompatibilityManifest,
        confirmation: str,
        maximum_seconds: int = 900,
        maximum_protected_rows: int = 100_000,
        store_factory: StoreFactory = SqlAlchemyStore,
    ) -> None:
        self.fresh_coordinate = _canonical_database_coordinate(fresh_database_url)
        self.upgrade_coordinate = _canonical_database_coordinate(upgrade_database_url)
        if self.fresh_coordinate["coordinate"] == self.upgrade_coordinate["coordinate"]:
            raise DomainError(
                "POSTGRESQL_MIGRATION_TARGET_INVALID", "fresh and upgrade databases must differ"
            )
        expected_confirmation = canonical_digest(
            {
                "operation": "postgresql-migration-drill",
                "fresh": self.fresh_coordinate["coordinate"],
                "upgrade": self.upgrade_coordinate["coordinate"],
                "manifest_digest": compatibility_manifest.digest,
            }
        )
        if confirmation != expected_confirmation:
            raise DomainError(
                "POSTGRESQL_MIGRATION_CONFIRMATION_INVALID",
                "migration confirmation is not bound to both disposable targets and the manifest",
            )
        if not 1 <= maximum_seconds <= 7200 or not 1 <= maximum_protected_rows <= 1_000_000:
            raise DomainError("POSTGRESQL_MIGRATION_LIMIT_INVALID", "migration limits are invalid")
        if (
            self.fresh_coordinate["server"] != self.upgrade_coordinate["server"]
            or self.fresh_coordinate["username"] != self.upgrade_coordinate["username"]
        ):
            raise DomainError(
                "POSTGRESQL_MIGRATION_TARGET_INVALID",
                "fresh and upgrade databases must use one managed server and migration role",
            )
        directory = Path(migration_directory).resolve(strict=True)
        paths = sorted((directory / "postgresql").glob("[0-9][0-9][0-9][0-9]_*.sql"))
        versions = [int(path.name.split("_", 1)[0]) for path in paths]
        if versions != list(range(1, compatibility_manifest.candidate_head + 1)):
            raise DomainError(
                "POSTGRESQL_MIGRATION_MANIFEST_INVALID",
                "packaged migration history does not match the compatibility manifest",
            )
        self.fresh_database_url = fresh_database_url
        self.upgrade_database_url = upgrade_database_url
        self.migration_directory = directory
        self.manifest = compatibility_manifest
        self.maximum_seconds = maximum_seconds
        self.maximum_protected_rows = maximum_protected_rows
        self.store_factory = store_factory

    def run(self) -> GateEvidence:
        started_at = utc_now()
        clock = time.monotonic()
        fresh = self.store_factory(self.fresh_database_url)
        upgrade = self.store_factory(self.upgrade_database_url)
        try:
            fresh_identity = _identity(fresh)
            upgrade_identity = _identity(upgrade)
            if (
                fresh_identity.get("database") != self.fresh_coordinate["database"]
                or upgrade_identity.get("database") != self.upgrade_coordinate["database"]
                or (
                    self.fresh_coordinate["username"]
                    and fresh_identity.get("username") != self.fresh_coordinate["username"]
                )
                or (
                    self.upgrade_coordinate["username"]
                    and upgrade_identity.get("username") != self.upgrade_coordinate["username"]
                )
            ):
                raise DomainError(
                    "POSTGRESQL_MIGRATION_TARGET_INVALID",
                    "database runtime identity does not match the confirmed target",
                )
            fresh_empty = not _public_tables(fresh)
            if not fresh_empty:
                raise DomainError(
                    "POSTGRESQL_MIGRATION_FRESH_NOT_EMPTY",
                    "fresh migration database must contain no public tables",
                )
            upgrade_history_before = _history(upgrade)
            if upgrade_history_before != list(range(1, self.manifest.prior_head + 1)):
                raise DomainError(
                    "POSTGRESQL_MIGRATION_PRIOR_HEAD_INVALID",
                    "upgrade database is not at the exact N-1 migration head",
                )
            protected_before = _protected_snapshot(
                upgrade,
                self.manifest.protected_tables,
                maximum_rows=self.maximum_protected_rows,
            )
            fresh_head = fresh.migrate_all(self.migration_directory)
            upgrade_head = upgrade.migrate_all(self.migration_directory)
            first_pass_seconds = time.monotonic() - clock
            fresh_second = fresh.migrate_all(self.migration_directory)
            upgrade_second = upgrade.migrate_all(self.migration_directory)
            protected_after = _protected_snapshot(
                upgrade,
                self.manifest.protected_tables,
                maximum_rows=self.maximum_protected_rows,
            )
            fresh_history = _history(fresh)
            upgrade_history = _history(upgrade)
            fresh_catalog = _catalog_digest(fresh)
            upgrade_catalog = _catalog_digest(upgrade)
            elapsed = time.monotonic() - clock
            expected_history = list(range(1, self.manifest.candidate_head + 1))
            checks = (
                GateCheck("fresh_database_was_empty", fresh_empty),
                GateCheck("upgrade_started_at_exact_n_minus_one", True),
                GateCheck(
                    "fresh_path_reached_candidate_head",
                    fresh_head == self.manifest.candidate_head
                    and fresh_history == expected_history,
                ),
                GateCheck(
                    "upgrade_path_reached_candidate_head",
                    upgrade_head == self.manifest.candidate_head
                    and upgrade_history == expected_history,
                ),
                GateCheck(
                    "migration_execution_idempotent",
                    fresh_second == fresh_head and upgrade_second == upgrade_head,
                ),
                GateCheck("protected_data_preserved", protected_before == protected_after),
                GateCheck("fresh_and_upgrade_catalogs_equal", fresh_catalog == upgrade_catalog),
                GateCheck("migration_rto", elapsed <= self.maximum_seconds),
            )
            return complete(
                "postgresql_migration",
                started_at=started_at,
                coordinates={
                    "source_revision": self.manifest.source_revision,
                    "source_digest": self.manifest.source_digest,
                    "compatibility_manifest_digest": self.manifest.digest,
                    "fresh_target_digest": canonical_digest(self.fresh_coordinate),
                    "upgrade_target_digest": canonical_digest(self.upgrade_coordinate),
                    "fresh_server_identity_digest": canonical_digest(fresh_identity),
                    "upgrade_server_identity_digest": canonical_digest(upgrade_identity),
                },
                checks=checks,
                metrics={
                    "compatibility_manifest_digest": self.manifest.digest,
                    "prior_head": self.manifest.prior_head,
                    "candidate_head": self.manifest.candidate_head,
                    "protected_tables": len(self.manifest.protected_tables),
                    "protected_rows": sum(int(item["rows"]) for item in protected_after.values()),
                    "first_pass_seconds": round(first_pass_seconds, 3),
                    "end_to_end_seconds": round(elapsed, 3),
                },
            )
        finally:
            upgrade.close()
            fresh.close()
