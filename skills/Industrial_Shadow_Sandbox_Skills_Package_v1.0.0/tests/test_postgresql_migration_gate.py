from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from shadow_sandbox.common.models import DomainError, canonical_digest
from shadow_sandbox.operations.postgresql_migration import (
    MigrationCompatibilityManifest,
    PostgreSqlMigrationProbe,
)

ROOT = Path(__file__).resolve().parents[1]


class FakeMigrationStore:
    def __init__(self, database: str, head: int, seeded: bool) -> None:
        self.database = database
        self.head = head
        self.seeded = seeded
        self.closed = False

    def close(self) -> None:
        self.closed = True

    def migrate_all(self, _directory: str | Path) -> int:
        self.head = 3
        return self.head

    def query(self, sql: str, _parameters: object = ()) -> list[dict[str, object]]:
        if "current_database()" in sql:
            return [
                {
                    "database": self.database,
                    "username": "shadow_migration",
                    "server_address": "10.0.0.8",
                    "server_port": "5432",
                }
            ]
        if "FROM schema_migrations" in sql:
            return [{"version": version} for version in range(1, self.head + 1)]
        if "FROM pg_tables" in sql:
            if self.head == 0:
                return []
            return [{"tablename": name} for name in ("artifacts", "runs")]
        if "to_jsonb(value)" in sql:
            return [{"payload": '{"id":"seed"}'}] if self.seeded else []
        return []


def manifest(path: Path) -> MigrationCompatibilityManifest:
    value = {
        "schema_version": 1,
        "source_revision": "a" * 40,
        "source_digest": "b" * 64,
        "prior_head": 2,
        "candidate_head": 3,
        "protected_tables": ["artifacts", "runs"],
        "manifest_digest": "",
    }
    value["manifest_digest"] = canonical_digest(value)
    path.write_text(json.dumps(value), encoding="utf-8")
    return MigrationCompatibilityManifest.load(
        path,
        expected_source_revision="a" * 40,
        expected_source_digest="b" * 64,
    )


def url(database: str, host: str = "managed.db.internal") -> str:
    return (
        f"postgresql://shadow_migration@{host}/{database}"
        "?sslmode=verify-full&sslrootcert=%2Fapproved%2Fca.pem"
    )


def test_migration_probe_runs_fresh_n_minus_one_idempotency_and_data_checks() -> None:
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        contract = manifest(Path(directory) / "migration.json")
        fresh_url = url("shadow_fresh_migration_drill")
        upgrade_url = url("shadow_upgrade_migration_drill")
        confirmation = canonical_digest(
            {
                "operation": "postgresql-migration-drill",
                "fresh": {
                    "server": "managed.db.internal",
                    "database": "shadow_fresh_migration_drill",
                    "username": "shadow_migration",
                    "tls_query": "sslmode=verify-full&sslrootcert=%2Fapproved%2Fca.pem",
                    "coordinate": (
                        "postgresql://managed.db.internal/shadow_fresh_migration_drill?"
                        "sslmode=verify-full&sslrootcert=%2Fapproved%2Fca.pem"
                    ),
                }["coordinate"],
                "upgrade": {
                    "coordinate": (
                        "postgresql://managed.db.internal/shadow_upgrade_migration_drill?"
                        "sslmode=verify-full&sslrootcert=%2Fapproved%2Fca.pem"
                    )
                }["coordinate"],
                "manifest_digest": contract.digest,
            }
        )
        stores = {
            fresh_url: FakeMigrationStore("shadow_fresh_migration_drill", 0, False),
            upgrade_url: FakeMigrationStore("shadow_upgrade_migration_drill", 2, True),
        }
        result = PostgreSqlMigrationProbe(
            fresh_url,
            upgrade_url,
            migration_directory=ROOT / "migrations",
            compatibility_manifest=contract,
            confirmation=confirmation,
            store_factory=lambda value: stores[value],
        ).run()
        assert result.status == "PASSED"
        assert result.metrics["candidate_head"] == 3
        assert all(store.closed for store in stores.values())


def test_migration_probe_rejects_cross_server_or_unverified_tls() -> None:
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        contract = manifest(Path(directory) / "migration.json")
        fresh = url("shadow_fresh_migration_drill")
        upgrade = url("shadow_upgrade_migration_drill", "other.db.internal")
        with pytest.raises(DomainError):
            PostgreSqlMigrationProbe(
                fresh,
                upgrade,
                migration_directory=ROOT / "migrations",
                compatibility_manifest=contract,
                confirmation="0" * 64,
            )
        with pytest.raises(DomainError):
            PostgreSqlMigrationProbe(
                fresh.replace("verify-full", "require"),
                url("shadow_upgrade_migration_drill"),
                migration_directory=ROOT / "migrations",
                compatibility_manifest=contract,
                confirmation="0" * 64,
            )
