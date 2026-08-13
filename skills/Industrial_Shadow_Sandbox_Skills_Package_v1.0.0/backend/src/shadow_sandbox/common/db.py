from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .models import DomainError
from .sqlalchemy_store import SqlAlchemyStore
from .store import SqliteStore


def open_database(path: str | Path, migrations: str | Path) -> SqliteStore:
    store = SqliteStore(path)
    store.migrate_all(migrations)
    return store


def open_store(
    database: str, migrations: str | Path, *, migrate: bool = True
) -> SqliteStore | SqlAlchemyStore:
    if database.startswith(("postgresql://", "postgresql+psycopg://")):
        store = SqlAlchemyStore(database)
    else:
        store = SqliteStore(database.removeprefix("sqlite:///"))
    if migrate:
        store.migrate_all(migrations)
    else:
        directory = Path(migrations)
        target = directory / "postgresql" if database.startswith("postgresql") else directory
        versions = [
            int(path.name.split("_", 1)[0]) for path in target.glob("[0-9][0-9][0-9][0-9]_*.sql")
        ]
        expected = max(versions, default=0)
        try:
            rows = store.query("SELECT MAX(version) AS version FROM schema_migrations")
            current = int(rows[0]["version"] or 0)
        except Exception as error:
            store.close()
            raise DomainError(
                "DATABASE_SCHEMA_UNAVAILABLE", "database schema is unavailable", status=503
            ) from error
        if not expected or current != expected:
            store.close()
            raise DomainError(
                "DATABASE_MIGRATION_DRIFT",
                "database migration head does not match this build",
                {"current": current, "expected": expected},
                status=503,
            )
    return store


@contextmanager
def database_lifecycle(path: str | Path, migrations: str | Path) -> Iterator[SqliteStore]:
    store = open_database(path, migrations)
    try:
        yield store
    finally:
        store.close()
