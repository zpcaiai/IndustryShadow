from __future__ import annotations

import atexit
import contextlib
import json
import sqlite3
import threading
import weakref
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol, Self

from .models import DomainError, EventEnvelope, canonical_digest, canonical_json, utc_now

_OPEN_STORES: weakref.WeakSet[SqliteStore] = weakref.WeakSet()


class Store(Protocol):
    """Transactional persistence port shared by SQLite and PostgreSQL adapters."""

    def close(self) -> None: ...

    def transaction(self) -> contextlib.AbstractContextManager[Any]: ...

    def migrate_all(self, directory: str | Path) -> int: ...

    def execute(self, sql: str, parameters: Sequence[Any] = ()) -> Any: ...

    def query(self, sql: str, parameters: Sequence[Any] = ()) -> list[dict[str, Any]]: ...

    def append_event(self, event: EventEnvelope) -> None: ...

    def put_artifact(
        self,
        *,
        kind: str,
        artifact_id: str,
        workspace_id: str,
        payload: Mapping[str, Any],
        version: int = 1,
        sealed: bool = False,
        supersedes: str | None = None,
    ) -> str: ...

    def get_artifact(
        self,
        kind: str,
        artifact_id: str,
        workspace_id: str,
        version: int | None = None,
    ) -> dict[str, Any]: ...

    def idempotent_result(
        self, workspace_id: str, scope: str, key: str
    ) -> dict[str, Any] | None: ...

    def record_idempotent_result(
        self,
        workspace_id: str,
        scope: str,
        key: str,
        request_digest: str,
        result: Mapping[str, Any],
    ) -> None: ...

    def audit(
        self,
        *,
        actor_id: str,
        tenant_id: str,
        workspace_id: str,
        action: str,
        target: str,
        result: str,
        trace_id: str,
        details: Mapping[str, Any] | None = None,
    ) -> str: ...


@atexit.register
def _close_open_stores() -> None:
    for store in tuple(_OPEN_STORES):
        store.close()


class SqliteStore:
    """Durable local store used by the reference runtime and tests.

    PostgreSQL remains the production target. SQLite provides real transactions,
    uniqueness, restart persistence, and executable migrations without pretending to
    prove PostgreSQL/RLS behavior.
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.RLock()
        self._closed = False
        self._finalizer = weakref.finalize(self, self.connection.close)
        _OPEN_STORES.add(self)

    def close(self) -> None:
        if not self._closed:
            if self._finalizer.alive:
                self._finalizer()
            self._closed = True
            _OPEN_STORES.discard(self)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                yield self.connection
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise

    def migrate(self, sql_path: str | Path) -> None:
        script = Path(sql_path).read_text(encoding="utf-8")
        with self._lock:
            self.connection.executescript(script)
            self.connection.commit()

    def migrate_all(self, directory: str | Path) -> int:
        """Apply only unapplied ordered migrations and return the database head."""
        paths = sorted(Path(directory).glob("[0-9][0-9][0-9][0-9]_*.sql"))
        if not paths:
            raise DomainError("MIGRATIONS_MISSING", "no SQL migrations were found", status=503)
        expected = [int(path.name.split("_", 1)[0]) for path in paths]
        if expected != list(range(1, len(expected) + 1)):
            raise DomainError(
                "MIGRATION_SEQUENCE_INVALID",
                "migration filenames must form a contiguous sequence starting at 1",
                {"versions": expected},
                status=503,
            )
        try:
            applied = [
                int(row["version"])
                for row in self.connection.execute(
                    "SELECT version FROM schema_migrations ORDER BY version"
                ).fetchall()
            ]
        except sqlite3.OperationalError as error:
            if "no such table: schema_migrations" not in str(error):
                raise
            applied = []
        if applied != expected[: len(applied)]:
            raise DomainError(
                "MIGRATION_HISTORY_INVALID",
                "applied migrations are not a prefix of the packaged migration sequence",
                {"applied": applied, "expected": expected},
                status=503,
            )
        for path in paths[len(applied) :]:
            self.migrate(path)
        actual = [
            int(row["version"])
            for row in self.connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        ]
        if actual != expected:
            raise DomainError(
                "MIGRATION_HEAD_INVALID",
                "migration did not advance to the expected head",
                {"applied": actual, "expected": expected},
                status=503,
            )
        return actual[-1]

    def execute(self, sql: str, parameters: Sequence[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cursor = self.connection.execute(sql, parameters)
            self.connection.commit()
            return cursor

    def query(self, sql: str, parameters: Sequence[Any] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self.connection.execute(sql, parameters).fetchall()]

    def put_artifact(
        self,
        *,
        kind: str,
        artifact_id: str,
        workspace_id: str,
        payload: Mapping[str, Any],
        version: int = 1,
        sealed: bool = False,
        supersedes: str | None = None,
    ) -> str:
        digest = canonical_digest(payload)
        with self.transaction() as tx:
            tx.execute(
                """INSERT INTO artifacts
                   (kind, artifact_id, workspace_id, version, digest, payload, sealed,
                    supersedes, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    kind,
                    artifact_id,
                    workspace_id,
                    version,
                    digest,
                    canonical_json(payload),
                    sealed,
                    supersedes,
                    utc_now(),
                ),
            )
        return digest

    def get_artifact(
        self, kind: str, artifact_id: str, workspace_id: str, version: int | None = None
    ) -> dict[str, Any]:
        params: list[Any] = [kind, artifact_id, workspace_id]
        sql = """SELECT * FROM artifacts
                 WHERE kind=? AND artifact_id=? AND workspace_id=?"""
        if version is not None:
            sql += " AND version=?"
            params.append(version)
        sql += " ORDER BY version DESC LIMIT 1"
        rows = self.query(sql, params)
        if not rows:
            raise DomainError("NOT_FOUND", f"{kind} not found", status=404)
        row = rows[0]
        row["payload"] = json.loads(row["payload"])
        return row

    def append_event(self, event: EventEnvelope) -> None:
        self.execute(
            """INSERT INTO outbox
               (event_id, event_type, tenant_id, workspace_id, run_id, trace_id,
                occurred_at, schema_version, payload, digest)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.event_id,
                event.event_type,
                event.tenant_id,
                event.workspace_id,
                event.run_id,
                event.trace_id,
                event.occurred_at,
                event.schema_version,
                canonical_json(event.payload),
                event.digest,
            ),
        )

    def idempotent_result(self, workspace_id: str, scope: str, key: str) -> dict[str, Any] | None:
        rows = self.query(
            """SELECT result FROM idempotency_records
               WHERE workspace_id=? AND scope=? AND idempotency_key=?""",
            (workspace_id, scope, key),
        )
        return json.loads(rows[0]["result"]) if rows and rows[0]["result"] else None

    def record_idempotent_result(
        self,
        workspace_id: str,
        scope: str,
        key: str,
        request_digest: str,
        result: Mapping[str, Any],
    ) -> None:
        with self.transaction() as tx:
            row = tx.execute(
                """SELECT request_digest FROM idempotency_records
                   WHERE workspace_id=? AND scope=? AND idempotency_key=?""",
                (workspace_id, scope, key),
            ).fetchone()
            if row and row["request_digest"] != request_digest:
                raise DomainError(
                    "IDEMPOTENCY_CONFLICT", "key reused with a different request", status=409
                )
            tx.execute(
                """INSERT INTO idempotency_records
                   (workspace_id, scope, idempotency_key, request_digest, result, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(workspace_id, scope, idempotency_key)
                   DO UPDATE SET result=excluded.result""",
                (
                    workspace_id,
                    scope,
                    key,
                    request_digest,
                    canonical_json(result),
                    utc_now(),
                ),
            )

    def audit(
        self,
        *,
        actor_id: str,
        tenant_id: str,
        workspace_id: str,
        action: str,
        target: str,
        result: str,
        trace_id: str,
        details: Mapping[str, Any] | None = None,
    ) -> str:
        audit_id = canonical_digest(
            [actor_id, workspace_id, action, target, result, trace_id, utc_now()]
        )
        self.execute(
            """INSERT INTO audit_records
               (audit_id, actor_id, tenant_id, workspace_id, action, target, result,
                trace_id, details, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                audit_id,
                actor_id,
                tenant_id,
                workspace_id,
                action,
                target,
                result,
                trace_id,
                canonical_json(details or {}),
                utc_now(),
            ),
        )
        return audit_id
