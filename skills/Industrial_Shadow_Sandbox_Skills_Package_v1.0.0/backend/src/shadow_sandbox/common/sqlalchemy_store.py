from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Self

from .models import DomainError, EventEnvelope, canonical_digest, canonical_json, utc_now
from .tenant_scope import current_workspace_id


def _statement(sql: str, parameters: Sequence[Any]) -> tuple[Any, dict[str, Any]]:
    try:
        from sqlalchemy import text
    except ImportError as exc:
        raise DomainError(
            "SQLALCHEMY_DEPENDENCY_UNAVAILABLE", "SQLAlchemy is required for PostgreSQL", status=503
        ) from exc
    converted = sql
    values: dict[str, Any] = {}
    for index, value in enumerate(parameters):
        converted = converted.replace("?", f":p{index}", 1)
        values[f"p{index}"] = value
    if "?" in converted:
        raise DomainError("SQL_BINDING_INVALID", "SQL placeholder count does not match parameters")
    if re.search(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", converted, re.IGNORECASE):
        converted = re.sub(
            r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT INTO", converted, flags=re.IGNORECASE
        )
        converted = converted.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
    return text(converted), values


class _Result:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.rowcount = result.rowcount

    def fetchone(self) -> Mapping[str, Any] | None:
        row = self.result.mappings().fetchone()
        return dict(row) if row is not None else None

    def fetchall(self) -> list[Mapping[str, Any]]:
        return [dict(row) for row in self.result.mappings().fetchall()]


class _Connection:
    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def execute(self, sql: str, parameters: Sequence[Any] = ()) -> _Result:
        statement, values = _statement(sql, parameters)
        return _Result(self.connection.execute(statement, values))


class SqlAlchemyStore:
    """PostgreSQL production store with the same transactional port as SqliteStore."""

    def __init__(self, database_url: str) -> None:
        if not database_url.startswith(("postgresql://", "postgresql+psycopg://")):
            raise DomainError(
                "DATABASE_URL_INVALID", "production store requires PostgreSQL", status=503
            )
        try:
            from sqlalchemy import create_engine
        except ImportError as exc:
            raise DomainError(
                "SQLALCHEMY_DEPENDENCY_UNAVAILABLE", "SQLAlchemy is required", status=503
            ) from exc
        normalized = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
        self.engine = create_engine(normalized, pool_pre_ping=True, pool_recycle=300)

    def close(self) -> None:
        self.engine.dispose()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[_Connection]:
        with self.engine.begin() as connection:
            self._bind_workspace(connection)
            yield _Connection(connection)

    @staticmethod
    def _bind_workspace(connection: Any) -> None:
        workspace_id = current_workspace_id()
        if workspace_id:
            statement, values = _statement(
                "SELECT set_config('shadow.workspace_id', ?, true)", (workspace_id,)
            )
            connection.execute(statement, values)

    def migrate_all(self, directory: str | Path) -> int:
        from sqlalchemy.exc import ProgrammingError

        target = Path(directory) / "postgresql"
        paths = sorted(target.glob("[0-9][0-9][0-9][0-9]_*.sql"))
        if not paths:
            raise DomainError("MIGRATIONS_MISSING", "PostgreSQL migrations are missing", status=503)
        expected = [int(path.name.split("_", 1)[0]) for path in paths]
        if expected != list(range(1, len(expected) + 1)):
            raise DomainError(
                "MIGRATION_SEQUENCE_INVALID",
                "migration filenames must form a contiguous sequence starting at 1",
                {"versions": expected},
                status=503,
            )
        try:
            rows = self.query("SELECT version FROM schema_migrations ORDER BY version")
            applied = [int(row["version"]) for row in rows]
        except ProgrammingError as error:
            if getattr(error.orig, "sqlstate", None) != "42P01":
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
            with self.engine.begin() as connection:
                connection.exec_driver_sql(path.read_text(encoding="utf-8"))
        rows = self.query("SELECT version FROM schema_migrations ORDER BY version")
        actual = [int(row["version"]) for row in rows]
        if actual != expected:
            raise DomainError(
                "MIGRATION_HEAD_INVALID",
                "migration did not advance to the expected head",
                {"applied": actual, "expected": expected},
                status=503,
            )
        return actual[-1]

    def execute(self, sql: str, parameters: Sequence[Any] = ()) -> _Result:
        with self.engine.begin() as connection:
            self._bind_workspace(connection)
            statement, values = _statement(sql, parameters)
            result = connection.execute(statement, values)
            return _Result(result)

    def query(self, sql: str, parameters: Sequence[Any] = ()) -> list[dict[str, Any]]:
        with self.engine.connect() as connection:
            self._bind_workspace(connection)
            statement, values = _statement(sql, parameters)
            return [
                dict(row) for row in connection.execute(statement, values).mappings().fetchall()
            ]

    def iterate(
        self,
        sql: str,
        parameters: Sequence[Any] = (),
        *,
        batch_size: int = 128,
    ) -> Iterator[dict[str, Any]]:
        """Stream a read query through a server-side cursor with bounded buffering."""

        if batch_size < 1 or batch_size > 4096:
            raise DomainError(
                "SQL_BATCH_SIZE_INVALID", "streaming query batch size must be between 1 and 4096"
            )
        with self.engine.connect() as connection:
            self._bind_workspace(connection)
            connection.exec_driver_sql("SET LOCAL TIME ZONE 'UTC'")
            statement, values = _statement(sql, parameters)
            result = connection.execution_options(
                stream_results=True,
                max_row_buffer=batch_size,
                yield_per=batch_size,
            ).execute(statement, values)
            for row in result.mappings():
                yield dict(row)

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
                """INSERT INTO artifacts(kind,artifact_id,workspace_id,version,digest,payload,sealed,supersedes,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
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
        sql = "SELECT * FROM artifacts WHERE kind=? AND artifact_id=? AND workspace_id=?"
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
            """INSERT INTO outbox(event_id,event_type,tenant_id,workspace_id,run_id,trace_id,occurred_at,schema_version,payload,digest) VALUES(?,?,?,?,?,?,?,?,?,?)""",
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
                """INSERT INTO idempotency_records(workspace_id,scope,idempotency_key,request_digest,result,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(workspace_id,scope,idempotency_key) DO UPDATE SET result=excluded.result""",
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
            """INSERT INTO audit_records(audit_id,actor_id,tenant_id,workspace_id,action,target,result,trace_id,details,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
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
