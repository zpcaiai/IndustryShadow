from __future__ import annotations

from typing import Any

from shadow_sandbox.common import ActorContext, DomainError, Store


class IngestionQueryService:
    def __init__(self, store: Store) -> None:
        self.store = store

    def events(
        self,
        actor: ActorContext,
        run_id: str,
        signal_key: str,
        start: str | None = None,
        end: str | None = None,
        limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 10_000:
            raise DomainError("INVALID_LIMIT", "limit must be within 1..10000")
        ownership = self.store.query(
            "SELECT 1 FROM runs WHERE run_id=? AND workspace_id=?", (run_id, actor.workspace_id)
        )
        if not ownership:
            raise DomainError("RUN_NOT_FOUND", "run not found", status=404)
        sql = """SELECT * FROM raw_signal_events
                 WHERE run_id=? AND workspace_id=? AND signal_key=?"""
        params: list[Any] = [run_id, actor.workspace_id, signal_key]
        if start:
            sql += " AND source_timestamp>=?"
            params.append(start)
        if end:
            sql += " AND source_timestamp<=?"
            params.append(end)
        sql += " ORDER BY source_timestamp, sequence LIMIT ?"
        params.append(limit)
        return self.store.query(sql, params)

    def health(self, run_id: str) -> dict[str, Any]:
        rows = self.store.query(
            """SELECT COUNT(*) AS count,
                      MAX(received_timestamp) AS last_received,
                      SUM(CASE WHEN flags_json LIKE '%gap%' THEN 1 ELSE 0 END) AS gaps
                 FROM raw_signal_events WHERE run_id=?""",
            (run_id,),
        )
        row = rows[0]
        return {
            "state": "healthy" if row["count"] else "empty",
            "event_count": row["count"],
            "last_received": row["last_received"],
            "gaps": row["gaps"] or 0,
        }
