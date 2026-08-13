from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from shadow_sandbox.common import SqliteStore, canonical_digest
from shadow_sandbox.common.models import new_id, utc_now


class TaskLedger:
    def __init__(self, store: SqliteStore) -> None:
        self.store = store

    def claim(self, workspace_id: str, run_id: str, stage: str, request: Mapping[str, Any]) -> str:
        digest = canonical_digest(request)
        existing = self.store.query(
            "SELECT task_id FROM processing_tasks WHERE workspace_id=? AND run_id=? AND stage=? AND request_digest=?",
            (workspace_id, run_id, stage, digest),
        )
        if existing:
            return str(existing[0]["task_id"])
        task_id = new_id("task")
        now = utc_now()
        self.store.execute(
            "INSERT INTO processing_tasks(task_id,run_id,workspace_id,stage,state,request_digest,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
            (task_id, run_id, workspace_id, stage, "CLAIMED", digest, now, now),
        )
        return task_id

    def complete(self, task_id: str, resource_type: str, resource_id: str) -> None:
        self.store.execute(
            "UPDATE processing_tasks SET state='COMPLETED', output_resource_type=?, output_resource_id=?, updated_at=? WHERE task_id=?",
            (resource_type, resource_id, utc_now(), task_id),
        )
