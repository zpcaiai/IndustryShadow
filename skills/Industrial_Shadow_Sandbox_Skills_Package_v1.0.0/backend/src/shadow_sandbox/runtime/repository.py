from shadow_sandbox.common import SqliteStore


class RunRepository:
    def __init__(self, store: SqliteStore) -> None:
        self.store = store

    def tasks(self, workspace_id: str, run_id: str):
        return self.store.query(
            "SELECT * FROM processing_tasks WHERE workspace_id=? AND run_id=? ORDER BY created_at",
            (workspace_id, run_id),
        )
