from shadow_sandbox.common import SqliteStore


class ActionRepository:
    def __init__(self, store: SqliteStore) -> None:
        self.store = store

    def by_run(self, run_id: str):
        return self.store.query(
            "SELECT * FROM action_executions WHERE run_id=? ORDER BY created_at", (run_id,)
        )
