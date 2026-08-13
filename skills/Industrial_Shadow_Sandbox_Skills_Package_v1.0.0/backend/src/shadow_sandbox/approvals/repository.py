from shadow_sandbox.common import SqliteStore


class ApprovalRepository:
    def __init__(self, store: SqliteStore) -> None:
        self.store = store

    def get(self, workspace_id: str, approval_id: str):
        rows = self.store.query(
            "SELECT * FROM approvals WHERE workspace_id=? AND approval_id=?",
            (workspace_id, approval_id),
        )
        return rows[0] if rows else None
