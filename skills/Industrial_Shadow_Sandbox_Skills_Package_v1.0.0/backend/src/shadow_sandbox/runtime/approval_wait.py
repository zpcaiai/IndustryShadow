from shadow_sandbox.common import SqliteStore


class ApprovalWait:
    def __init__(self, store: SqliteStore) -> None:
        self.store = store

    def pending(self, run_id: str) -> list[str]:
        return [
            str(row["approval_id"])
            for row in self.store.query(
                "SELECT approval_id FROM approvals WHERE run_id=? AND state='PENDING'", (run_id,)
            )
        ]
