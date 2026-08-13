from shadow_sandbox.common import SqliteStore


class EndpointRegistry:
    def __init__(self, store: SqliteStore) -> None:
        self.store = store

    def get(self, workspace_id: str, endpoint_id: str):
        rows = self.store.query(
            "SELECT * FROM endpoint_registry WHERE workspace_id=? AND endpoint_id=?",
            (workspace_id, endpoint_id),
        )
        return rows[0] if rows else None
