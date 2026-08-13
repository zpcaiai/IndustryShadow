from shadow_sandbox.common import SqliteStore


class SnapshotRegistry:
    def __init__(self, store: SqliteStore) -> None:
        self.store = store

    def metadata(self, snapshot_id: str):
        rows = self.store.query(
            "SELECT snapshot_id,simulator_id,run_id,reason,content_hash,protected,created_at FROM snapshots WHERE snapshot_id=?",
            (snapshot_id,),
        )
        return rows[0] if rows else None
