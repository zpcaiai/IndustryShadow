from shadow_sandbox.common import SqliteStore


class SqliteAuditSink:
    def __init__(self, store: SqliteStore) -> None:
        self.store = store
