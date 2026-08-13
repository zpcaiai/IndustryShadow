CREATE TABLE idempotency_records_v2 (
  workspace_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  result TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY(workspace_id, scope, idempotency_key)
);

INSERT INTO idempotency_records_v2
  (workspace_id, scope, idempotency_key, request_digest, result, created_at)
SELECT '', scope, idempotency_key, request_digest, result, created_at
FROM idempotency_records;

DROP TABLE idempotency_records;
ALTER TABLE idempotency_records_v2 RENAME TO idempotency_records;

INSERT INTO schema_migrations(version, applied_at)
VALUES (3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
