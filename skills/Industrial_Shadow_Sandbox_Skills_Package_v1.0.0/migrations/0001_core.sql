PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_migrations(version, applied_at)
VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

CREATE TABLE IF NOT EXISTS artifacts (
  kind TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version > 0),
  digest TEXT NOT NULL,
  payload TEXT NOT NULL,
  sealed INTEGER NOT NULL DEFAULT 0 CHECK (sealed IN (0, 1)),
  supersedes TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY(kind, artifact_id, workspace_id, version),
  UNIQUE(kind, workspace_id, digest)
);
CREATE INDEX IF NOT EXISTS idx_artifacts_lookup
  ON artifacts(workspace_id, kind, artifact_id, version DESC);

CREATE TRIGGER IF NOT EXISTS artifacts_sealed_update
BEFORE UPDATE ON artifacts WHEN OLD.sealed = 1
BEGIN SELECT RAISE(ABORT, 'sealed artifacts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS artifacts_sealed_delete
BEFORE DELETE ON artifacts WHEN OLD.sealed = 1
BEGIN SELECT RAISE(ABORT, 'sealed artifacts are immutable'); END;

CREATE TABLE IF NOT EXISTS outbox (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  run_id TEXT,
  trace_id TEXT,
  occurred_at TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  payload TEXT NOT NULL,
  digest TEXT NOT NULL,
  published_at TEXT
);

CREATE TABLE IF NOT EXISTS idempotency_records (
  scope TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  result TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY(scope, idempotency_key)
);

CREATE TABLE IF NOT EXISTS audit_records (
  audit_id TEXT PRIMARY KEY,
  actor_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  result TEXT NOT NULL,
  trace_id TEXT NOT NULL,
  details TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_scope_time
  ON audit_records(workspace_id, created_at DESC);

CREATE TRIGGER IF NOT EXISTS audit_append_only_update
BEFORE UPDATE ON audit_records BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_append_only_delete
BEFORE DELETE ON audit_records BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;

CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  manifest TEXT NOT NULL,
  manifest_digest TEXT NOT NULL,
  state TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_scope_state ON runs(workspace_id, state);

CREATE TABLE IF NOT EXISTS run_transitions (
  transition_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  from_state TEXT,
  to_state TEXT NOT NULL,
  reason TEXT,
  actor_id TEXT NOT NULL,
  trace_id TEXT NOT NULL,
  occurred_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_signal_events (
  logical_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  scenario_id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  signal_key TEXT NOT NULL,
  data_type TEXT NOT NULL,
  value_json TEXT NOT NULL,
  source_timestamp TEXT NOT NULL,
  server_timestamp TEXT NOT NULL,
  received_timestamp TEXT NOT NULL,
  status_code TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  flags_json TEXT NOT NULL,
  event_digest TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_raw_run_signal_time
  ON raw_signal_events(run_id, signal_key, source_timestamp, sequence);

CREATE TABLE IF NOT EXISTS snapshots (
  snapshot_id TEXT PRIMARY KEY,
  simulator_id TEXT NOT NULL,
  run_id TEXT,
  reason TEXT NOT NULL,
  content_hash TEXT NOT NULL UNIQUE,
  envelope TEXT NOT NULL,
  protected INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  workspace_id TEXT NOT NULL,
  plan_hash TEXT NOT NULL,
  simulator_digest TEXT NOT NULL,
  request_json TEXT NOT NULL,
  decision_json TEXT,
  state TEXT NOT NULL,
  version INTEGER NOT NULL,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS action_executions (
  action_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  approval_id TEXT NOT NULL REFERENCES approvals(approval_id),
  plan_hash TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL,
  request_json TEXT NOT NULL,
  result_json TEXT,
  pre_snapshot_id TEXT,
  post_snapshot_id TEXT,
  rollback_snapshot_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS edge_batches (
  gateway_id TEXT NOT NULL,
  sequence_start INTEGER NOT NULL,
  sequence_end INTEGER NOT NULL,
  batch_hash TEXT NOT NULL,
  payload TEXT NOT NULL,
  received_at TEXT NOT NULL,
  PRIMARY KEY(gateway_id, sequence_start),
  UNIQUE(gateway_id, batch_hash)
);

CREATE TABLE IF NOT EXISTS gold_vault (
  gold_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  scenario_ref TEXT NOT NULL,
  key_ref TEXT NOT NULL,
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  digest TEXT NOT NULL,
  sealed INTEGER NOT NULL CHECK (sealed = 1),
  created_at TEXT NOT NULL,
  PRIMARY KEY(gold_id, workspace_id, version),
  UNIQUE(workspace_id, digest)
);

CREATE TRIGGER IF NOT EXISTS gold_vault_update
BEFORE UPDATE ON gold_vault BEGIN SELECT RAISE(ABORT, 'sealed Gold is immutable'); END;
CREATE TRIGGER IF NOT EXISTS gold_vault_delete
BEFORE DELETE ON gold_vault BEGIN SELECT RAISE(ABORT, 'sealed Gold is immutable'); END;
