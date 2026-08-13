CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO schema_migrations(version) VALUES (1) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS artifacts (
  kind TEXT NOT NULL, artifact_id TEXT NOT NULL, workspace_id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK(version>0), digest CHAR(64) NOT NULL,
  payload TEXT NOT NULL, sealed BOOLEAN NOT NULL DEFAULT FALSE,
  supersedes TEXT, created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(kind,artifact_id,workspace_id,version), UNIQUE(kind,workspace_id,digest)
);
CREATE INDEX IF NOT EXISTS idx_artifacts_lookup ON artifacts(workspace_id,kind,artifact_id,version DESC);

CREATE TABLE IF NOT EXISTS outbox (
  event_id TEXT PRIMARY KEY,event_type TEXT NOT NULL,tenant_id TEXT NOT NULL,workspace_id TEXT NOT NULL,
  run_id TEXT,trace_id TEXT,occurred_at TIMESTAMPTZ NOT NULL,schema_version INTEGER NOT NULL,
  payload TEXT NOT NULL,digest CHAR(64) NOT NULL,published_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_outbox_unpublished ON outbox(occurred_at) WHERE published_at IS NULL;

CREATE TABLE IF NOT EXISTS idempotency_records (
  scope TEXT NOT NULL,idempotency_key TEXT NOT NULL,request_digest CHAR(64) NOT NULL,
  result TEXT,created_at TIMESTAMPTZ NOT NULL,PRIMARY KEY(scope,idempotency_key)
);

CREATE TABLE IF NOT EXISTS audit_records (
  audit_id CHAR(64) PRIMARY KEY,actor_id TEXT NOT NULL,tenant_id TEXT NOT NULL,workspace_id TEXT NOT NULL,
  action TEXT NOT NULL,target TEXT NOT NULL,result TEXT NOT NULL,trace_id TEXT NOT NULL,
  details TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_scope_time ON audit_records(workspace_id,created_at DESC);

CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,workspace_id TEXT NOT NULL,manifest TEXT NOT NULL,
  manifest_digest CHAR(64) NOT NULL,state TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1,
  last_error TEXT,created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_scope_state ON runs(workspace_id,state);

CREATE TABLE IF NOT EXISTS run_transitions (
  transition_id TEXT PRIMARY KEY,run_id TEXT NOT NULL REFERENCES runs(run_id),from_state TEXT,to_state TEXT NOT NULL,
  reason TEXT,actor_id TEXT NOT NULL,trace_id TEXT NOT NULL,occurred_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_signal_events (
  logical_id CHAR(64) PRIMARY KEY,tenant_id TEXT NOT NULL,workspace_id TEXT NOT NULL,
  run_id TEXT NOT NULL REFERENCES runs(run_id),scenario_id TEXT NOT NULL,endpoint_id TEXT NOT NULL,
  node_id TEXT NOT NULL,signal_key TEXT NOT NULL,data_type TEXT NOT NULL,value_json TEXT NOT NULL,
  source_timestamp TIMESTAMPTZ NOT NULL,server_timestamp TIMESTAMPTZ NOT NULL,received_timestamp TIMESTAMPTZ NOT NULL,
  status_code TEXT NOT NULL,sequence BIGINT NOT NULL,flags_json TEXT NOT NULL,event_digest CHAR(64) NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_raw_run_signal_time ON raw_signal_events(run_id,signal_key,source_timestamp,sequence);

CREATE TABLE IF NOT EXISTS snapshots (
  snapshot_id TEXT PRIMARY KEY,simulator_id TEXT NOT NULL,run_id TEXT,reason TEXT NOT NULL,
  content_hash CHAR(64) NOT NULL UNIQUE,envelope TEXT NOT NULL,protected BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,run_id TEXT NOT NULL REFERENCES runs(run_id),workspace_id TEXT NOT NULL,
  plan_hash CHAR(64) NOT NULL,simulator_digest CHAR(64) NOT NULL,request_json TEXT NOT NULL,
  decision_json TEXT,state TEXT NOT NULL,version INTEGER NOT NULL,expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS action_executions (
  action_id TEXT PRIMARY KEY,run_id TEXT NOT NULL REFERENCES runs(run_id),approval_id TEXT NOT NULL REFERENCES approvals(approval_id),
  plan_hash CHAR(64) NOT NULL,idempotency_key TEXT NOT NULL UNIQUE,state TEXT NOT NULL,request_json TEXT NOT NULL,
  result_json TEXT,pre_snapshot_id TEXT,post_snapshot_id TEXT,rollback_snapshot_id TEXT,
  created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS edge_batches (
  gateway_id TEXT NOT NULL,sequence_start BIGINT NOT NULL,sequence_end BIGINT NOT NULL,
  batch_hash CHAR(64) NOT NULL,payload TEXT NOT NULL,received_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(gateway_id,sequence_start),UNIQUE(gateway_id,batch_hash)
);

CREATE TABLE IF NOT EXISTS gold_vault (
  gold_id TEXT NOT NULL,workspace_id TEXT NOT NULL,version INTEGER NOT NULL,scenario_ref TEXT NOT NULL,
  key_ref TEXT NOT NULL,nonce BYTEA NOT NULL,ciphertext BYTEA NOT NULL,digest CHAR(64) NOT NULL,
  sealed BOOLEAN NOT NULL CHECK(sealed),created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(gold_id,workspace_id,version),UNIQUE(workspace_id,digest)
);

CREATE OR REPLACE FUNCTION deny_immutable_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'immutable record cannot be changed'; END $$;
DROP TRIGGER IF EXISTS artifacts_sealed_change ON artifacts;
CREATE TRIGGER artifacts_sealed_change BEFORE UPDATE OR DELETE ON artifacts
FOR EACH ROW WHEN (OLD.sealed) EXECUTE FUNCTION deny_immutable_change();
DROP TRIGGER IF EXISTS audit_append_only ON audit_records;
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit_records
FOR EACH ROW EXECUTE FUNCTION deny_immutable_change();
DROP TRIGGER IF EXISTS gold_append_only ON gold_vault;
CREATE TRIGGER gold_append_only BEFORE UPDATE OR DELETE ON gold_vault
FOR EACH ROW EXECUTE FUNCTION deny_immutable_change();
