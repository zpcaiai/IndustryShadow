PRAGMA foreign_keys=ON;

INSERT OR IGNORE INTO schema_migrations(version, applied_at)
VALUES (2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- A durable resource ledger for drafts and execution products.  Domain services
-- still enforce their type-specific invariants; this table supplies tenant scope,
-- optimistic locking, immutability, version history, and deterministic digests.
CREATE TABLE IF NOT EXISTS domain_resources (
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  state TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version > 0),
  payload TEXT NOT NULL,
  digest TEXT NOT NULL,
  sealed INTEGER NOT NULL DEFAULT 0 CHECK (sealed IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(resource_type, resource_id, workspace_id)
);
CREATE INDEX IF NOT EXISTS idx_domain_resources_list
  ON domain_resources(workspace_id, resource_type, updated_at DESC, resource_id);
CREATE INDEX IF NOT EXISTS idx_domain_resources_state
  ON domain_resources(workspace_id, resource_type, state);

CREATE TABLE IF NOT EXISTS domain_resource_versions (
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version > 0),
  state TEXT NOT NULL,
  payload TEXT NOT NULL,
  digest TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(resource_type, resource_id, workspace_id, version),
  UNIQUE(resource_type, workspace_id, digest)
);

CREATE TRIGGER IF NOT EXISTS sealed_domain_resource_update
BEFORE UPDATE ON domain_resources WHEN OLD.sealed = 1
BEGIN SELECT RAISE(ABORT, 'sealed domain resources are immutable'); END;
CREATE TRIGGER IF NOT EXISTS sealed_domain_resource_delete
BEFORE DELETE ON domain_resources WHEN OLD.sealed = 1
BEGIN SELECT RAISE(ABORT, 'sealed domain resources are immutable'); END;
CREATE TRIGGER IF NOT EXISTS domain_resource_versions_update
BEFORE UPDATE ON domain_resource_versions
BEGIN SELECT RAISE(ABORT, 'resource history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS domain_resource_versions_delete
BEFORE DELETE ON domain_resource_versions
BEGIN SELECT RAISE(ABORT, 'resource history is append-only'); END;

CREATE TABLE IF NOT EXISTS processing_tasks (
  task_id TEXT PRIMARY KEY,
  run_id TEXT REFERENCES runs(run_id),
  workspace_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  state TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  output_resource_type TEXT,
  output_resource_id TEXT,
  error_code TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id, run_id, stage, request_digest)
);
CREATE INDEX IF NOT EXISTS idx_processing_tasks_run
  ON processing_tasks(workspace_id, run_id, created_at);

CREATE TABLE IF NOT EXISTS endpoint_registry (
  endpoint_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  environment_type TEXT NOT NULL,
  application_uri TEXT NOT NULL,
  endpoint_uri TEXT NOT NULL,
  namespace_allowlist TEXT NOT NULL,
  node_allowlist TEXT NOT NULL,
  certificate_fingerprint TEXT NOT NULL,
  identity_digest TEXT NOT NULL,
  policy TEXT NOT NULL,
  state TEXT NOT NULL,
  last_seen_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(endpoint_id, workspace_id)
);

CREATE TABLE IF NOT EXISTS edge_gateways (
  gateway_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  site_id TEXT NOT NULL,
  identity_digest TEXT NOT NULL,
  certificate_fingerprint TEXT NOT NULL,
  config_digest TEXT NOT NULL,
  state TEXT NOT NULL,
  last_sequence INTEGER NOT NULL DEFAULT 0,
  last_heartbeat_at TEXT,
  health_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(gateway_id, workspace_id),
  UNIQUE(workspace_id, identity_digest)
);

CREATE TABLE IF NOT EXISTS release_promotions (
  promotion_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  gate_id TEXT NOT NULL,
  certification_digest TEXT NOT NULL,
  bundle_digest TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  promoted_at TEXT NOT NULL,
  UNIQUE(workspace_id, bundle_digest)
);
