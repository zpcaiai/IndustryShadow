INSERT INTO schema_migrations(version) VALUES (2) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS domain_resources (
  resource_type TEXT NOT NULL,resource_id TEXT NOT NULL,tenant_id TEXT NOT NULL,workspace_id TEXT NOT NULL,
  state TEXT NOT NULL,version INTEGER NOT NULL CHECK(version>0),payload TEXT NOT NULL,digest CHAR(64) NOT NULL,
  sealed BOOLEAN NOT NULL DEFAULT FALSE,created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(resource_type,resource_id,workspace_id)
);
CREATE INDEX IF NOT EXISTS idx_domain_resources_list ON domain_resources(workspace_id,resource_type,updated_at DESC,resource_id);
CREATE INDEX IF NOT EXISTS idx_domain_resources_state ON domain_resources(workspace_id,resource_type,state);

CREATE TABLE IF NOT EXISTS domain_resource_versions (
  resource_type TEXT NOT NULL,resource_id TEXT NOT NULL,workspace_id TEXT NOT NULL,version INTEGER NOT NULL CHECK(version>0),
  state TEXT NOT NULL,payload TEXT NOT NULL,digest CHAR(64) NOT NULL,created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(resource_type,resource_id,workspace_id,version),UNIQUE(resource_type,workspace_id,digest)
);

CREATE TABLE IF NOT EXISTS processing_tasks (
  task_id TEXT PRIMARY KEY,run_id TEXT REFERENCES runs(run_id),workspace_id TEXT NOT NULL,stage TEXT NOT NULL,state TEXT NOT NULL,
  request_digest CHAR(64) NOT NULL,output_resource_type TEXT,output_resource_id TEXT,error_code TEXT,
  created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL,
  UNIQUE(workspace_id,run_id,stage,request_digest)
);
CREATE INDEX IF NOT EXISTS idx_processing_tasks_run ON processing_tasks(workspace_id,run_id,created_at);

CREATE TABLE IF NOT EXISTS endpoint_registry (
  endpoint_id TEXT NOT NULL,workspace_id TEXT NOT NULL,environment_type TEXT NOT NULL,application_uri TEXT NOT NULL,
  endpoint_uri TEXT NOT NULL,namespace_allowlist TEXT NOT NULL,node_allowlist TEXT NOT NULL,
  certificate_fingerprint TEXT NOT NULL,identity_digest CHAR(64) NOT NULL,policy TEXT NOT NULL,state TEXT NOT NULL,
  last_seen_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(endpoint_id,workspace_id)
);

CREATE TABLE IF NOT EXISTS edge_gateways (
  gateway_id TEXT NOT NULL,tenant_id TEXT NOT NULL,workspace_id TEXT NOT NULL,site_id TEXT NOT NULL,
  identity_digest CHAR(64) NOT NULL,certificate_fingerprint TEXT NOT NULL,config_digest CHAR(64) NOT NULL,
  state TEXT NOT NULL,last_sequence BIGINT NOT NULL DEFAULT 0,last_heartbeat_at TIMESTAMPTZ,
  health_json TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(gateway_id,workspace_id),UNIQUE(workspace_id,identity_digest)
);

CREATE TABLE IF NOT EXISTS release_promotions (
  promotion_id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,gate_id TEXT NOT NULL,
  certification_digest CHAR(64) NOT NULL,bundle_digest CHAR(64) NOT NULL,actor_id TEXT NOT NULL,
  reason TEXT NOT NULL,promoted_at TIMESTAMPTZ NOT NULL,UNIQUE(workspace_id,bundle_digest)
);

DROP TRIGGER IF EXISTS sealed_domain_resource_change ON domain_resources;
CREATE TRIGGER sealed_domain_resource_change BEFORE UPDATE OR DELETE ON domain_resources
FOR EACH ROW WHEN (OLD.sealed) EXECUTE FUNCTION deny_immutable_change();
DROP TRIGGER IF EXISTS domain_resource_versions_append_only ON domain_resource_versions;
CREATE TRIGGER domain_resource_versions_append_only BEFORE UPDATE OR DELETE ON domain_resource_versions
FOR EACH ROW EXECUTE FUNCTION deny_immutable_change();
