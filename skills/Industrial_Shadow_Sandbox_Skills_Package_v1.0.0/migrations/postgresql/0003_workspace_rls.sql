ALTER TABLE idempotency_records ADD COLUMN workspace_id TEXT;
UPDATE idempotency_records SET workspace_id = '' WHERE workspace_id IS NULL;
ALTER TABLE idempotency_records ALTER COLUMN workspace_id SET NOT NULL;
ALTER TABLE idempotency_records DROP CONSTRAINT idempotency_records_pkey;
ALTER TABLE idempotency_records
  ADD PRIMARY KEY(workspace_id, scope, idempotency_key);

ALTER TABLE artifacts ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON artifacts
  USING (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''))
  WITH CHECK (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''));

ALTER TABLE outbox ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON outbox
  USING (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''))
  WITH CHECK (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''));

ALTER TABLE idempotency_records ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON idempotency_records
  USING (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''))
  WITH CHECK (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''));

ALTER TABLE audit_records ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON audit_records
  USING (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''))
  WITH CHECK (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''));

ALTER TABLE runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON runs
  USING (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''))
  WITH CHECK (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''));

ALTER TABLE raw_signal_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON raw_signal_events
  USING (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''))
  WITH CHECK (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''));

ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON approvals
  USING (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''))
  WITH CHECK (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''));

ALTER TABLE gold_vault ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON gold_vault
  USING (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''))
  WITH CHECK (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''));

ALTER TABLE domain_resources ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON domain_resources
  USING (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''))
  WITH CHECK (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''));

ALTER TABLE domain_resource_versions ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON domain_resource_versions
  USING (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''))
  WITH CHECK (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''));

ALTER TABLE processing_tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON processing_tasks
  USING (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''))
  WITH CHECK (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''));

ALTER TABLE endpoint_registry ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON endpoint_registry
  USING (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''))
  WITH CHECK (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''));

ALTER TABLE edge_gateways ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON edge_gateways
  USING (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''))
  WITH CHECK (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''));

ALTER TABLE release_promotions ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON release_promotions
  USING (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''))
  WITH CHECK (workspace_id = NULLIF(current_setting('shadow.workspace_id', true), ''));

ALTER TABLE run_transitions ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON run_transitions
  USING (EXISTS (
    SELECT 1 FROM runs
    WHERE runs.run_id = run_transitions.run_id
      AND runs.workspace_id = NULLIF(current_setting('shadow.workspace_id', true), '')
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM runs
    WHERE runs.run_id = run_transitions.run_id
      AND runs.workspace_id = NULLIF(current_setting('shadow.workspace_id', true), '')
  ));

ALTER TABLE action_executions ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON action_executions
  USING (EXISTS (
    SELECT 1 FROM approvals
    WHERE approvals.approval_id = action_executions.approval_id
      AND approvals.workspace_id = NULLIF(current_setting('shadow.workspace_id', true), '')
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM approvals
    WHERE approvals.approval_id = action_executions.approval_id
      AND approvals.workspace_id = NULLIF(current_setting('shadow.workspace_id', true), '')
  ));

ALTER TABLE edge_batches ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON edge_batches
  USING (EXISTS (
    SELECT 1 FROM edge_gateways
    WHERE edge_gateways.gateway_id = edge_batches.gateway_id
      AND edge_gateways.workspace_id = NULLIF(current_setting('shadow.workspace_id', true), '')
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM edge_gateways
    WHERE edge_gateways.gateway_id = edge_batches.gateway_id
      AND edge_gateways.workspace_id = NULLIF(current_setting('shadow.workspace_id', true), '')
  ));

ALTER TABLE snapshots ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON snapshots
  USING (EXISTS (
    SELECT 1 FROM runs
    WHERE runs.run_id = snapshots.run_id
      AND runs.workspace_id = NULLIF(current_setting('shadow.workspace_id', true), '')
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM runs
    WHERE runs.run_id = snapshots.run_id
      AND runs.workspace_id = NULLIF(current_setting('shadow.workspace_id', true), '')
  ));

INSERT INTO schema_migrations(version) VALUES (3);
