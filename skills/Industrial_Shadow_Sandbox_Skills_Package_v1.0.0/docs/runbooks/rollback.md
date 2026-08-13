# Rollback

Stop new Runs and revoke outstanding approvals. Scale the action executor to zero,
record the last action ledger state, and deploy the declared rollback image digest.
Only roll back across a schema version listed as compatible in the Release Manifest;
otherwise restore into a new database and verify counts/digests before traffic moves.
Re-enable actions only after interrupted actions are `ROLLED_BACK` or explicitly
resolved from `RECOVERY_REQUIRED`.
