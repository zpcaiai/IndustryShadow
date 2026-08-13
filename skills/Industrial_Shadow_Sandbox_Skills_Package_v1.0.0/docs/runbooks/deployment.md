# Deployment

Verify signed image/SBOM/provenance digests against the Release Manifest, render the
environment overlay, and run policy/IaC checks. Apply the migration Job alone and
wait for success before workloads. Confirm `/api/v1/version`, readiness migration
head, action-service simulator digest, Collector fingerprint/namespace, S3 write/read,
and all NetworkPolicies. Keep promotion `NOT_CERTIFIED` until the target smoke and
rollback-preflight evidence is attached.
