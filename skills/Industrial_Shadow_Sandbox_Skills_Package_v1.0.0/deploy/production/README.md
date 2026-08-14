# Production deployment contract

This directory is a fail-closed Kustomize base. It contains no credentials and its
image digests, OIDC coordinates, Collector binding, simulator attestation digest,
and real OPC UA host are deliberately non-routable placeholders.

Before deployment, a reviewed environment overlay must:

1. replace every all-zero image digest with a signed digest from the same Release Manifest;
2. replace `shadow-release-coordinates` and both Collector bindings, NodeId allowlists,
   server/client fingerprints, and client ApplicationUris;
3. replace the `192.0.2.0/32`, `198.51.100.10/32`, `198.51.100.20/32`, and
   `198.51.100.30/32` NetworkPolicy placeholders with the approved read-only OPC UA,
   HTTPS identity/object-storage, PostgreSQL, and object-storage addresses respectively;
4. replace the OIDC issuer, audience, JWKS, public client, evaluator-service client allowlist,
   asymmetric ID-token algorithm allowlist, authorization, token, and logout URL placeholders;
   register `/auth/callback` as an exact Authorization Code + PKCE redirect;
   then create
   `shadow-api-secrets`, `shadow-action-secrets`, `shadow-simulator-secrets`,
   `shadow-worker-secrets`, `shadow-migration-secrets`, `shadow-backup-secrets`,
   `shadow-real-ot-collector-secrets`, `shadow-simulator-collector-secrets`,
   `shadow-simulator-pki`, and the four target-specific Collector PKI Secrets from the
   platform secret manager;
5. route ingress only through a namespace labelled `industrial-shadow-ingress=allowed`;
6. provide S3 lifecycle/versioning/Object Lock, an exact KMS key ARN, and a PostgreSQL role
   with no schema-owner privileges.

The acceptance-only object-storage probe, simulator snapshots, and database backups use
three distinct, signed prefixes. `SHADOW_OBJECT_STORAGE_PREFIX` exists only in the
acceptance runner; the sealed runtime ConfigMap carries
`SHADOW_SNAPSHOT_OBJECT_STORAGE_PREFIX` and
`SHADOW_BACKUP_OBJECT_STORAGE_PREFIX`. Do not collapse them in an overlay. The acceptance
gate uses separate short-lived backup and snapshot identity sessions, proves a
version-pinned KMS round trip in each runtime prefix, and requires AccessDenied when each
identity reads a pre-created sentinel in the opposite prefix.

The API, action, Collector, worker, migration, and backup secrets each carry a distinct
`SHADOW_DATABASE_URL`; the three internal services also carry their scoped copy of
`SHADOW_INTERNAL_SERVICE_TOKEN`. Workloads never consume an entire Secret through
`envFrom`. The sealed manifests use non-optional `secretKeyRef` entries with this exact
allowlist:

- `control-api`: `SHADOW_DATABASE_URL` and `SHADOW_INTERNAL_SERVICE_TOKEN` from
  `shadow-api-secrets`;
- `worker`: `SHADOW_DATABASE_URL` from `shadow-worker-secrets`;
- `action-executor`: `SHADOW_DATABASE_URL` and `SHADOW_INTERNAL_SERVICE_TOKEN` from
  `shadow-action-secrets`;
- `simulator`: `SHADOW_INTERNAL_SERVICE_TOKEN` from `shadow-simulator-secrets`;
- real-OT and simulator Collectors: `SHADOW_DATABASE_URL` from their corresponding
  `shadow-*-collector-secrets`;
- migration and backup: `SHADOW_DATABASE_URL` from `shadow-migration-secrets` and
  `shadow-backup-secrets`, respectively.

Additional Secret keys are inert. Overlays must not reintroduce Secret `envFrom`, optional
secret references, aliases, or other `valueFrom` sources. Sealed non-secret coordinates
continue to use the exact ConfigMap `envFrom` allowlist. Bucket, region, KMS key, and OIDC issuer,
audience, public and evaluator-service client IDs, signing algorithms, PKCE endpoints, and
JWKS URL are non-secret release coordinates
in the runtime ConfigMap. The
worker secret has a distinct PostgreSQL URL for a dedicated, non-login-to-API `BYPASSRLS`
maintenance role; API/action/collector roles must be non-owner roles without `BYPASSRLS`.
The migration secret uses a schema-owner role and is mounted only into the one-shot Job.
The backup secret uses a dedicated `BYPASSRLS` backup role with read-only object grants and
is mounted only into the CronJob; full-database backup cannot use a tenant-filtered role.
Collector database Secrets and PKI Secrets are separate. Each target has an independent
current Secret (`client.crt`, `client.key`, and pinned `server.crt`) plus a next Secret
(`client.crt` and `client.key`). Both client certificates must carry that target Collector's
exact ApplicationUri SAN and clientAuth EKU, match their private keys, be distinct for
rotation, and be mounted read-only. The collector sets its asyncua ApplicationUri before
loading the current certificate; asyncua then binds that certificate and URI into the secure
session. Simulator PKI contains `server.crt` and `server.key`; the runtime ConfigMap must pin
the corresponding Collector client certificate SHA-256 fingerprints before rollout.
The migration Job validates all pre-created database roles and applies least-privilege
grants/default privileges after migrations. Real-OT and simulator Collectors use separate
Deployments, ServiceAccounts, configuration, database Secrets, client PKI, and
`collector-target` labels. The real-OT NetworkPolicy has no simulator peer and the simulator
Collector has no real-OT IP peer, so swapping a binding does not grant cross-plane egress.
Simulator, Collectors, and backup use separate workload identities; the environment overlay
must replace their placeholder annotations.

No production policy contains `0.0.0.0/0`. If the IdP or S3 provider uses changing address
ranges, the environment must use a reviewed CNI/FQDN egress policy rather than widening the
Kubernetes `NetworkPolicy`. `deploy/production/validation/` contains the live plane-labelled
probe contract that must pass after the overlay is applied.

For local contract inspection, apply the namespace/config/secrets first, then the migration
Job and wait for it:

```sh
kubectl apply -f namespace.yaml -f config.yaml
kubectl apply -f migration-job.yaml
kubectl wait --for=condition=complete --timeout=10m job/shadow-migrate -n industrial-shadow
kubectl apply -f workloads.yaml -f network-policies.yaml -f backup-cronjob.yaml
kubectl rollout status deployment/control-api -n industrial-shadow --timeout=10m
```

Do not issue a closure certificate from rendered YAML alone. PostgreSQL migration,
backup/restore, OIDC, S3, OPC UA interoperability, NetworkPolicy enforcement, load,
resilience, and rollback evidence must be generated in the target environment.
Run the environment-protected `production-acceptance` workflow to generate digest-bound
gate evidence. A closure input is created only after independent `release_owner` and
`security_owner` Ed25519 signatures bind the exact evidence digest set.
Formal production publication uses the sealed four-manifest plan described in
`docs/runbooks/production-acceptance.md` and the protected `production-deploy` workflow; do
not use these illustrative base-file commands as a release mechanism.
