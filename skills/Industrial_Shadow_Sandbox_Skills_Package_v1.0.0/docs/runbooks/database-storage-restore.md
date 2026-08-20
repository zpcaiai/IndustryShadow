# Database and object-storage restore

The backup Job opens a read-only `REPEATABLE READ` transaction, exports one PostgreSQL
snapshot, and keeps that transaction open while both the streaming fingerprints and
`pg_dump --snapshot` run. The version 3 manifest binds the resulting custom archive to the
backup-time table multiset fingerprints, RLS policies, migration history, full catalog and
runtime sequence state. Sequence values are taken from the custom archive's exact
`SEQUENCE SET` entries rather than a second live query because PostgreSQL sequences are not
MVCC. The manifest contains only counts, SHA-256 digests, role posture, and non-secret AWS
partition metadata; it does not contain table rows or credentials.

In production the connection URL accepts only the TLS parameters that are copied to
`pg_dump`; options such as `options=-c role=...` are rejected. The snapshot connection is
also built from the same explicit host/port/database/user/password/TLS allowlist and clears
ambient libpq options, so the exporter and dump process cannot silently use different
effective roles or connection settings.

Production writes three distinct versioned KMS objects under the dedicated backup prefix:
the custom archive, its canonical manifest, and a canonical sealed receipt. The local
`SHADOW_BACKUP_RESTORE_RECEIPT` is an owner-only `0400`/`0600` pointer that binds all three
exact S3 version IDs, sizes, SHA-256 values, the manifest/snapshot digests, and the KMS
partition. Restore fetches the sealed receipt first, then the manifest and archive by those
exact versions. It rejects a mutable/latest read, a different KMS partition, a noncanonical
object, or any digest mismatch.

Do not copy that pointer into a CI secret or transcribe it from a terminal. After the signed
formal and deployment bundles have been staged, select the already completed backup Job by
its exact context, namespace, name, and Kubernetes UID. The production acceptance workflow
sets `SHADOW_BACKUP_JOB_NAMESPACE`, `SHADOW_BACKUP_JOB_NAME`, and
`SHADOW_BACKUP_JOB_UID` as protected environment variables, then runs:

```sh
install -d -m 0700 "${SHADOW_BACKUP_RESTORE_RECEIPT%/*}"
PYTHONPATH=backend/src python tools/collect_production_backup_receipt.py \
  --context "$SHADOW_KUBERNETES_STORAGE_CONTEXT" \
  --namespace "$SHADOW_BACKUP_JOB_NAMESPACE" \
  --job-name "$SHADOW_BACKUP_JOB_NAME" \
  --job-uid "$SHADOW_BACKUP_JOB_UID" \
  --candidate-image "$SHADOW_CANDIDATE_IMAGE" \
  --build-digest "$SHADOW_BUILD_DIGEST" \
  --simulator-build-digest "$SHADOW_SIMULATOR_BUILD_DIGEST" \
  --environment-digest "$SHADOW_PRODUCTION_ENVIRONMENT_DIGEST" \
  --deployment-plan-digest "$SHADOW_DEPLOYMENT_PLAN_DIGEST" \
  --formal-report "$SHADOW_FORMAL_BENCHMARK_REPORT" \
  --deployment-plan "$SHADOW_PRODUCTION_DEPLOYMENT_PLAN" \
  --trust-store "$SHADOW_ASSESSOR_TRUST_STORE" \
  --trust-root-attestation "$SHADOW_ASSESSOR_TRUST_ROOT_ATTESTATION" \
  --trust-root-public-key "$SHADOW_ASSESSOR_TRUST_ROOT_PUBLIC_KEY" \
  --trust-root-key-sha256 "$SHADOW_ASSESSOR_TRUST_ROOT_KEY_SHA256" \
  --output "$SHADOW_BACKUP_RESTORE_RECEIPT"
```

The collector is Kubernetes-read-only. Before requesting logs it re-verifies the signed
cluster identity, a clean single-completion Job, the exact backup ServiceAccount with ambient
token automount disabled, one owned Pod, one non-restarted backup container, the exact
candidate and live image digest, and successful terminal Pod/container state. It requests
only that Pod and container's logs and accepts exactly one canonical schema-v2 JSON line. The
output path must be absent under an owner-controlled directory; publication is no-follow,
exclusive, atomic, single-link, and mode `0600`. Finally the normal
`BackupRestoreReceipt.load` parser rechecks the signed source-coordinate and receipt digests.
Any stale UID, extra Pod, restart, image drift, additional stdout, existing output, symlink,
or hard link blocks restore acceptance.

The restore ceiling is 100 GiB, so an archive above the single-request limit uses bounded
multipart streaming. `CreateMultipartUpload` carries the exact SSE-KMS algorithm and key
ARN; `UploadPart` and `CompleteMultipartUpload` do not carry those initiation headers, even
though S3 authorizes them as `s3:PutObject`. The workload role therefore has separate,
unconditioned exact-prefix `s3:PutObject` and `s3:AbortMultipartUpload` statements. Do not
add the legacy SSE request-header condition to either allow. Encryption remains fail-closed:
the live probe verifies the bucket's exact default KMS encryption and key policy, and every
completed upload is checked by exact VersionId, KMS key ARN, metadata checksum, length, and
content readback. On part failure the client invokes only the exact-prefix abort operation.
The signed bucket-control digest additionally binds `BucketOwnerEnforced`, the observed
versioning `MFADelete` state, and one positive incomplete-multipart expiry period on each of
the three exact lifecycle prefixes, so abandoned uploads cannot accumulate outside the
reviewed control plane.

Versioning alone is not treated as immutability. Before a production backup command can
succeed, it calls the S3 Object Lock retention API separately for the archive, manifest, and
sealed-receipt VersionId and requires a future GOVERNANCE or COMPLIANCE retain-until time.
The restore drill repeats all three exact-version retention reads at restore time and binds
the normalized mode/timestamp digests into its evidence; a bucket-level default or a bare
VersionId is not accepted as proof.
The backup workload policy and the acceptance/restore caller therefore require exact-prefix
`s3:GetObjectRetention`; neither receives cross-prefix write permission.

Restore the selected PostgreSQL custom dump only into an explicitly empty isolated database
whose name contains `restore_drill`. The drill runs `pg_restore --list`, restores in one
transaction, reapplies the exact runtime grants, and compares the restored tables, catalog,
RLS, sequences, and migration history only with the immutable backup-time fingerprint. It
does not query the current live source database for a comparison baseline, so legitimate
writes after backup cannot invalidate the drill. The configured source URL is still used to
bind the credential-free source coordinate in the signed receipt and managed-control-plane
evidence.

KMS key ARNs accept only exact `key/...` resources in `aws`, `aws-us-gov`, or `aws-cn` and
must match their configured region/account. For AWS RDS, both database resource ARNs and
each live `KmsKeyId` must share the same partition, account, and region. Preserve the RPO
check from the exported-snapshot timestamp: an already stale backup is rejected before any
restore, and its age is recomputed after all integrity/role checks so a long drill cannot pass
an expired RPO. The end-to-end RTO includes object fetch, database restore, and validation.
Never overwrite production in place. Delete the disposable target only after evidence
export, and switch traffic only after a two-person review records RPO/RTO and integrity
evidence.
