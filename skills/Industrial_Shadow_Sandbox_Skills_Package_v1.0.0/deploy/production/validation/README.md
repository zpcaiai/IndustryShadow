# Production acceptance inputs

These files are environment-owned inputs for `.github/workflows/production-acceptance.yml`.
The checked-in files use documentation-only addresses and digest placeholders, so running
them unchanged must fail closed. An approved overlay replaces them on the isolated
`industrial-shadow-acceptance` runner.

The workflow variables `SHADOW_OPCUA_PROBE_CONFIG`, `SHADOW_NETWORK_PROBE_CONFIG`,
`SHADOW_LOAD_PROBE_CONFIG`, `SHADOW_KUBERNETES_DRILL_CONFIG`, and
`SHADOW_CHAOS_DRILL_CONFIG` must point to approved target-owned replacements; the checked-in
examples are not used as production defaults. `SHADOW_PRODUCTION_DEPLOYMENT_PLAN` points to
the sealed phased manifest plan and `SHADOW_DEPLOYMENT_PLAN_DIGEST` is one of the five
closure-bound release coordinates.

Secret material is never stored here. OIDC persona bearer values and load-probe credentials
are runner-readable files with mode `0400` or `0600`. Current and next OPC UA client private
keys are separately supplied so the CA gate can prove certificate/key pairing; their paths
also feed the read-only client security string. The real-OT probe config separately binds the
server certificate fingerprint, client certificate fingerprint, client ApplicationUri, and
NodeId allowlist. Its evidence records a canonical NodeId allowlist digest and must match the
external-CA evidence on server/client fingerprints, client ApplicationUri, and security
policy. This is identity/permission evidence only: the probe never attempts a trial Write or
Method Call. Database URLs are environment secrets.

The independently signed formal target profile records both
`cluster_uid_digest = sha256(canonical_json({api_server_ca_sha256,
kube_system_namespace_uid}))` and the separate `kubernetes_api_ca_digest`. Every live
Kubernetes gate resolves these values through its separately approved network, storage,
chaos, or rollback context; the publisher uses its own deployment context. A namespace UID,
API CA, context, or plan namespace mismatch fails before mutation, and each gate rejects a
credential whose exact least-privilege RBAC set belongs to another gate.

The NetworkPolicy suite first verifies the runner's narrow probe RBAC and exact live-vs-approved
policy set/specification. The same parser used by deployment-plan loading checks the storage
policy's canonical, digest-bound regional S3/STS endpoint and CIDR assignment. The live gate
then independently resolves both canonical A/AAAA sets and requires exact equality with the
two TCP/443 rules; it records the resolution-set digest and fails closed on DNS errors or
drift. It then launches short-lived, credential-free pods with the same `app`
labels as each production plane, verifies allowed and denied destinations, captures
digest-bound results, and deletes each probe pod. The exact confirmation value must be
`<namespace>:network-policy`.
If either regional endpoint rotates, the operator must regenerate the exact sorted CIDR sets,
canonical contract annotation, manifest digest, and deployment-plan digest and then obtain new
target-profile/release signatures. Editing the live policy or reusing the old signed bundle is
not an accepted recovery path.
The storage selector is shared only by the simulator, backup CronJob, and the two bounded
storage-identity Jobs. Candidate and rollback parsing rejects a missing label, opt-in by any
other workload, or a second storage route in the legacy simulator/data-job policies.
The suite has distinct `real-ot-collector` and `simulator-collector` probes. The former must
reach only the reviewed OT host (plus PostgreSQL) and must not reach the simulator; the latter
must reach the simulator and must not reach the real-OT host.

The external-CA gate requires current and next server/client leaf certificates, URI SANs,
distinct pinned SHA-256 fingerprints, a currently valid CRL, EKU/KeyUsage, strong keys,
purpose-valid chains, and matching current/next client private keys. Server private keys
remain outside the acceptance runner.

The resilience and rollback drill requires `<namespace>:<deployment>` confirmation, at
least two available replicas, digest-pinned current/candidate images, and a maintenance
database role. The rollback image is captured from the live Deployment and restored in a
`finally` path even when candidate readiness fails.

Security, privacy, human accessibility, and formal benchmark inputs are directory bundles,
not bare `PASSED`
flags. Their signed reports and every referenced structured artifact are copied into production
evidence, re-imported before the approval digest is built, and independently re-imported by
the final release checker. All three external assurance reports use v3 and bind the exact
candidate, build, target environment, required control coverage, one structured artifact per
control, approved assessor key, and
90-day freshness window. Automated browser checks do not satisfy the human accessibility
gate.

The Docker Scout credentials file is a runner-owned `0400` or `0600` JSON object containing
only `username` and `personal_access_token`. The probe uses an isolated temporary Docker
configuration, targets the exact backend and Web `@sha256:` references from the sealed
deployment plan, retains a separate SARIF report for each image, and fails on any critical
or high finding. Missing Docker ID authentication never becomes a PASS.

S3 workload-identity acceptance uses a dedicated, least-privilege Kubernetes context. It
first proves exact RBAC, the signed cluster UID/API CA, and the two live ServiceAccount role
annotations without mutation. It then creates one bounded Job per identity, requires the
admission result to contain only the exact audience-bound IRSA token projection and regional
AWS endpoints with IMDS disabled, validates the candidate image ID and sealed evidence, and
foreground-deletes both Jobs and all owned Pods. Runner profiles and runner-side WebIdentity
token files are not evidence. The two forbidden sentinel keys must already exist under the
opposite workload prefix and must not be readable by the identity being tested.
The long-running simulator snapshot and backup CronJob separately disable ambient
ServiceAccount automount and use the same exact audience-bound projection shape. Each literal
role ARN must match its sealed ServiceAccount annotation in both candidate and rollback
bundles. Regional STS and the `us-east-1` regional S3 mode are mandatory; acceptance Jobs do
not retroactively prove that long-running workload contract. All three workload classes pin
shared AWS config/credential files to `/dev/null`; long-running ConfigMap imports cannot add
AWS, Boto, proxy, or CA-bundle overrides.
The shared shape is the EKS IAM webhook convention: volume `aws-iam-token`, read-only mount
`/var/run/secrets/eks.amazonaws.com/serviceaccount`, token file `token`, audience
`sts.amazonaws.com`, expiration 3600 seconds, and mode `0400`. Admission must recognise that
existing projection and may not leave a second projected token volume or mount.
