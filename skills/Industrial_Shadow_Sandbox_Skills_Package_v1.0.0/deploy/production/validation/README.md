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
also feed the read-only client security string. Database URLs are environment secrets.

The NetworkPolicy suite first verifies the runner's narrow probe RBAC and exact live-vs-approved
policy set/specification. It then launches short-lived, credential-free pods with the same `app`
labels as each production plane, verifies allowed and denied destinations, captures
digest-bound results, and deletes each probe pod. The exact confirmation value must be
`<namespace>:network-policy`.

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
flags. Their signed reports and every referenced artifact are copied into production
evidence, re-imported before the approval digest is built, and independently re-imported by
the final release checker. All three external assurance reports use v2 and bind the exact
candidate, build, target environment, required control coverage, approved assessor key, and
90-day freshness window. Automated browser checks do not satisfy the human accessibility
gate.

The Docker Scout credentials file is a runner-owned `0400` or `0600` JSON object containing
only `username` and `personal_access_token`. The probe uses an isolated temporary Docker
configuration, targets the exact backend and Web `@sha256:` references from the sealed
deployment plan, retains a separate SARIF report for each image, and fails on any critical
or high finding. Missing Docker ID authentication never becomes a PASS.
