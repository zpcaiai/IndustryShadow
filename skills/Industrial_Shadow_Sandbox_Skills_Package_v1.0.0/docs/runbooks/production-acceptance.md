# Production acceptance and closure

Run these gates only from the isolated `industrial-shadow-acceptance` runner after an
environment approval. The runner needs read-only access to real OT, workload identity for
the dedicated S3/KMS probe prefix, owner access to an explicitly empty database whose name
contains `restore_drill`, and narrowly scoped Kubernetes permissions for probe Pods and the
approved Deployment drill.

First dispatch `release.yml`. It runs the local regression/audit/build gates and publishes
backend and web candidates to GHCR with source-revision tags, provenance, and SBOMs. Consume
only the `@sha256:` references in its `immutable-release-candidate` artifact; a tag alone is
never an acceptance or deployment coordinate. Candidate publication is not production
deployment and does not require or create closure evidence.

## Safety preflight

The workflow first verifies release provenance/SBOM attestations and independently imports
the signed formal benchmark, then runs the non-mutating `preflight` gate. Preflight validates
every required input, file permission, binary, release/environment digest, HTTPS/TLS
endpoint, disposable restore target, exact drill confirmation, policy-plane coverage,
placeholder removal, and trusted signer purpose. A separate prerequisite summary requires
all three gates to be v2 `PASSED`, limitation-free, and bound to the same acceptance run and
release before any live OIDC, database, storage, OT, network, load, chaos, or rollout probe.

1. Confirm the source database URL and the empty restore target are different. The restore
   tool refuses any target name without `restore_drill` and refuses a non-empty target.
2. Confirm current and candidate images are distinct `@sha256:` references. The rollback
   drill always restores the captured current digest in a `finally` path.
3. Confirm the selected Deployment has at least two desired and available replicas before
   pod-loss injection.
4. Confirm the OPC UA account, certificate, NodeId list, and CNI route expose only
   Browse/Read/Subscribe. The real probe has no Write, Call, or HistoryUpdate method.
5. Confirm OIDC and load bearer files are runner-owned, single-link regular files with
   exact mode `0400` or `0600`. The browser reader opens the OIDC secret with
   `O_NOFOLLOW`, performs a bounded read through that one descriptor, and rejects any
   owner, mode, link-count, size, inode, modification-time, or change-time drift between
   its before/after `fstat` calls.
6. Replace every TEST-NET and `.invalid` value in the environment overlay. Unchanged
   examples are expected to fail.
7. Stage a signed formal benchmark bundle containing sanitized results for the exact 174
   Episode suite, the target measurement log, and the declared hardware profile. The
   importer recomputes metrics, per-fault slices, red lines, and the Release Gate; the local
   deterministic benchmark is diagnostic evidence only and cannot satisfy production
   closure.
8. Set `SHADOW_ACCEPTANCE_RUN_ID` once for the workflow and bind the candidate image,
   application build, simulator build, target-profile digest, and sealed Kubernetes
   deployment-plan digest as the five release coordinates. Every production gate emits v2
   evidence carrying the same run ID and release digest; mixed-run or mixed-release evidence
   is rejected.
   Set `SHADOW_OIDC_BROWSER_JOURNEY` only to
   `web/test-results/production-oidc-journey-${SHADOW_ACCEPTANCE_RUN_ID}.json`. Preflight
   validates that pristine output target and does not require a browser result before
   Playwright runs. The workflow removes only that run-attempt-qualified target, and the
   browser creates it without overwriting an existing file. Its version 2 payload carries
   the exact acceptance run ID, release digest, backend/Web image digests, build and
   simulator digests, target-profile digest, and deployment-plan digest. Run the OIDC gate
   immediately afterward: it rejects a mismatched binding, a future completion time, or a
   completion more than ten minutes before the gate started. The gate reopens the final
   `0600`, single-link result with the same bounded, non-following descriptor discipline.
   A result from another run or an earlier attempt cannot satisfy production OIDC evidence.
9. Supply a runner-owned Docker Scout credential JSON with mode `0400` or `0600` and the
   exact keys `username` and `personal_access_token`. The probe authenticates inside an
   ephemeral Docker configuration, scans both immutable backend and Web digests from the
   sealed deployment plan for all critical and high findings, retains separate SARIF
   reports, and deletes the temporary login state. Missing Docker ID authentication or any
   finding blocks closure.
   Supply the candidate registry credential separately through
   `SHADOW_IMAGE_REGISTRY_CREDENTIALS_FILE`; for Docker Hub images its identity and token
   must exactly match the Docker ID credential so a second login cannot replace Scout
   authentication. GHCR acceptance also requires the workflow-scoped `GH_TOKEN` for
   attestation verification.
10. Treat the runner-side `production-probes` write as a separate, one-run mutation.
    After the acceptance workflow exposes its run ID and attempt, but before approving the
    `production-acceptance` environment, provision
    `SHADOW_PRODUCTION_S3_CONTROL_PLANE_CONFIRMATION` in that environment. Its exact value
    is the canonical digest returned below; it binds the signed target-profile digest,
    signed bucket and acceptance prefix, and `${github.run_id}-${github.run_attempt}`. A
    value copied from another run, bucket, prefix, or target profile is rejected. The probe
    completes the bucket-owner/location/public-access/TLS/versioning/KMS/rotation/Object
    Lock checks, all three lifecycle-prefix checks, and both pre-created immutable sentinel
    bindings before it compares this confirmation or performs any `PutObject`/`DeleteObject`:

    ```sh
    PYTHONPATH=backend/src python - <<'PY'
    import os
    from shadow_sandbox.operations.storage_probe import s3_control_plane_mutation_confirmation

    print(s3_control_plane_mutation_confirmation(
        bucket=os.environ["SHADOW_OBJECT_STORAGE_BUCKET"],
        prefix=os.environ["SHADOW_OBJECT_STORAGE_PREFIX"],
        acceptance_run_id=os.environ["SHADOW_ACCEPTANCE_RUN_ID"],
        signed_target_profile_digest=os.environ["SHADOW_PRODUCTION_ENVIRONMENT_DIGEST"],
    ))
    PY
    ```

11. Supply `SHADOW_PRODUCTION_S3_WORKLOAD_IDENTITY_CONFIRMATION` as the exact
    `<namespace>:s3-workload-identity-probe` secret. The gate creates two bounded Jobs in
    the signed target namespace, runs them with the sealed backup and snapshot
    ServiceAccounts and their ambient workload identities, then foreground-deletes the
    Jobs and verifies that no owned Pods remain. Before the first Job mutation, it verifies
    the storage context's exact RBAC and both raw ServiceAccount role annotations. Each live
    Pod must contain only the audience-bound IRSA token projection and read-only mount,
    regional S3/STS coordinates, and an explicit IMDS prohibition. Runner profiles and
    runner-side WebIdentity token files are not accepted as workload evidence. Configure
    `SHADOW_REQUIRE_OBJECT_LOCK=true`; both Jobs pass that exact contract into the
    inside-Pod probe, treat retained-version delete denial as safe disposition without
    calling the retention API, and use the workload-specific KMS encryption context
    `{"application":"industrial-shadow","purpose":"backup"}` or
    `{"application":"industrial-shadow","purpose":"snapshot"}`.
    Configure
    distinct signed
    `SHADOW_BACKUP_OBJECT_STORAGE_PREFIX`, `SHADOW_SNAPSHOT_OBJECT_STORAGE_PREFIX`, and
    acceptance-only `SHADOW_OBJECT_STORAGE_PREFIX` values plus a
    pre-created forbidden sentinel under the opposite prefix for each identity. Both roles
    must complete a version-pinned KMS round trip and receive AccessDenied for the
    cross-prefix sentinel. The sealed/live `storage-identity-probe-egress` NetworkPolicy
    must resolve its fail-closed endpoint placeholders to the exact regional S3 and STS
    HTTPS addresses before the network gate authorizes either Job.
12. Configure four distinct kubeconfig contexts for the same signed cluster:
    `SHADOW_KUBERNETES_NETWORK_CONTEXT`, `SHADOW_KUBERNETES_STORAGE_CONTEXT`,
    `SHADOW_KUBERNETES_CHAOS_CONTEXT`, and `SHADOW_KUBERNETES_ROLLBACK_CONTEXT`.
    Each gate independently verifies the cluster UID and API CA, then requires its own
    exact least-privilege RBAC set. A shared over-privileged acceptance identity is rejected.

## Trusted signer registry

External reports do not become trusted merely because their embedded Ed25519 signature is
valid. Before acceptance, security assessor, privacy assessor, human accessibility
assessor, measurement assessor, release owner, and security owner public-key fingerprints
must be allowlisted in one
`schemas/production/assessor-trust-store-v1.json` document. Purposes and validity windows
are checked independently and revoked entries never verify. Build the public, digest-bound
registry from an input whose `digest` is empty:

```sh
python tools/seal_signer_trust_store.py \
  --input /approved/trust-store-draft.json \
  --output /approved/assessor-trust-store.json
python tools/sign_trust_store_root.py \
  --trust-store /approved/assessor-trust-store.json \
  --private-key /offline/trust-root-ed25519.pem \
  --public-key-output /approved/assessor-trust-root-public-key.pem \
  --output /approved/assessor-trust-root-attestation.json
```

Pin the emitted SHA-256 of the raw 32-byte public key in the protected
`SHADOW_ASSESSOR_TRUST_ROOT_KEY_SHA256` variable. The detached root approval must be renewed
at least annually; stale or untimely root approvals fail closed.

The checked-in `assessor-trust-store.example.json` is deliberately unusable in production.
The protected runner supplies its approved replacement through
`SHADOW_ASSESSOR_TRUST_STORE`; a detached offline-root signature and separately pinned root
fingerprint are mandatory. The exact trust-store digest is included in the approval digest
and rechecked during closure.

Independent assessors can construct the v3 report without hand-calculating artifact hashes
or signatures by using `tools/build_external_assurance_report.py`. Its checks JSON must cover
the exact required control names enforced by `ExternalAssuranceImporter.REQUIRED_CHECKS`;
every `--artifact` must be a structured JSON evidence file whose `artifact_kind` matches one
required control. The builder rejects an
untrusted assessor key before writing a report. The `accessibility` report is an independent
human review of WCAG AA, keyboard navigation, screen-reader behavior, focus order, contrast,
zoom/reflow, error identification, and remediation; the automated Playwright/axe result is
supporting evidence only.
Each external report must use `--deployment-plan-digest` with the same sealed value supplied
to acceptance, so security, privacy, and accessibility approval cannot be moved to a
different web image or Kubernetes manifest bundle.

The formal evaluator writes `episodes.json` against
`schemas/production/formal-benchmark-results-v1.json`, a measurement log against
`formal-measurement-log-v1.json`, and a target hardware/profile JSON against
`target-profile-v1.json`. The log must list the exact 174 planned and completed Episode IDs,
an empty failed set, the result digest, and the target-profile digest. Its `run_id`,
`started_at`, and `completed_at` must exactly equal the report's benchmark ID and time range.
With an Ed25519 private key
restricted to the evaluator account (`0400` or `0600`), build the signed report as follows:

```sh
python tools/build_formal_benchmark_report.py \
  --candidate-image 'registry.example/image@sha256:...' \
  --build-digest '...' --simulator-build-digest '...' \
  --deployment-plan-digest "$SHADOW_DEPLOYMENT_PLAN_DIGEST" \
  --episode-results docs/evidence/batch-24/production/formal-benchmark/episodes.json \
  --measurement-log docs/evidence/batch-24/production/formal-benchmark/measurement.log \
  --target-profile docs/evidence/batch-24/production/formal-benchmark/target-profile.json \
  --private-key /approved/evaluator-ed25519.pem \
  --trust-store /approved/assessor-trust-store.json \
  --trust-root-attestation /approved/assessor-trust-root-attestation.json \
  --trust-root-public-key /approved/assessor-trust-root-public-key.pem \
  --trust-root-key-sha256 "$SHADOW_ASSESSOR_TRUST_ROOT_KEY_SHA256" \
  --benchmark-id target-2026-08 --assessor independent-evaluator \
  --started-at '2026-08-06T00:00:00Z' --completed-at '2026-08-06T01:00:00Z' \
  --output docs/evidence/batch-24/production/formal-benchmark/report.json
```

The signer never receives or emits cause labels: each fault result carries only the rank of
the sealed expected cause. The importer joins Episode IDs to evaluator-side suite metadata,
rejects missing/duplicate/extra Episodes, and recomputes all metrics and slice thresholds.

## Sealed deployment plan

The deployment bundle is not a mutable overlay path. The target namespace and runtime
Secrets are pre-provisioned outside the release identity. The bundle contains four distinct,
rendered and reviewed YAML files: namespace-scoped bootstrap resources, a release-unique
migration Job, the candidate runtime manifest, and the exact prior-release rollback
manifest. Its plan lists all seven
workloads, exact backend/web image digests, HTTPS readiness URLs for API/web, every artifact
SHA-256, target namespace, and migration Job name. Seal the draft only after those rendered
files are final:

```sh
python tools/seal_production_deployment_plan.py \
  --input docs/evidence/batch-24/production-deployment/deployment-plan.draft.json \
  --output docs/evidence/batch-24/production-deployment/deployment-plan.json
```

Set `SHADOW_DEPLOYMENT_PLAN_DIGEST` to the emitted digest. Production preflight reopens every
manifest, verifies its hash, rejects mutable image tags and incomplete workload coverage,
and binds the plan digest into every source gate's release digest. The loader also enforces
phase-specific namespaced resource allowlists, one exact container per declared runtime
workload, restricted Pod/container security contexts, current-image binding, and immutable
single-image backend/Web rollback sets. The rollback manifest must exactly cover the union
of bootstrap and runtime resource identities; the publisher applies it for failures from
the first mutating bootstrap call onward, then verifies prior workload images and readiness.

## Evidence sequence

Dispatch `.github/workflows/production-acceptance.yml`. It executes
all source gates, uploads `docs/evidence/batch-24/production`, and emits
`approval-request.json`. Failed or missing probes never produce a verified closure input.
The uploaded evidence includes the v3 signed security/privacy/accessibility reports, both
Docker Scout SARIF reports, the formal-benchmark report, and every digest-bound source
artifact; the closure checker re-verifies all external signatures and both scan evidence
digests.

The release owner and security owner independently sign the ASCII `approval_digest` with
Ed25519. Each owner reviews the exact `approval-request.json` and uses a distinct `0400` or
`0600` key. The helper validates the approval digest, trust-store digest, key fingerprint,
role, and key type before signing; the second invocation atomically appends and verifies the
two-person set:

```sh
python tools/sign_production_approval.py \
  --approval-request docs/evidence/batch-24/production/approval-request.json \
  --identity release-owner@example.org --role release_owner \
  --private-key /approved/release-owner.pem \
  --trust-store docs/evidence/batch-24/production/assessor-trust-store.json \
  --trust-root-attestation docs/evidence/batch-24/production/assessor-trust-root-attestation.json \
  --trust-root-public-key docs/evidence/batch-24/production/assessor-trust-root-public-key.pem \
  --trust-root-key-sha256 "$SHADOW_ASSESSOR_TRUST_ROOT_KEY_SHA256" \
  --output /approved/closure-signatories.json || test $? -eq 2

python tools/sign_production_approval.py --append \
  --approval-request docs/evidence/batch-24/production/approval-request.json \
  --identity security-owner@example.org --role security_owner \
  --private-key /approved/security-owner.pem \
  --trust-store docs/evidence/batch-24/production/assessor-trust-store.json \
  --trust-root-attestation docs/evidence/batch-24/production/assessor-trust-root-attestation.json \
  --trust-root-public-key docs/evidence/batch-24/production/assessor-trust-root-public-key.pem \
  --trust-root-key-sha256 "$SHADOW_ASSESSOR_TRUST_ROOT_KEY_SHA256" \
  --output /approved/closure-signatories.json
```

The resulting versioned file contains distinct identity, role, `approved=true`, approval
digest, timezone-aware `signed_at`, base64 raw public key, and base64 signature. Both keys
and role purposes must match the same trust store. Store that file in the protected
acceptance runner path referenced by the `SHADOW_CLOSURE_SIGNATORIES_FILE` environment
secret. Dispatch
`.github/workflows/production-closure.yml` with the successful acceptance run ID. The closure
workflow downloads that exact immutable artifact set instead of rerunning probes, then
`build_production_closure.py` revalidates all artifacts and signatures and
`check_release_evidence.py` independently repeats the verification.

After closure succeeds, dispatch `.github/workflows/production-deploy.yml` with the closure
run ID. Its protected self-hosted runner must hold only narrowly scoped patch/get/wait
permissions and the exact `<namespace>:<plan-id>:deploy` confirmation. The publisher repeats
closure verification, performs server-side dry runs for candidate and rollback manifests,
applies bootstrap then the release-unique migration Job, verifies that Job uses the approved
backend digest, rolls out all seven workloads, and checks exact observed images plus HTTPS
readiness. Any runtime rollout or readiness failure reapplies the prior manifest and waits
for every rollback rollout before returning failed evidence. This workflow remains NOT_RUN
until a real closure artifact and target cluster are supplied.

Each deployment writes an immutable `deployment-binding.json` before cluster mutation. It
binds the exact signed closure input and approval digests, release and deployment-plan
digests, target cluster UID and API CA digests, current candidate images, sealed rollback
image set, repository, checked-out source revision, closure workflow run and run attempt,
immutable closure artifact ID and SHA-256 digest, and deployment workflow run and run
attempt. The workflow requires exactly one non-expired closure artifact whose creation
time falls inside the selected latest run attempt; a constant-name artifact left by an
older rerun attempt fails closed. Before the first mutating `kubectl`, an immutable recovery
envelope binds that record to the workflow run, closure, plan, namespace, cluster UID, and
API CA. The publisher then fsyncs `candidate_mutation_started` before its first apply, so a
terminated process cannot misclassify a partial apply as a no-op. A final execution envelope
binds the immutable record to the digest-valid deployment evidence and completed journal by
their SHA-256 digests.

On a failed or cancelled deploy step, the same workflow attempt invokes the separately
authorized recovery entry point with the exact `<namespace>:<plan-id>:rollback` protected
secret. It validates the original binding, recovery envelope, and strict journal before any
write. A journal that is only an authentic read-only preflight prefix produces a verified
no-op; an unfinished mutation restores the sealed prior bundle; an already completed
rollback is read back without another apply. Each outcome receives its own binding,
recovery envelope, journal, evidence, and final execution envelope. The original deploy
failure/cancellation remains visible even when recovery succeeds.

For later recovery, select `restore-prior-bundle`, supply the failed or cancelled deployment
run ID, and provide that same rollback-specific secret. The workflow downloads the exact
run-attempt-qualified artifact. A normally failed run must contain digest-valid failed
deployment evidence plus its final execution envelope. A cancelled run may lack those final
files, but it is eligible only when its immutable recovery envelope and strict journal prove
that candidate mutation began and the rollback remains unfinished. The new restore binding
also records the selected prior artifact ID and SHA-256 digest. A deploy authorization cannot
call either recovery entry point, a rollback authorization cannot publish candidate
manifests, and a completed deployment/rollback or mismatched candidate, plan, closure, run,
artifact, source, or cluster blocks recovery before Kubernetes mutation.

The repository-visible weekly `.github/workflows/scheduled-closure-revalidation.yml`
entrypoint is rendered from the package `recertification.yml` template and deliberately
named `scheduled-closure-revalidation`. It re-runs deterministic/policy checks and verifies the
previously signed closure only after applying the same exact run-attempt, artifact ID,
artifact SHA-256, source revision, and creation-time checks, then publishes a status
artifact that keeps
`live_production_recertification=NOT_RUN`. It is not a new production acceptance, external
review, human sign-off, or certification. Those require a fresh release candidate,
production-acceptance run, signed closure, and their new evidence.

Never sign evidence from one run and attach it to a second run. The closure builder and
independent checker require all 17 source gates to carry the same acceptance run ID and
release digest, verify evidence freshness, and bind all report, artifact, trust-store, and
release-coordinate digests into the approval.

Do not commit bearer values, database URLs, private keys, raw OT samples, customer
identifiers, or unredacted penetration reports. Evidence stores only target-coordinate
digests, bounded metrics, signed assessor statements, and artifact hashes.

## Cleanup and rollback

- Delete the disposable restored database after evidence export; the tool deliberately
  retains it so an operator can inspect it first.
- With Object Lock disabled, the S3 probe removes every version and delete marker for its
  random object key. With required default retention enabled, the immutable 4 KiB random
  probe version is deliberately retained and must expire through the verified lifecycle
  policy; attempting to bypass retention would invalidate the control being tested.
- Network probe Pods are deleted in a `finally` path.
- Let the same-run recovery step finish whenever a deployment step fails or is cancelled;
  it uses the rollback-specific confirmation and never clears the original workflow
  outcome. If the journal proves an unfinished mutation after that attempt, use
  `restore-prior-bundle` with the exact failed/cancelled run artifact. Normal failures require
  final failed evidence and an execution envelope; cancellation recovery requires the
  immutable activation envelope and strict unfinished journal. Missing or inconsistent
  records fail closed, so the incident commander must use the separately reviewed cluster
  recovery procedure rather than fabricating resumable evidence.
- Any real write attempt, Gold exposure, unauthorized action, evidence digest mismatch, or
  missing second signature blocks release without waiver.
