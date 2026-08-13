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

The workflow first runs the non-mutating `preflight` gate. It validates every required
input, file permission, binary, release/environment digest, HTTPS/TLS endpoint, disposable
restore target, exact drill confirmation, policy-plane coverage, placeholder removal, and
trusted signer purpose. A failed preflight writes digest-sealed `FAILED` evidence and stops
before any restore, load, chaos, or rollout mutation.

1. Confirm the source database URL and the empty restore target are different. The restore
   tool refuses any target name without `restore_drill` and refuses a non-empty target.
2. Confirm current and candidate images are distinct `@sha256:` references. The rollback
   drill always restores the captured current digest in a `finally` path.
3. Confirm the selected Deployment has at least two desired and available replicas before
   pod-loss injection.
4. Confirm the OPC UA account, certificate, NodeId list, and CNI route expose only
   Browse/Read/Subscribe. The real probe has no Write, Call, or HistoryUpdate method.
5. Confirm OIDC and load bearer files are owned by the runner account with mode `0600`.
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
9. Supply a runner-owned Docker Scout credential JSON with mode `0400` or `0600` and the
   exact keys `username` and `personal_access_token`. The probe authenticates inside an
   ephemeral Docker configuration, scans both immutable backend and Web digests from the
   sealed deployment plan for all critical and high findings, retains separate SARIF
   reports, and deletes the temporary login state. Missing Docker ID authentication or any
   finding blocks closure.

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
```

The checked-in `assessor-trust-store.example.json` is deliberately unusable in production.
The protected runner supplies its approved replacement through
`SHADOW_ASSESSOR_TRUST_STORE`; the exact trust-store digest is included in the approval
digest and rechecked during closure.

Independent assessors can construct the v2 report without hand-calculating artifact hashes
or signatures by using `tools/build_external_assurance_report.py`. Its checks JSON must cover
the exact required control names enforced by `ExternalAssuranceImporter.REQUIRED_CHECKS`;
every `--artifact` must be a regular repository evidence file. The builder rejects an
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
  --episode-results docs/evidence/batch-24/production/formal-benchmark/episodes.json \
  --measurement-log docs/evidence/batch-24/production/formal-benchmark/measurement.log \
  --target-profile docs/evidence/batch-24/production/formal-benchmark/target-profile.json \
  --private-key /approved/evaluator-ed25519.pem \
  --trust-store /approved/assessor-trust-store.json \
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
manifest. Its plan lists all six
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
The uploaded evidence includes the v2 signed security/privacy/accessibility reports, both
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
  --output /approved/closure-signatories.json || test $? -eq 2

python tools/sign_production_approval.py --append \
  --approval-request docs/evidence/batch-24/production/approval-request.json \
  --identity security-owner@example.org --role security_owner \
  --private-key /approved/security-owner.pem \
  --trust-store docs/evidence/batch-24/production/assessor-trust-store.json \
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
backend digest, rolls out all six workloads, and checks exact observed images plus HTTPS
readiness. Any runtime rollout or readiness failure reapplies the prior manifest and waits
for every rollback rollout before returning failed evidence. This workflow remains NOT_RUN
until a real closure artifact and target cluster are supplied.

Never sign evidence from one run and attach it to a second run. The closure builder and
independent checker require all 15 source gates to carry the same acceptance run ID and
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
- If the Kubernetes workflow is interrupted outside its `finally` path, deploy the captured
  rollback digest and run `kubectl rollout status` before reopening traffic.
- Any real write attempt, Gold exposure, unauthorized action, evidence digest mismatch, or
  missing second signature blocks release without waiver.
