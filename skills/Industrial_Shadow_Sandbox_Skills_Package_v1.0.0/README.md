# Industrial Shadow Sandbox

Industrial Shadow Sandbox is a code-complete reference implementation for the 24-batch
skill package in `implement-industrial-shadow-sandbox`. It provides a deterministic
industrial simulator, OPC UA interoperability, lossless collection, diagnosis and causal
ranking, human approval, simulation-only actions, replay/evaluation/reporting, read-only
edge integration, and evidence-gated production deployment assets.

The non-negotiable boundary is enforced in code and deployment policy: real industrial
endpoints are read-only, while state-changing actions can reach registered simulators only.

## Runtime layout

- `backend/src/shadow_sandbox`: control API, domain services, worker, security, storage,
  evaluation, release, and operations.
- `services/simulator`: deterministic process model, snapshot/action API, and OPC UA server.
- `services/collector`: read-only collection and raw-event/Parquet persistence.
- `services/edge-gateway`: signed, allowlisted, read-only edge connector.
- `web`: Vue control and diagnosis console.
- `migrations`: ordered SQLite development and PostgreSQL production migrations.
- `deploy`: local Compose plus fail-closed Kubernetes production manifests.
- `docs/evidence/batch-01` through `batch-24`: command logs and digest-bound manifests.

## Local verification

Python 3.12 and Node.js are required.

```sh
python -m pip install --require-hashes -r backend/requirements.lock
npm --prefix web ci --ignore-scripts --no-audit --no-fund
make test lint typecheck python-audit sbom validate schemas client-contract
make web-test web-e2e web-build
make demo
make measured-benchmark
make smoke
```

`backend/requirements.lock` is a Python 3.12 universal, hash-verified lock covering runtime,
OPC UA, observability, object storage, testing, audit, and SBOM tooling. Regenerate it only
from the reviewed `backend/pyproject.toml`. The reduced, hash-verified
`backend/requirements.runtime.lock` contains only production runtime extras and is used by
the backend image, while CI uses the full lock; both installs use `--require-hashes`. The
Playwright suite uses local Chrome on macOS; Linux CI installs the pinned Playwright Chromium
build before running it.

`make smoke` is the package-level local closure path: it validates implementation and
batch contracts, runs Python lint/type checks and both dependency audits, generates a
reproducible CycloneDX runtime SBOM with root and transitive dependency edges, then runs Python, web-unit, six-persona browser,
and automated WCAG A/AA smoke suites, builds and audits the web bundle, renders the Compose
and Kubernetes deployment contracts,
executes a CLI demo against `.runtime/smoke.db`, and emits a local benchmark Gate result
under `artifacts/measured-benchmark/`. It also builds both images and verifies their
non-root, read-only runtime behavior, backend health/OpenAPI/build-digest contract, and web
security headers/source-map denial. Deployment rendering uses explicit contract-only
values and never starts services; real runtime secrets remain mandatory for deployment.

The historical results recorded in `IMPLEMENTATION_STATUS.yaml` predate the latest
production-closure hardening. The post-hardening full `make smoke` matrix has **not** been
run because the shared host is still inside an exclusive low-disk resource window; no new
large pytest, npm, image-build, or Docker workload is started while that window is active.
Those prior baselines are not presented as verification of the current tree.

For the real PostgreSQL adapter and RLS probe, point only at a disposable database owned by
a migration role:

```sh
SHADOW_TEST_POSTGRESQL_URL='postgresql+psycopg://...' make postgres-test
SHADOW_TEST_POSTGRESQL_URL='postgresql+psycopg://...' make evidence
```

The probe creates a temporary non-owner `NOBYPASSRLS` role and validates migration history,
tenant visibility, child rows, Outbox isolation, and workspace-scoped idempotency. Do not
run it against an application database containing production data.

For a local dump/restore integrity drill, create a separate empty database whose name
contains `restore_drill`, keep both URLs on loopback, and opt in explicitly:

```sh
SHADOW_TEST_POSTGRESQL_URL='postgresql+psycopg://.../shadow_test?sslmode=disable' \
SHADOW_TEST_RESTORE_POSTGRESQL_URL='postgresql+psycopg://.../shadow_restore_drill?sslmode=disable' \
SHADOW_ALLOW_LOCAL_RESTORE_DRILL=true make postgres-restore-test
```

The command refuses non-loopback URLs, a non-empty or ambiguously named target, a source
equal to the target, and invocations without the exact confirmation flag. It first creates
an exported-snapshot custom backup, then exercises the same version-bound receipt, catalog,
row, RLS, archive-size, RPO, and RTO restore path used by the production gate. Its
process-local object backend explicitly simulates version IDs, KMS, and Object Lock and the
result carries that limitation. It is local evidence only and does not substitute for live
S3/KMS/Object Lock or a managed PostgreSQL production gate.

## Deployment and release boundary

Render the production base with `kubectl kustomize deploy/production`; an environment
overlay must replace every fail-closed image, identity, certificate, network, and storage
placeholder. Follow `deploy/production/README.md` for database role separation and rollout
order.

`IMPLEMENTATION_STATUS.yaml` deliberately remains `implemented_unverified`. Local gates
cannot certify a production environment. `tools/check_release_evidence.py` will remain
blocked until digest-bound evidence for all target-environment gates and two distinct human
signatories is supplied. In particular,
`docs/evidence/batch-24/production-closure-input.json` is deliberately absent, so the
release check continues to fail closed with `RELEASE_BLOCKED` rather than manufacturing a
production pass, signature, certification, or external-acceptance record.

GitHub can discover six entrypoint workflows at the repository root: `ci.yml`,
`release.yml`, `production-acceptance.yml`, `production-closure.yml`,
`production-deploy.yml`, and `scheduled-closure-revalidation.yml`. They are
deterministically rendered from the six package templates and retain package-relative
working directories, exact workflow paths, immutable artifact names, and run-ID/run-attempt
bindings. `tools/check_root_workflow_sync.py` rejects missing, extra, symlinked, or drifted
root entrypoints; this activation is code and static-contract readiness, not evidence that
remote CI or a production workflow has run.

Every remaining target-environment gate has an executable harness in
`tools/production_gate.py`. The environment-protected
`.github/workflows/production-acceptance.yml` first verifies release attestations and the
signed formal target profile, then runs a non-mutating, fail-closed input preflight before
authorizing any target mutation. It subsequently runs live OIDC personas, an isolated managed
PostgreSQL restore, S3/KMS controls, external CA/CRL and real read-only OPC UA, plane-labelled
NetworkPolicy probes, measured load, controlled pod loss, exact image rollback, signed
security/privacy/human-accessibility assurance imports, authenticated Docker Scout scans
of both immutable backend and Web candidate images, a local diagnostic 174-Episode run, and an independently
signed formal target result set whose metrics and exact-bundle Gate are recomputed. See
`docs/runbooks/production-acceptance.md` before enabling the workflow. The separate
`.github/workflows/production-closure.yml` downloads one exact acceptance run by ID and
verifies the two-person signatures without rerunning or changing the evidence. All 17 source
gates are bound to one acceptance run, five exact release/environment coordinates
(including the sealed Kubernetes deployment-plan digest), and a
purpose-scoped assessor/approver trust-store digest. These controls improve code readiness;
they do not turn any unexecuted target gate into `PASSED`.

The live OIDC browser journey is produced only after preflight into a pristine,
runner-private output whose filename and payload bind the exact GitHub run attempt. Its v2
record binds the acceptance run, release, both image digests, build, simulator, target
environment, and sealed deployment plan, and the gate independently enforces freshness,
PKCE/JWS, logout, persona, and server-side RBAC results. The managed PostgreSQL restore gate
uses streaming, duplicate-sensitive row fingerprints and compares source and restore
catalog/ownership/ACL/default-ACL/RLS state before reporting equivalence, then reapplies and
checks the exact runtime and backup role privilege matrices.
The S3 gate performs its workload-identity checks inside distinct target Kubernetes backup
and snapshot Pods: exact RBAC and annotated service accounts, projected
`sts.amazonaws.com` tokens under the single EKS-standard `aws-iam-token` volume and
`/var/run/secrets/eks.amazonaws.com/serviceaccount` read-only mount,
`AssumeRoleWithWebIdentity`, purpose-specific KMS encryption
contexts, exact-version and listing denial across workload prefixes, and required
version/Object Lock disposition are all evidence inputs. These are fail-closed executable contracts only; live-provider OIDC,
managed PostgreSQL, and real S3/KMS target execution remain `NOT_RUN`.

After closure, `.github/workflows/production-deploy.yml` downloads that exact closure run,
re-verifies it, matches the sealed phased deployment plan and backend image, performs
server-side dry runs, runs the candidate-image migration Job, rolls out all seven workloads,
verifies exact image digests and HTTPS readiness, and reapplies the digest-pinned prior
manifest if rollout fails. Plan loading rejects cluster-scoped/RBAC/Secret resources,
out-of-namespace objects, undeclared workloads, mutable or unbound runtime images, and
non-restricted Pod security; rollback also verifies the exact prior image digests and
readiness. The prior-state manifest must exactly cover every object changed by bootstrap
and runtime. Before the first candidate mutation, the publisher persists a run-attempt-bound
recovery envelope and records `candidate_mutation_started`; the workflow schedules a
separately confirmed same-run recovery step for failure or cancellation. Recovery validates
the binding, envelope, and ordered journal, safely no-ops when no mutation began, and restores
the exact prior manifest after an interrupted mutation. A separate break-glass path accepts
only a closure-bound failed or cancelled prior deployment artifact and requires the rollback
confirmation. The workflow requires a separately protected deployment environment and exact
`<namespace>:<plan-id>:deploy` confirmation. No target deployment, interruption drill, or
rollback has yet been executed by this repository.
