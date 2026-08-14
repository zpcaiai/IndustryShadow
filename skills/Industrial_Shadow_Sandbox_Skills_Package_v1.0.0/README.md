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
equal to the target, and invocations without the exact confirmation flag. It verifies a
custom-format dump, migration history, per-table row fingerprints, RLS policy inventory,
catalog integrity, archive size, and restore RTO. It is local evidence only and does not
substitute for the managed PostgreSQL production gate.

## Deployment and release boundary

Render the production base with `kubectl kustomize deploy/production`; an environment
overlay must replace every fail-closed image, identity, certificate, network, and storage
placeholder. Follow `deploy/production/README.md` for database role separation and rollout
order.

`IMPLEMENTATION_STATUS.yaml` deliberately remains `implemented_unverified`. Local gates
cannot certify a production environment. `tools/check_release_evidence.py` will remain
blocked until digest-bound evidence for all target-environment gates and two distinct human
signatories is supplied.

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

After closure, `.github/workflows/production-deploy.yml` downloads that exact closure run,
re-verifies it, matches the sealed phased deployment plan and backend image, performs
server-side dry runs, runs the candidate-image migration Job, rolls out all seven workloads,
verifies exact image digests and HTTPS readiness, and reapplies the digest-pinned prior
manifest if rollout fails. Plan loading rejects cluster-scoped/RBAC/Secret resources,
out-of-namespace objects, undeclared workloads, mutable or unbound runtime images, and
non-restricted Pod security; rollback also verifies the exact prior image digests and
readiness. The prior-state manifest must exactly cover every object changed by bootstrap
and runtime, and compensation begins on the first mutating apply, including partial
bootstrap or migration failure. The workflow requires a separately protected deployment
environment and exact `<namespace>:<plan-id>:deploy` confirmation.
