# Industrial Shadow Sandbox system contract

## Purpose

Implement a platform that can simulate industrial processes, inject reproducible faults, collect OPC UA data, generate evidence-backed diagnoses, obtain human approval for simulation-only checks or recovery, replay the same input, and evaluate every algorithm version. It is not a real-device autonomous control system.

## Stable vocabulary

- **Asset Model**: versioned hierarchy and semantics for sites, units, equipment, components, signals, units, and topology.
- **Process Model**: executable simulator equations and parameters.
- **Scenario Spec**: non-secret operating profile, timeline, disturbances, and injected faults used by the runtime.
- **Gold Spec**: evaluator-only root causes, expected symptoms, required checks, safety-critical steps, and forbidden actions.
- **Episode**: one deterministic execution of a scenario with one seed and immutable version manifest.
- **Run**: orchestrated record for an Episode, replay, suite, or experiment variant.
- **Symptom**: normalized abnormal behavior with time window, severity, quality state, related signals, and evidence references.
- **Evidence**: immutable, hash-addressed observation derived from raw samples through a versioned transformation.
- **Hypothesis**: candidate root cause with evidence score, support, contradiction, missing observations, and rank.
- **Check Plan**: ordered, typed diagnostic checks with cost, risk, expected information, preconditions, and rollback.
- **Approval**: immutable decision bound to the exact plan hash and validity window.
- **Virtual Action**: type-safe check or recovery supported only by a registered simulator.
- **Replay**: rerun of selected pipeline stages over a frozen dataset.
- **Release Gate**: non-bypassable policy combining quality thresholds with absolute safety red lines.
- **Domain Pack**: versioned assets, semantics, models, faults, causal graph, detectors, checks, scenarios, Gold, and report labels for one industrial domain.

## Hard invariants

1. Real endpoint data access is Browse/Read/Subscribe only.
2. Simulator and real endpoint identities, certificates, credentials, services, networks, and interfaces remain separate.
3. Gold is stored and served through an evaluator-only boundary.
4. No action executes without a valid approval bound to the unchanged plan.
5. Every action is idempotent and has pre/post snapshot evidence.
6. Every numeric or device-state claim refers to Evidence.
7. LLM output cannot override deterministic safety, quality, residual, ranking, or execution policy.
8. Data-quality failure routes to `DATA_UNTRUSTED`; evidence insufficiency routes to `INCONCLUSIVE`.
9. Every result is reproducible from an immutable run manifest.
10. Any safety red-line failure fails the release regardless of aggregate score.

## Canonical target layout

Use existing repository conventions when a compatible implementation already exists. For a greenfield repository, use:

```text
backend/
  pyproject.toml
  src/shadow_sandbox/
    common/ asset_registry/ runtime/ scenarios/ ingestion/
    quality/ diagnosis/ planning/ approvals/ actions/
    replay/ evaluation/ reports/ security/ observability/ integrations/
  tests/
services/
  simulator/src/shadow_simulator/
  collector/src/shadow_collector/
web/src/
  api/ components/ features/ router/ stores/ views/
domain-packs/pump-tank-v1/
  assets/ signals/ models/ faults/ graph/ rules/ checks/ scenarios/ gold/ tests/
schemas/
  api/ events/ tools/ scenarios/
migrations/
tests/
  contract/ integration/ scenario/ replay/ e2e/ security/ performance/
deploy/compose/
docs/evidence/batch-XX/
IMPLEMENTATION_STATUS.yaml
```

## Default implementation choices

- Python 3.12, FastAPI, Pydantic, SQLAlchemy, Alembic.
- Vue 3, TypeScript, Pinia, and ECharts.
- PostgreSQL for metadata and workflow state.
- PyArrow/Parquet for raw events and frozen datasets.
- asyncua for the MVP simulator and collector; validate production capacity before scaling.
- OpenTelemetry for traces, metrics, and logs.
- Docker Compose for local integration.
- PostgreSQL-backed durable state machine and transactional outbox for MVP. Reuse an existing Control Plane or durable workflow service through an adapter when present.
- No Kafka, Kubernetes, large time-series cluster, arbitrary plugin execution, or real control path in the MVP unless the repository already has a justified and tested dependency.

## Shared API rules

- Prefix REST routes with `/api/v1` and publish OpenAPI.
- Use UUID/ULID identifiers consistently; never accept tenant ownership from an untrusted payload when it can be derived from auth.
- Return RFC 9457-style problem details with stable machine codes.
- Require `Idempotency-Key` for command routes and `If-Match` for mutable versioned drafts.
- Publish versioned JSON Schemas for REST payloads, events, tools, Scenario DSL, and Gold DSL.
- Use an outbox for domain events written in the same transaction as state changes.
- Include `event_id`, `schema_version`, `occurred_at`, `tenant_id`, `workspace_id`, `run_id`, and `trace_id` in events when applicable.

## Shared evidence rules

Every batch creates `docs/evidence/batch-XX/manifest.json` with:

```json
{
  "batch": "XX",
  "status": "passed|partial|blocked",
  "commands": [{"command": "...", "exit_code": 0, "log": "..."}],
  "artifacts": [{"path": "...", "sha256": "..."}],
  "tests": [{"suite": "...", "passed": 0, "failed": 0, "skipped": 0}],
  "safety_assertions": [{"id": "...", "result": "passed|failed"}],
  "known_limits": []
}
```

Store JUnit, coverage, Playwright, benchmark, OpenAPI/JSON Schema, Compose, trace, and report artifacts beside the manifest as required. A manifest that references missing files fails validation. Do not store secrets, credentials, production raw data, or Gold answers in ordinary evidence.

## Completion semantics

- `not_started`: no relevant implementation.
- `in_progress`: code exists but tests or contracts are incomplete.
- `blocked`: exact external blocker documented; do not claim completion.
- `implemented_unverified`: code exists but critical real integration was not run.
- `completed`: every batch DoD item has executable evidence and all required safety assertions pass.

Documentation, generated placeholders, mocked-only tests, unchecked boxes, or structure validators never qualify as `completed`.

