# Batch 02: Asset, signal, unit, and topology registry

## Context

- Completed dependency: Batch 01 foundation and database/API conventions.
- The asset registry is the semantic source for simulator nodes, collector mappings, residuals, causal graphs, and reports.
- Published versions are immutable; drafts use optimistic locking.
- MVP Domain Pack models Pump P101, Valves V101/V102, Tank T101, Heater H101, sensors, and system signals.

## Outcome

- Engineers can create, validate, publish, retrieve, and visualize a versioned industrial asset model.
- Invalid units, duplicate signal paths, broken topology, unsafe writability, and missing semantic metadata are rejected before publication.
- Downstream modules consume one canonical model digest and typed signal identifiers.

## Inputs

- Batch 01 application, database, error, OpenAPI, status, and evidence contracts.
- Pump–valve–tank–heater hierarchy and signal list from the system design.
- UCUM-compatible engineering unit catalog and controlled asset/signal semantic labels.
- User/workspace context may be a development service identity until Batch 21 adds full RBAC.

## Code modules

- `backend/src/shadow_sandbox/asset_registry/entities.py`: draft and published entities.
- `backend/src/shadow_sandbox/asset_registry/schemas.py`: API/domain schemas.
- `backend/src/shadow_sandbox/asset_registry/service.py`: create, validate, publish, and read use cases.
- `backend/src/shadow_sandbox/asset_registry/validation.py`: unit, hierarchy, signal, and topology rules.
- `backend/src/shadow_sandbox/asset_registry/repository.py`: persistence port and SQL implementation.
- `backend/src/shadow_sandbox/asset_registry/api.py`: REST routes.
- `backend/src/shadow_sandbox/asset_registry/events.py`: versioned publication event.
- `migrations/*_asset_registry.py`: tables and indexes.
- `schemas/api/asset-model*.json` and `schemas/events/asset-model-published-v1.json`.
- `domain-packs/pump-tank-v1/assets/asset-model.yaml` and `signals/signal-catalog.yaml`.
- `web/src/features/assets/`: list, editor, validation panel, topology, and version views.

## Interfaces

- Entities: `AssetModel`, `AssetModelVersion`, `Asset`, `Component`, `SignalDefinition`, `TopologyEdge`, `UnitDefinition`.
- Signal fields: stable key, display name, NodeId template, type, unit, range, sample period, access mode, quality policy, semantic tags, and owning asset.
- `POST /api/v1/asset-models`; `GET/PATCH /api/v1/asset-models/{id}` with `If-Match`.
- `POST /api/v1/asset-models/{id}/validate` returns errors with JSON Pointer locations.
- `POST /api/v1/asset-models/{id}/publish` produces an immutable version and digest.
- `GET /api/v1/asset-model-versions/{id}` and `/topology` return canonical published data.
- Event `asset_model.published.v1` carries model/version IDs, digest, workspace, and trace context.
- Service methods: `create_draft`, `update_draft`, `validate_draft`, `publish`, `get_published`, `resolve_signal`.

## Implementation requirements

1. Add relational constraints and indexes for stable keys, version uniqueness, parent relationships, and workspace ownership.
2. Validate that every signal belongs to one asset, has a supported scalar type, valid unit, positive sampling interval, and coherent range.
3. Reject cycles in containment; permit directed process/control/causal topology edges with declared edge type.
4. Require explicit access mode. Sensor and status signals in the MVP Pack must be read-only; simulation command signals may be marked simulation-write only.
5. Normalize units without silently converting stored values. Record canonical and display units.
6. Compute the published digest from canonicalized content, not database IDs or timestamps.
7. Prevent mutation or deletion of published versions referenced by runs.
8. Render hierarchy and topology without assuming a single factory/line.
9. Provide YAML import/export with schema validation and deterministic ordering.
10. Emit the publication event via the transactional outbox.
11. Seed the complete pump-tank model, including all NodeId templates and semantic tags.
12. Avoid implementing simulator equations in this batch.

## Tests

- Unit: unit validation, canonicalization, digest stability, cycle detection, duplicate paths, range/type rules.
- Repository: tenant/workspace isolation, optimistic-lock conflict, unique version, immutable publication.
- API contract: create/update/validate/publish/read and RFC problem errors.
- Event contract: validate outbox payload against the v1 JSON Schema.
- Import/export: YAML round trip preserves canonical digest.
- Integration: publish the seeded Pump Tank model in PostgreSQL and retrieve the exact hierarchy/topology.
- Frontend: edit valid/invalid signals, display pointer-level errors, publish, and browse immutable version.
- Security: attempt cross-workspace read/update and simulation-write on a sensor definition.

## Required evidence

- `docs/evidence/batch-02/manifest.json`.
- Database migration log and schema snapshot for registry tables/indexes.
- OpenAPI and event-schema validation reports.
- `pump-tank-model-validation.json`, published digest, and YAML round-trip diff.
- Unit/API/integration/frontend JUnit or equivalent reports.
- Playwright trace or screenshots showing validation errors and published topology.
- Security test log proving cross-workspace and invalid access modes are rejected.

## Definition of Done

- The seeded model publishes through the real API and persists in PostgreSQL.
- The published model is immutable, digest-stable, and resolvable by downstream code.
- All required equipment and signals exist with units, access modes, ranges, NodeId templates, and semantic tags.
- Invalid models fail with actionable, pointer-addressed errors.
- Asset UI uses the API and displays loading, error, empty, draft, invalid, and published states.
- Publication writes a schema-valid outbox event atomically.
- Tests and evidence prove isolation, immutability, canonical digest, and import/export round trip.

## Out of scope

- Numerical simulation, OPC UA runtime nodes, data collection, causal diagnosis, and full enterprise roles.
- Automatic discovery from a real factory endpoint.

