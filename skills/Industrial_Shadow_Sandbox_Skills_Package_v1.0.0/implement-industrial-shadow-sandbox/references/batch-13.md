# Batch 13: First-class symptoms, evidence, and evidence timeline

## Context

- Completed dependencies: raw events, quality/anomaly observations, process residuals, and cross-signal consistency.
- Evidence must be immutable and independently inspectable; report prose is not authoritative evidence.
- Symptoms normalize low-level observations into reusable diagnostic facts without selecting a root cause.

## Outcome

- The platform materializes content-addressed Evidence and normalized Symptoms from prior detector outputs.
- Users can navigate a time-aligned evidence timeline from a symptom to transformations and source events.
- Numeric/state claims are rejected unless they cite valid Evidence in the same Run/workspace.

## Inputs

- Raw-event ranges and Parquet manifests from Batch 06.
- QualityWindow, AnomalyObservation, ResidualObservation, and ConsistencyObservation from Batches 11–12.
- Asset/signal metadata, units, modes, and topology from Batch 02.
- Symptom catalog and extraction mappings in the Pump Tank Domain Pack.

## Code modules

- `backend/src/shadow_sandbox/diagnosis/evidence/entities.py`: immutable evidence and source refs.
- `backend/src/shadow_sandbox/diagnosis/evidence/canonical.py`: canonical payload and content hash.
- `backend/src/shadow_sandbox/diagnosis/evidence/service.py`: materialize, validate, retrieve, and render data.
- `backend/src/shadow_sandbox/diagnosis/symptoms/entities.py` and `catalog.py`.
- `backend/src/shadow_sandbox/diagnosis/symptoms/extractor.py`: mapping/temporal aggregation.
- `backend/src/shadow_sandbox/diagnosis/claims.py`: claim-to-evidence validation.
- `backend/src/shadow_sandbox/diagnosis/api.py` and `events.py`.
- `migrations/*_evidence_symptoms.py`.
- `domain-packs/pump-tank-v1/rules/symptom-mappings.yaml`.
- `web/src/features/diagnosis/EvidenceTimeline.vue`, `SymptomList.vue`, and `EvidenceDrawer.vue`.

## Interfaces

- `EvidenceV1`: evidence ID/hash, Run/window, type, source refs/hashes, transformation ref/config, quality state, observation/baseline/threshold/residual, units, related signals/assets, and visualization hint.
- Evidence roles: support, contradiction, neutral, missing-expected, and data-quality limitation.
- `SymptomV1`: catalog ID, Run/window, severity, quality state, related assets/signals, Evidence refs, extraction version, and lifecycle status.
- `ClaimV1`: typed subject/predicate/value/unit/window plus mandatory Evidence refs and claim origin.
- `POST /api/v1/runs/{id}/materialize-evidence`; `GET /evidence`, `/evidence/{id}`, `/symptoms`, `/evidence-timeline`.
- Events `evidence.created.v1`, `symptom.created/updated/closed.v1`, and `claim.rejected.v1`.
- `EvidenceValidator.validate_claim` is reused by hypothesis/report/narrative modules.

## Implementation requirements

1. Canonicalize evidence content and hash the transformation inputs; do not hash database IDs alone.
2. Keep evidence immutable; corrections create superseding evidence with lineage.
3. Store enough source location to reconstruct the observation from raw events or frozen Parquet.
4. Map low-level outputs to stable symptom IDs such as flow-response-low, command-actual-mismatch, mass-deficit, pressure-noise, and multi-signal-stale.
5. Merge adjacent observations only under versioned gap/window rules; preserve original Evidence refs.
6. Record support, contradiction, limitation, and missing-expected evidence explicitly.
7. Validate units, Run/workspace ownership, time overlap, and source existence for every claim.
8. Reject evidence mutation, cross-Run citation, dangling source, or untrusted numeric claim.
9. Generate downsampled chart data on demand while retaining original source references.
10. Timeline must align process, commands, faults/events visible to operators, quality, residuals, symptoms, and later workflow states.
11. Avoid Gold/root-cause labels in symptom extraction.
12. Instrument evidence creation latency, hash deduplication, rejected claims, and source reconstruction failures.

## Tests

- Unit: canonical hash stability, lineage, source validation, symptom mapping, temporal merge/split, and claim rules.
- Reconstruction: recompute representative Evidence from source events and match content hash/value within tolerance.
- Scenario: F01–F10 yield expected symptom directions without passing Gold into extraction.
- Contradiction: create cases where a candidate-relevant observation is absent or opposing and preserve it.
- Security: cross-workspace/Run citation, dangling IDs, tampered Parquet hash, and unsupported claim are rejected.
- Contract: REST/event/claim schemas and immutable persistence.
- Frontend: timeline zoom/filter, evidence drawer, raw-source link, empty/untrusted/error states.
- Performance: materialize and query a full MVP Run within declared limits.

## Required evidence

- `docs/evidence/batch-13/manifest.json`.
- Representative Evidence/Symptom JSON for normal and each fault category.
- Source reconstruction and content-hash verification report.
- Unsupported/cross-Run/tampered-source rejection report.
- F01–F10 symptom coverage matrix and no-Gold dependency scan.
- API/event schemas, migration, performance, and OTel reports.
- Playwright trace of evidence timeline and source drill-down.

## Definition of Done

- Real detector/residual outputs become immutable Evidence and stable Symptoms through persisted services.
- Every numeric claim accepted by the validator cites reconstructable same-Run Evidence.
- Source tampering, dangling/cross-Run refs, mutation, and unsupported claims fail server-side.
- Timeline displays real source-aligned data and explicit quality limitations.
- Contradictory and missing-expected evidence are first-class, not discarded.
- Symptom extraction remains root-cause/Gold independent and versioned.
- Evidence hashes and reconstruction pass deterministic tests.

## Out of scope

- Selecting/ranking root causes, suggesting checks, natural-language reports, and human approval.
- Generic vector retrieval as an authority for numerical claims.

