# Batch 22: Historical data import and signal mapping

## Context

- Completed dependencies: complete S0 platform, asset registry, raw event Schema, quality/detection pipeline, evaluation, and RBAC/audit.
- This batch advances to S1: offline real data replay without connecting to live equipment.
- Source labels, timestamps, units, values, maintenance text, and files are untrusted and may be incomplete or inconsistent.

## Outcome

- Engineers can profile CSV/JSONL/Parquet or a read-only Historian export, map source tags to canonical signals, normalize timestamps/units/quality, and create immutable dataset snapshots.
- Imported data enters the same quality, diagnosis, replay, and evaluation paths as simulated data while retaining provenance.
- Data cannot be used for certification until mapping, quality, labeling, and split checks pass.

## Inputs

- Canonical asset/signal registry and unit system from Batch 02.
- `RawSignalEventV1`, Parquet manifest, quality pipeline, replay, and dataset protections.
- Source files supplied locally or read-only Historian adapter with test double.
- Import policy: timezone, timestamp format, duplicate handling, quality mapping, missing signals, retention, and data classification.

## Code modules

- `backend/src/shadow_sandbox/integrations/imports/entities.py`: source, profile, mapping, job, dataset.
- `backend/src/shadow_sandbox/integrations/imports/readers/csv_reader.py`, `jsonl_reader.py`, `parquet_reader.py`.
- `backend/src/shadow_sandbox/integrations/imports/historian.py`: read-only adapter port.
- `backend/src/shadow_sandbox/integrations/imports/profiler.py`.
- `backend/src/shadow_sandbox/integrations/imports/mapping.py` and `units.py`.
- `backend/src/shadow_sandbox/integrations/imports/normalizer.py`, `writer.py`, and `service.py`.
- `migrations/*_historical_imports.py`.
- `schemas/api/import*.json` and dataset-manifest schema.
- `web/src/features/imports/`: upload/source, profile, mapping, preview, validation, job, and dataset views.
- `tests/fixtures/imports/`: sanitized deterministic normal, faulty, malformed, and adversarial files.

## Interfaces

- `SourceProfileV1`: columns/tags, inferred types/units/timezone, row counts, sampling distribution, missing/duplicate/outlier/quality summary, and warnings.
- `SignalMappingV1`: source tag/column, canonical signal version, conversion, timestamp/quality rules, confidence, reviewer, and version.
- `ImportJobV1`: source hash, mapping/policy digests, state, counts, rejects, warnings, and dataset output.
- `POST /api/v1/import-sources`, `/profile`, `/mappings/validate`, `/import-jobs`; `GET /import-jobs/{id}`, `/datasets/{id}`.
- Dataset Manifest contains source, mapping, normalization, asset, time range, counts, quality, lineage, split label, and content hashes.
- Historian port implements bounded query/read only; no write/update/delete operation.

## Implementation requirements

1. Stream files with size/row/time/resource limits; avoid loading entire sources into memory.
2. Detect file type from content/declared media, reject unsafe paths, archives, formulas/macros, and malformed encodings according to policy.
3. Require explicit timezone/DST handling; retain original and normalized timestamp provenance.
4. Map units through registered conversions and reject incompatible dimensions.
5. Map source quality codes to canonical status while retaining the original value.
6. Profile before import and require human review for low-confidence mappings.
7. Write valid rows to immutable Parquet and rejected rows to a controlled error artifact without sensitive leakage.
8. Preserve source hash, mapping/policy/version, transformation lineage, and row-count reconciliation.
9. Run quality assessment after import and flag datasets not fit for diagnosis/certification.
10. Support expert incident labels as versioned provenance with conflict/dispute state; do not silently manufacture Gold.
11. Detect duplicate Episode/content leakage across train/tune/validation/certification splits.
12. Treat maintenance/alarm text as untrusted and keep it out of tool policy/Prompt authority.

## Tests

- Unit: timestamp/timezone/DST, unit conversion, quality mapping, type coercion, mapping confidence, and row reconciliation.
- Format contract: CSV/JSONL/Parquet valid and malformed fixtures.
- Security: path traversal, decompression bomb policy, CSV formula injection, oversized/deep fields, Prompt Injection text, and unauthorized Historian operations.
- Integration: import deterministic dataset, query normalized raw events, run quality/detection/replay, and verify lineage.
- Failure: partial bad rows, storage failure, job restart/cancel, duplicate import, and mapping version change.
- Privacy: audit/export/redaction and deletion/retention for an unreferenced dataset.
- Split: duplicate-content leakage and disputed labels block certification eligibility.
- Frontend E2E: profile, map, preview, correct error, import, monitor, and inspect quality.

## Required evidence

- `docs/evidence/batch-22/manifest.json`.
- Source-to-normalized row-count/hash reconciliation and Dataset Manifest.
- Timezone/unit/quality mapping reports and rejected-row summary.
- File/adversarial security test report.
- Imported-dataset quality/replay trace with provenance links.
- Split-leakage and label-dispute gate results.
- API schemas, migration, job restart/cancel, performance, and Playwright evidence.

## Definition of Done

- Supported sources import through a streamed, resumable, audited pipeline into canonical raw events and Parquet.
- Every normalized value/time/quality field traces to source plus mapping/conversion version.
- Incompatible units, ambiguous time, unsafe files, unauthorized operations, and low-confidence unmapped signals are blocked or explicitly reviewed.
- Row reconciliation and source/dataset hashes match.
- Imported data runs through the existing quality/replay path without a parallel diagnostic implementation.
- Split leakage/disputed labels prevent certification eligibility.
- No live equipment connection or write capability is introduced.

## Out of scope

- Online live Shadow subscriptions, automatic Gold creation, unsupervised asset discovery, and arbitrary ETL code.
- Rewriting source Historian data.

