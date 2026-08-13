# Batch 11: Data-quality and interpretable univariate detection

## Context

- Completed dependencies: lossless raw events and durable completed Runs.
- Diagnosis begins with trust in data. Poor data quality must gate process diagnosis and favor communication/measurement hypotheses.
- MVP detection uses explainable, versioned statistical methods rather than an opaque end-to-end model.

## Outcome

- Raw Run data is converted into quality windows and interpretable single-signal anomalies with precise evidence inputs.
- Startup, shutdown, setpoint changes, maintenance, and normal noise are mode-aware to reduce false alarms.
- Runs with insufficient data enter `DATA_UNTRUSTED` and do not produce confident equipment diagnoses.

## Inputs

- Raw event query/Parquet interfaces from Batch 06 and Run Manifest/mode timeline from Batch 10.
- Signal sampling interval, quality policy, type, range, and semantics from Batch 02.
- Detector configuration and mode-specific thresholds in the Pump Tank Domain Pack.
- Normal Scenario corpus from Batch 09 for calibration without exposing fault Gold.

## Code modules

- `backend/src/shadow_sandbox/quality/entities.py`: quality issue/window/summary.
- `backend/src/shadow_sandbox/quality/checks.py`: stale, gap, duplicate, reorder, flatline, quality, clock, interval, multi-freeze.
- `backend/src/shadow_sandbox/quality/service.py`: windowing and Run quality state.
- `backend/src/shadow_sandbox/diagnosis/detectors/protocol.py`: versioned detector contract.
- `backend/src/shadow_sandbox/diagnosis/detectors/univariate.py`: threshold, EWMA, robust Z, slope, variance, CUSUM/change point.
- `backend/src/shadow_sandbox/diagnosis/detectors/mode_context.py`: operating-mode context.
- `backend/src/shadow_sandbox/diagnosis/pipeline.py`: quality-gated execution.
- `migrations/*_quality_detection.py`.
- `domain-packs/pump-tank-v1/rules/quality.yaml` and `detectors.yaml`.
- `web/src/features/runs/QualityPanel.vue` and `AnomalyTimeline.vue`.

## Interfaces

- `QualityWindowV1`: Run/signal/window, sample count, expected count, missing/duplicate/reorder ratio, freshness, status distribution, clock skew, issues, and state.
- Quality states: `TRUSTED`, `DEGRADED`, `UNTRUSTED`, with versioned reason codes.
- `DetectorInputV1`: quality-filtered series, signal metadata, operating mode, command/event context, and detector config digest.
- `AnomalyObservationV1`: detector ref, window, observed statistic, baseline, threshold, direction, severity, quality state, and raw event refs.
- `POST /api/v1/runs/{id}/quality-and-detect` idempotently starts the stage; `GET /quality`, `/anomalies`.
- Events `data_quality.assessed.v1`, `data_quality.untrusted.v1`, and `anomaly.observed.v1`.
- Detectors cannot query Gold or arbitrary external data.

## Implementation requirements

1. Preserve raw events; derived windows reference their source ranges and algorithm/config versions.
2. Compute expected samples using mode and sampling policy; account for explicit Collector reconnect gaps.
3. Detect stale/future timestamps, gaps, duplicates, reorder, Bad/Uncertain status, flatline, interval drift, clock skew, and multiple-node freeze.
4. Implement mode-aware baselines and suppression windows for legitimate transitions.
5. Normalize detector severity to 0–1 using documented bounds without calling it probability.
6. Gate downstream process detectors per signal/window when quality is untrusted.
7. Separate communication/data-quality anomalies from process/equipment anomalies.
8. Version detector code/config and save digests in every result.
9. Support incremental windows during live Run and deterministic batch recomputation after completion.
10. Add human-readable reason codes and charts while retaining structured authoritative values.
11. Calibrate thresholds on normal corpus and persist the calibration dataset/config digest.
12. Expose detector duration, window lag, anomaly counts, suppression, and quality-state metrics.

## Tests

- Unit: every quality check and detector on synthetic normal/edge series.
- Property: time-order permutations and missing data produce stable, bounded results and no NaN.
- Mode: startup/shutdown/load/setpoint/maintenance normal scenarios avoid forbidden alarms.
- Fault: F02, F03, and F10 produce expected quality/univariate signatures.
- Determinism: online incremental and offline batch results match under the same window policy.
- API/event contract and persistence idempotency.
- Security: detector cannot access Gold role/schema; query windows enforce Run ownership.
- Performance: process MVP data within P95 five seconds after a window closes.

## Required evidence

- `docs/evidence/batch-11/manifest.json`.
- Normal-corpus calibration report with dataset/config digest.
- Quality/detector test matrix and representative anomaly JSON.
- Online-versus-batch deterministic comparison.
- Normal transition false-alarm report and F02/F03/F10 signature report.
- API/event schemas, migration output, performance benchmark, and trace.
- Playwright evidence for quality state and anomaly timeline including untrusted data.

## Definition of Done

- Every completed Run can produce versioned quality windows and univariate anomaly observations from real raw events.
- `DATA_UNTRUSTED` is reached and surfaced for configured severe quality failures.
- Normal operating transitions are context-aware and pass the declared false-alarm tests.
- Communication, sensor, and process anomaly categories remain distinct.
- Incremental and batch calculations match for frozen input.
- Results reference source events, detector/config digest, and operating mode.
- No LLM or Gold content participates in authoritative detection.

## Out of scope

- Process residuals, cross-signal rules, final Symptoms, causal ranking, and natural-language diagnosis.
- Learned deep anomaly models.

