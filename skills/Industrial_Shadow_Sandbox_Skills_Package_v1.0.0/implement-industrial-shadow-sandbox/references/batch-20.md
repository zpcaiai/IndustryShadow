# Batch 20: Evaluator, reports, and non-bypassable Release Gate

## Context

- Completed dependencies: sealed Gold, benchmark corpus, structured diagnosis/plans/actions, and versioned replays/experiments.
- Evaluator is the only runtime that joins results to Gold.
- Aggregate quality scores never offset safety red-line failures.

## Outcome

- The platform computes diagnosis, false-positive, timing, evidence, plan, safety, recovery, robustness, and operational metrics by Episode and slice.
- JSON/HTML/PDF-ready reports link every result to source Evidence and immutable version coordinates.
- A version bundle becomes Champion/eligible only after a signed Release Gate passes; failure remains visible and non-bypassable.

## Inputs

- Sealed Gold resolver and fault/normal Scenario Suites from Batch 09.
- Diagnosis, Evidence, plan, approval, action, replay, and experiment outputs.
- Metric definitions, slice axes, thresholds, safety red lines, and comparison baseline.
- Report templates and optional PDF renderer; JSON/HTML are mandatory.

## Code modules

- `backend/src/shadow_sandbox/evaluation/metrics/diagnosis.py`.
- `backend/src/shadow_sandbox/evaluation/metrics/false_positive.py`.
- `backend/src/shadow_sandbox/evaluation/metrics/evidence.py`.
- `backend/src/shadow_sandbox/evaluation/metrics/planning.py`.
- `backend/src/shadow_sandbox/evaluation/metrics/safety.py`.
- `backend/src/shadow_sandbox/evaluation/metrics/recovery.py`.
- `backend/src/shadow_sandbox/evaluation/service.py`, `slicing.py`, and `comparison.py`.
- `backend/src/shadow_sandbox/evaluation/gates.py` and `certification.py`.
- `backend/src/shadow_sandbox/reports/model.py`, `renderer.py`, `service.py`, and `api.py`.
- `migrations/*_evaluation_release_gate.py`.
- `domain-packs/pump-tank-v1/gold/gate-policy.yaml` and report template.
- `web/src/features/evaluation/` and `reports/` dashboards.

## Interfaces

- Metrics: Top-1/2/3, mean rank/MRR, detection/false-negative, Episode/window false-positive, MTTD, duplicate alarm, inconclusive, evidence citation/sufficiency/contradiction, unsupported claim, hallucinated signal, weighted plan completeness, critical-step omission, forbidden action, ordering, post-verification, approval bypass, real-write/write-attempt, idempotency/rollback, recovery, runtime, and report/Trace success.
- `EvaluationV1`: corpus/result versions, metric results, slice results, failed Episodes, limitations, evaluator/gold/gate digests.
- `ReleaseGateResultV1`: policy, baseline comparison, thresholds, red lines, pass/fail, reasons, approver/signature, and certification digest.
- `POST /api/v1/evaluations`; `GET /evaluations/{id}`, `/slices`, `/episodes`.
- `POST /api/v1/release-gates/evaluate`; `POST /release-gates/{id}/promote` only when passed.
- `GET /api/v1/reports/{id}` and content negotiation for JSON/HTML/PDF.
- Events `evaluation.completed.v1`, `release_gate.passed/failed.v1`, `report.generated/failed.v1`.

## Implementation requirements

1. Join Gold only inside evaluator service identity and never copy labels into Agent-facing stores before evaluation.
2. Define numerator, denominator, exclusions, normal corpus, window policy, units, and version for every metric.
3. Compute slices by fault, severity, load, mode, seed, asset, quality, and version; guard tiny denominators.
4. Implement weighted plan completeness plus absolute failure for missing critical safety steps.
5. Treat unsupported claims, unapproved actions, real writes/attempts, critical omissions, and Gold leakage as safety red lines.
6. Compare Challenger to baseline and fail material per-slice regressions even when aggregate improves according to policy.
7. Report confidence intervals or uncertainty where sample size supports it; do not overstate small corpora.
8. Produce a version Manifest and content hash for reports/certifications.
9. Keep evaluation/report reruns idempotent and immutable; corrections create superseding versions.
10. Report renderer accepts only typed data and escapes untrusted asset/notes content.
11. Promotion requires a passed Gate tied to the exact bundle digest; no manual database flag or admin override.
12. Store report/trace generation failures independently so evaluation results remain recoverable.

## Tests

- Unit: every metric with hand-calculated fixtures, denominators, missing data, multi-root cause, alternatives, and slice behavior.
- Safety: each red line independently forces Gate failure despite high aggregate score.
- Corpus: evaluate the ≥100 fault/≥50 normal suite and validate target MVP thresholds.
- Regression: synthetic aggregate improvement with one critical slice regression fails according to policy.
- Gold boundary: evaluator authorized; ordinary services cannot read Gold; outputs expose only intended post-evaluation labels.
- Report: JSON Schema, HTML escaping/accessibility, PDF optional rendering, links/hashes, large report, and failure retry.
- Promotion: wrong bundle, stale Gate, failed Gate, modified policy, and admin bypass rejected.
- Frontend E2E: dashboard, slices, failed Episodes, report, Gate reasons, and eligible promotion.

## Required evidence

- `docs/evidence/batch-20/manifest.json`.
- Hand-calculated metric fixture report and metric-definition catalog.
- Full benchmark evaluation JSON with sanitized Episode references and slice tables.
- Safety red-line matrix proving every red line forces failure.
- Challenger/baseline regression report and Gate decision.
- Generated JSON/HTML report, optional PDF, hashes, schema/accessibility/security tests.
- Gold boundary, promotion denial, migration, API/event, OTel, and Playwright evidence.

## Definition of Done

- The real benchmark corpus evaluates through the evaluator-only Gold boundary.
- All declared metrics have explicit definitions and deterministic tests.
- Safety red lines are non-compensable and cannot be overridden through UI/API/admin/database paths tested by the suite.
- Reports open, link to real Evidence/versions, escape untrusted content, and reproduce from the Evaluation Manifest.
- Promotion accepts only an exact version bundle with a current passed Gate.
- Failed Episode and slice drill-down explain aggregate numbers.
- The result states corpus limits and never equates sandbox certification with real-device safety certification.

## Out of scope

- Real-device authorization, regulatory certification claims, learned evaluator models, and automatic production rollout.
- Hiding failed slices behind aggregate scores.

