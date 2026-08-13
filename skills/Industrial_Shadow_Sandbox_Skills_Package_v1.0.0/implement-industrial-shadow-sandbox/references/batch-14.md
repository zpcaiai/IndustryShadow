# Batch 14: Causal graph, candidate generation, and Top-3 ranking

## Context

- Completed dependencies: versioned assets/topology and first-class Symptoms/Evidence.
- Root-cause generation follows causal structure, fault catalog, temporal order, residual explanation, and contradictions.
- Scores are evidence scores until a separate probability-calibration process is proven.

## Outcome

- The system generates bounded candidate root causes and ranks Top-3 with support, contradiction, missing expected observations, causal path, and score breakdown.
- `INCONCLUSIVE` is returned when evidence is insufficient, low quality, unknown, or poorly separated.
- The seeded benchmark can measure but does not expose Gold during inference.

## Inputs

- Asset/process/control topology from Batch 02 and Domain Pack causal graph definitions.
- Symptoms, Evidence, quality limitations, and Claims from Batch 13.
- Fault catalog with applicability, expected manifestations, priors, and exclusions from Batch 08 Pack.
- Operating mode/load and Run Manifest from Batch 10.

## Code modules

- `backend/src/shadow_sandbox/diagnosis/graph/entities.py`, `validation.py`, and `repository.py`.
- `backend/src/shadow_sandbox/diagnosis/graph/traversal.py`: bounded upstream/common-cause search.
- `backend/src/shadow_sandbox/diagnosis/hypotheses/generator.py`.
- `backend/src/shadow_sandbox/diagnosis/hypotheses/features.py`.
- `backend/src/shadow_sandbox/diagnosis/hypotheses/ranker.py`.
- `backend/src/shadow_sandbox/diagnosis/hypotheses/inconclusive.py`.
- `backend/src/shadow_sandbox/diagnosis/hypotheses/service.py`, `api.py`, and `events.py`.
- `migrations/*_causal_graph_hypotheses.py`.
- `domain-packs/pump-tank-v1/graph/causal-graph.yaml`, `faults/catalog.yaml`, and ranking policy.
- `web/src/features/diagnosis/HypothesisPanel.vue` and `CausalPathView.vue`.

## Interfaces

- Graph nodes: asset, component health, command, actual state, process state, signal, communication health, and operating context.
- Graph edges: causes, measures, controls, affects, depends_on, and common_cause; every edge has direction, condition, version, and source.
- `HypothesisV1`: cause ID, rank, evidence score, feature breakdown, support/contradiction/missing Evidence refs, causal paths, applicability, uncertainty reasons, and ranker digest.
- `DiagnosisResultV1`: `RANKED` or `INCONCLUSIVE`, Top-K, quality summary, candidate coverage, and additional-information needs.
- `POST /api/v1/runs/{id}/hypotheses`; `GET /hypotheses`, `/causal-subgraph`.
- Events `hypotheses.ready.v1` and `diagnosis.inconclusive.v1`.
- Ranker feature contract: rule match, temporal consistency, graph consistency, residual explanatory power, prior, contradiction, missing evidence, and quality penalty.

## Implementation requirements

1. Validate graph references, units/semantics where applicable, cycles by edge policy, disconnected required nodes, and maximum traversal depth.
2. Generate candidates by upstream traversal 2–3 hops, symptom/fault mapping, and communication common-cause expansion.
3. Keep the candidate set bounded and provide why each candidate entered or was excluded.
4. Compute versioned feature values and weighted score; expose the exact breakdown.
5. Use temporal precedence and operating mode; do not reward a cause that occurs after the symptom without an explicit lag model.
6. Penalize contradictions and missing expected observations; never hide them from the result.
7. Define `INCONCLUSIVE` gates for untrusted data, no candidate, low evidence coverage, low top score, or insufficient Top-1/Top-2 separation.
8. Do not label evidence score as probability in API/UI/report.
9. Validate every cited Evidence through the Batch 13 claim boundary.
10. Version graph, fault catalog, feature extractor, weights, and policy; store all digests.
11. Add deterministic ordering for equal scores.
12. Instrument candidate count, traversal, score distribution, inconclusive reasons, and latency.

## Tests

- Unit: graph validation/traversal, candidate bounds, every score feature, contradiction/missing penalty, tie-breaking, and inconclusive gates.
- Golden-structure: known synthetic symptom sets yield expected candidate sets and causal paths without evaluator Gold access.
- Scenario: run F01–F10 completed Evidence through inference and verify a well-formed Top-3 or justified inconclusive result.
- Pair discrimination: F01/F08, F04/F07, F05/F06, and F10/multi-sensor failure.
- Quality: untrusted inputs suppress equipment certainty and prioritize data/communication hypotheses.
- Security: graph DSL cannot execute code; cross-workspace Evidence and Gold access fail.
- Contract: API/events and score-breakdown schemas.
- Performance: bounded traversal/ranking meets P95 target for MVP graph.

## Required evidence

- `docs/evidence/batch-14/manifest.json`.
- Validated causal graph export/digest and graph-lint report.
- F01–F10 Top-3 outputs with support, contradiction, causal paths, and score breakdown.
- Pair-discrimination and inconclusive-gate reports.
- Evidence-citation integrity and Gold-access-denial logs.
- API/event schemas, migration, performance benchmark, and traces.
- UI trace showing score wording, causal path, contradictions, and inconclusive state.

## Definition of Done

- Top-3 hypotheses are produced from actual persisted Symptoms/Evidence and a published causal graph.
- Each result exposes candidate origin, causal path, score breakdown, support, contradiction, and missing evidence.
- Quality and insufficient-evidence cases return explicit `INCONCLUSIVE` rather than forced certainty.
- Scores are consistently presented as evidence scores.
- Graph/weights/catalog/feature versions are immutable and stored in the Run result.
- Deterministic ranking and pair-discrimination tests pass.
- Runtime code has no permission to resolve Gold.

## Out of scope

- Probability calibration, learned graph discovery, check planning, approval, recovery, and LLM-authored prose.
- Automatic causal claims from correlation alone.

