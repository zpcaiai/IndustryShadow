---
name: implement-industrial-shadow-sandbox
description: Implement, continue, audit, or repair the Industrial Shadow Sandbox as a code-producing, evidence-gated sequence of 24 batches. Use when Codex must build the industrial simulator, OPC UA read-only collector, fault DSL, deterministic diagnosis, causal root-cause ranking, human approval, simulation-only recovery, replay, evaluation, reporting, real read-only Shadow integration, or production hardening; also use when checking whether a claimed batch is genuinely implemented rather than merely documented.
---

# Implement Industrial Shadow Sandbox

Build a read-only, replayable, evidence-scored industrial diagnosis validation platform. Preserve the hard boundary: real industrial endpoints are read-only; approved side effects execute only against registered simulators.

## Load the required contract

Always read [references/system-contract.md](references/system-contract.md). Then read exactly the requested batch file from the map below. Read earlier batch files only when the repository lacks a referenced contract or a compatibility question cannot be answered from code.

| Batch | Reference | Outcome |
|---:|---|---|
| 01 | [batch-01.md](references/batch-01.md) | Repository foundation and executable evidence ledger |
| 02 | [batch-02.md](references/batch-02.md) | Asset, signal, unit, and topology registry |
| 03 | [batch-03.md](references/batch-03.md) | Deterministic pump–valve–tank–heater simulator |
| 04 | [batch-04.md](references/batch-04.md) | Snapshot, restore, deterministic clock, and reproducibility |
| 05 | [batch-05.md](references/batch-05.md) | Virtual OPC UA address space and subscriptions |
| 06 | [batch-06.md](references/batch-06.md) | Shadow Collector and lossless raw-event storage |
| 07 | [batch-07.md](references/batch-07.md) | Scenario DSL, schema validation, and publishing |
| 08 | [batch-08.md](references/batch-08.md) | Fault runtime and ten fault operator families |
| 09 | [batch-09.md](references/batch-09.md) | Gold isolation, scenario suites, and benchmark corpus |
| 10 | [batch-10.md](references/batch-10.md) | Durable run orchestration and lifecycle state machine |
| 11 | [batch-11.md](references/batch-11.md) | Data-quality and interpretable univariate detection |
| 12 | [batch-12.md](references/batch-12.md) | Process residuals and cross-signal consistency |
| 13 | [batch-13.md](references/batch-13.md) | First-class symptoms, evidence, and evidence timeline |
| 14 | [batch-14.md](references/batch-14.md) | Causal graph, candidate generation, and Top-3 ranking |
| 15 | [batch-15.md](references/batch-15.md) | Discriminative check library and safe plan ordering |
| 16 | [batch-16.md](references/batch-16.md) | Agent Control Plane tools and deny-by-default policies |
| 17 | [batch-17.md](references/batch-17.md) | Human approval, plan binding, and durable interruption |
| 18 | [batch-18.md](references/batch-18.md) | Simulation-only actions, verification, and rollback |
| 19 | [batch-19.md](references/batch-19.md) | Replay, experiments, and Champion/Challenger comparison |
| 20 | [batch-20.md](references/batch-20.md) | Evaluator, reports, and non-bypassable Release Gate |
| 21 | [batch-21.md](references/batch-21.md) | Web/admin completion, RBAC, audit, and health |
| 22 | [batch-22.md](references/batch-22.md) | Historical data import and signal mapping |
| 23 | [batch-23.md](references/batch-23.md) | Edge read-only connector and real Shadow pilot |
| 24 | [batch-24.md](references/batch-24.md) | Security, resilience, performance, and production closure |

## Select the batch

1. Use the batch explicitly named by the user.
2. If the user asks to continue, inspect `IMPLEMENTATION_STATUS.yaml`, Git state, code, migrations, and evidence. Choose the first batch whose dependencies are complete but whose DoD is not proven.
3. Treat checked boxes, prose claims, static screenshots, generated JSON, or a package validator as insufficient proof of coding completion.
4. If prior batches are incomplete, report the exact missing executable contracts and implement the earliest blocker unless the user explicitly scopes work otherwise.

## Execute the batch

1. Inspect `AGENTS.md`, repository conventions, current changes, dependency manifests, migrations, API schemas, and existing tests.
2. Establish a preflight baseline. Run the narrowest relevant existing build and test commands before editing; preserve unrelated user changes.
3. Verify every declared input. Do not fabricate an earlier module, endpoint, table, fixture, credential, or external service.
4. Implement the batch inside the exact module boundaries in its reference. Reuse prior contracts; do not create parallel domain types or duplicate services.
5. Enforce failure, permission, privacy, and safety behavior at the server or execution boundary, not only in the UI or prompt.
6. Add migrations, typed schemas, seeds/fixtures, API/event contracts, observability, and documentation required by the batch.
7. Run unit, contract, integration, scenario, E2E, safety, and performance checks specified by the batch. Use real local dependencies through the Compose profile when required; mocks alone cannot prove integration.
8. Save raw evidence under `docs/evidence/batch-XX/`. Include commands, exit codes, machine-readable test reports, relevant logs/traces, schema/contract outputs, and artifact digests. Redact secrets and Gold content.
9. Update `IMPLEMENTATION_STATUS.yaml` only after verification. Record `status`, Git commit when available, commands, evidence paths, known limits, and the exact DoD items passed.
10. Report implemented behavior, files changed, tests run, concrete evidence, and remaining risks. Never say “complete” when critical verification was skipped or blocked.

## Apply global coding gates

- Keep real endpoint clients physically read-only. Do not import or expose OPC UA Write/Call in the real connector process.
- Keep the simulator action executor on a network and credential plane with no route to real OT endpoints.
- Store `scenario_spec` and `gold_spec` separately. Gold must never appear in Agent input, UI payloads, ordinary logs, traces, or report narratives before evaluation.
- Make every side effect require `run_id`, `action_id`, `approval_id`, `plan_hash`, and `idempotency_key`.
- Use structured evidence references for numeric and state claims. The LLM may narrate evidence; it may not invent signals or calculate the authoritative residual.
- Return `DATA_UNTRUSTED` or `INCONCLUSIVE` instead of forcing a root cause.
- Version and digest every scenario, dataset, process model, detector, rule graph, check library, prompt, configuration, and build used by a run.
- Use migrations and backward-compatible API/event evolution. Do not hand-edit production tables.
- Reject TODO handlers, hard-coded success responses, skipped critical tests, empty repositories, static-only UIs, and in-memory substitutes presented as completed production storage.

## Validate this package

Run:

```bash
python scripts/validate_batch_contracts.py .
```

This validates specification structure only. It never proves that a target repository has implemented a batch.
