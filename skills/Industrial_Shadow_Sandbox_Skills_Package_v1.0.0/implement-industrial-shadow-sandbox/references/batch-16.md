# Batch 16: Agent Control Plane tools and deny-by-default policies

## Context

- Completed dependencies: evidence, hypotheses, and Check Plan services.
- Reuse the existing Agent Control Plane when available; this batch implements a bounded adapter and typed tools, not a second general Agent platform.
- The Agent narrates and requests; deterministic services calculate and policies authorize.

## Outcome

- A diagnosis workflow can call a small typed tool set under workspace, Run, endpoint, Node, time, result-size, and parameter policies.
- Every tool call is schema-validated, audited, traced, rate-limited, and denied by default.
- Arbitrary code, SQL, HTTP, file, OPC UA Write/Call, Gold, and cross-workspace access are impossible through the tool layer.

## Inputs

- Existing Control Plane tool registry, policy, audit, sandbox, and identity interfaces if present.
- Asset/run/data-quality/evidence/graph/hypothesis/plan service APIs from Batches 02 and 10–15.
- Environment and endpoint policy metadata.
- LLM provider adapter is optional; deterministic tool-contract tests must run without external model credentials.

## Code modules

- `backend/src/shadow_sandbox/integrations/control_plane/adapter.py`.
- `backend/src/shadow_sandbox/integrations/control_plane/context.py`: trusted tool context.
- `backend/src/shadow_sandbox/integrations/control_plane/tools/metadata.py`.
- `backend/src/shadow_sandbox/integrations/control_plane/tools/timeseries.py`.
- `backend/src/shadow_sandbox/integrations/control_plane/tools/evidence.py`.
- `backend/src/shadow_sandbox/integrations/control_plane/tools/graph.py`.
- `backend/src/shadow_sandbox/integrations/control_plane/tools/planning.py`.
- `backend/src/shadow_sandbox/integrations/control_plane/policy.py` and `audit.py`.
- `backend/src/shadow_sandbox/diagnosis/workflow.py`: deterministic nodes plus optional narrative node.
- `schemas/tools/*.json`, `domain-packs/pump-tank-v1/rules/tool-policy.yaml`.
- `tests/security/tools/` and `web/src/features/admin/ToolAuditView.vue`.

## Interfaces

- Read tools: `get_asset_metadata`, `query_signal_window`, `query_events`, `get_data_quality`, `get_symptoms`, `get_evidence`, `query_causal_graph`.
- Compute tool: `compute_registered_residual`; accepts a registered residual ID and bounded input reference, never source code.
- Proposal tools: `propose_check_plan`, `request_virtual_action`; the latter creates an approval request only after Batch 17.
- Narrative tool: `generate_report_narrative` receives validated Claims/Evidence, not raw arbitrary databases.
- `ToolContextV1`: service/user identity, tenant/workspace, Run, allowed endpoints/Nodes/time, purpose, trace, token/row/time budgets, and environment type.
- `ToolResultV1`: typed result, evidence refs, truncation, policy decision ID, duration, and error.
- Tool errors: invalid schema, denied, budget exceeded, stale context, not found, rate-limited, and dependency unavailable.

## Implementation requirements

1. Generate JSON Schemas for every tool and reject unknown fields.
2. Derive tenant/workspace/Run ownership from trusted context; ignore ownership fields in model output.
3. Enforce endpoint, Node prefix, signal, time range, row count, payload size, call count, timeout, and rate budgets.
4. Permit only registered residuals and graph traversals of bounded depth.
5. Keep Agent workflow inputs to structured Symptoms/Evidence/Hypotheses/Plans and necessary metadata.
6. Validate every narrative claim with EvidenceValidator; unsupported claims are removed/rejected and recorded.
7. Treat asset names, alarm text, maintenance notes, and retrieved content as untrusted data that cannot change policy.
8. Do not register shell, arbitrary SQL, arbitrary HTTP, filesystem, Gold, Write, or MethodCall tools.
9. `request_virtual_action` cannot execute; it emits a proposal with simulator environment requirement.
10. Add timeouts, bounded retries for read-only calls, circuit breaking, and deterministic fallback summaries.
11. Audit request schema digest, redacted arguments, policy result, tool result digest, and Trace.
12. Make the core diagnostic result available when the LLM provider is unavailable.

## Tests

- Contract: validate success/failure examples against every tool schema.
- Policy: tenant/workspace/Run, Node/time/row/payload/call/depth/rate/timeout boundaries.
- Adversarial: Prompt Injection in asset/alarm/notes, tool-name spoofing, unknown fields, path/SQL/URL/shell payloads.
- Safety: attempts to register/call OPC UA Write/Call, Gold, arbitrary residual, or real action are denied.
- Claim grounding: unsupported numbers/signals/evidence refs fail; valid claims pass.
- Resilience: LLM unavailable, tool timeout, dependency failure, truncated query, and retry budget.
- Integration: workflow calls actual metadata/time-series/evidence/graph/plan services and emits correlated audit/Trace.
- UI: authorized auditor can filter calls while sensitive values remain redacted.

## Required evidence

- `docs/evidence/batch-16/manifest.json`.
- Tool schema registry and digest list.
- Policy decision matrix covering allow and deny paths.
- Prompt Injection/adversarial report with zero policy escapes.
- Write/Call/Gold/arbitrary-code denial logs and tool-registry inspection.
- Claim-grounding report and LLM-unavailable fallback trace.
- Integration trace linking workflow, tool calls, Evidence, and audit records.

## Definition of Done

- All declared tools invoke real typed domain services under trusted context and bounded policies.
- Unregistered tools/fields/residuals, excessive queries, cross-scope access, and unsafe actions are denied server-side.
- Every numeric narrative claim is Evidence-grounded or explicitly labeled an unverified human hypothesis.
- Agent untrusted text cannot modify policies or tool availability.
- Core structured diagnosis works without an LLM.
- Audit and Trace correlate every call without leaking secrets or Gold.
- No real control or arbitrary execution capability exists in the tool registry or adapter dependencies.

## Out of scope

- Human approval UI, virtual action execution, generic autonomous multi-Agent collaboration, and external web browsing.
- Training or fine-tuning an LLM.

