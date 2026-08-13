from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from shadow_sandbox.common import ActorContext, DomainError, PolicyDecision, Store
from shadow_sandbox.common.models import canonical_digest

ALLOWED_TOOLS = frozenset(
    {
        "get_asset_metadata",
        "query_signal_window",
        "query_events",
        "get_data_quality",
        "get_symptoms",
        "get_evidence",
        "query_causal_graph",
        "compute_registered_residual",
        "propose_check_plan",
        "request_virtual_action",
        "generate_report_narrative",
    }
)
FORBIDDEN_ARGUMENTS = frozenset(
    {"tenant_id", "workspace_id", "endpoint_url", "sql", "shell", "code", "path", "gold"}
)


@dataclass(frozen=True, slots=True)
class ToolContext:
    actor: ActorContext
    run_id: str
    environment_type: str
    allowed_signal_keys: frozenset[str]
    allowed_time_start: str
    allowed_time_end: str
    row_budget: int = 10_000
    payload_budget_bytes: int = 1_000_000
    call_budget: int = 25
    timeout_seconds: float = 5.0
    max_graph_depth: int = 3


@dataclass(frozen=True, slots=True)
class ToolResult:
    tool: str
    data: Any
    evidence_refs: tuple[str, ...]
    truncated: bool
    policy_decision_id: str
    duration_ms: float
    result_digest: str


class ToolPolicy:
    def __init__(self) -> None:
        self.policy_digest = canonical_digest(
            [sorted(ALLOWED_TOOLS), sorted(FORBIDDEN_ARGUMENTS), "v1"]
        )

    def authorize(
        self, context: ToolContext, tool: str, arguments: Mapping[str, Any]
    ) -> PolicyDecision:
        if tool not in ALLOWED_TOOLS:
            return PolicyDecision(
                False, "TOOL_DENIED", "tool is not registered", self.policy_digest
            )
        if FORBIDDEN_ARGUMENTS.intersection(arguments):
            return PolicyDecision(
                False,
                "OWNERSHIP_OR_UNSAFE_ARGUMENT",
                "trusted scope cannot come from model output",
                self.policy_digest,
            )
        if tool == "request_virtual_action" and context.environment_type != "simulator":
            return PolicyDecision(
                False, "REAL_ACTION_DENIED", "actions require simulator context", self.policy_digest
            )
        if int(arguments.get("limit", 0)) > context.row_budget:
            return PolicyDecision(
                False, "ROW_BUDGET_EXCEEDED", "query row budget exceeded", self.policy_digest
            )
        if int(arguments.get("depth", 0)) > context.max_graph_depth:
            return PolicyDecision(
                False, "GRAPH_DEPTH_EXCEEDED", "graph depth budget exceeded", self.policy_digest
            )
        signal = arguments.get("signal_key")
        if signal and signal not in context.allowed_signal_keys:
            return PolicyDecision(
                False, "SIGNAL_DENIED", "signal is not allowlisted", self.policy_digest
            )
        serialized = repr(arguments).lower()
        if any(
            marker in serialized
            for marker in (
                "file://",
                "http://",
                "https://",
                "select ",
                "drop table",
                "/bin/",
                "__import__",
            )
        ):
            return PolicyDecision(
                False, "INJECTION_DENIED", "unsafe argument content", self.policy_digest
            )
        return PolicyDecision(True, "ALLOWED", "registered bounded tool", self.policy_digest)


class ControlPlaneAdapter:
    def __init__(self, store: Store, handlers: Mapping[str, Callable[..., Any]]) -> None:
        extra = set(handlers) - ALLOWED_TOOLS
        if extra:
            raise DomainError(
                "UNSAFE_TOOL_REGISTRATION", "unregistered tools supplied", {"tools": sorted(extra)}
            )
        self.store = store
        self.handlers = dict(handlers)
        self.policy = ToolPolicy()
        self.calls: dict[str, int] = {}

    def invoke(self, context: ToolContext, tool: str, arguments: Mapping[str, Any]) -> ToolResult:
        scope = context.actor.trace_id
        self.calls[scope] = self.calls.get(scope, 0) + 1
        if self.calls[scope] > context.call_budget:
            raise DomainError("TOOL_CALL_BUDGET_EXCEEDED", "tool call budget exhausted", status=429)
        decision = self.policy.authorize(context, tool, arguments)
        if not decision.allowed:
            self._audit(context, tool, arguments, decision, "denied", None)
            raise DomainError(decision.code, decision.reason, status=403)
        handler = self.handlers.get(tool)
        if not handler:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "registered tool has no available service", status=503
            )
        start = time.monotonic()
        data = handler(context=context, **dict(arguments))
        duration_ms = (time.monotonic() - start) * 1000
        if duration_ms > context.timeout_seconds * 1000:
            raise DomainError("TOOL_TIMEOUT", "tool exceeded execution time budget", status=504)
        encoded = repr(data).encode("utf-8")
        truncated = len(encoded) > context.payload_budget_bytes
        if truncated:
            data = {"truncated": True, "digest": canonical_digest(data)}
        evidence_refs = tuple(data.get("evidence_refs", ()) if isinstance(data, Mapping) else ())
        digest = canonical_digest(data)
        self._audit(context, tool, arguments, decision, "allowed", digest)
        return ToolResult(
            tool, data, evidence_refs, truncated, decision.decision_id, duration_ms, digest
        )

    def _audit(
        self,
        context: ToolContext,
        tool: str,
        arguments: Mapping[str, Any],
        decision: PolicyDecision,
        result: str,
        result_digest: str | None,
    ) -> None:
        redacted = {
            key: "[REDACTED]" if "note" in key or "text" in key else value
            for key, value in arguments.items()
        }
        self.store.audit(
            actor_id=context.actor.actor_id,
            tenant_id=context.actor.tenant_id,
            workspace_id=context.actor.workspace_id,
            action=f"tool.{tool}",
            target=context.run_id,
            result=result,
            trace_id=context.actor.trace_id,
            details={
                "arguments_digest": canonical_digest(redacted),
                "decision_id": decision.decision_id,
                "result_digest": result_digest,
            },
        )
