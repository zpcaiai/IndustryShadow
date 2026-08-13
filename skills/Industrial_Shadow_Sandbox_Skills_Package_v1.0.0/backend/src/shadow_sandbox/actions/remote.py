from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import asdict
from typing import Any
from urllib.parse import urlsplit

from shadow_sandbox.approvals import ApprovalService
from shadow_sandbox.common import DomainError
from shadow_sandbox.common.models import canonical_digest, canonical_json, new_id, utc_now
from shadow_sandbox.observability.metrics import VIRTUAL_ACTIONS

from . import ActionRequest, ActionResult


class FixedJsonClient:
    """Small bounded HTTP client whose authority can only come from trusted config."""

    def __init__(self, base_url: str, token: str, *, timeout_seconds: float = 10.0) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise DomainError(
                "SERVICE_URL_INVALID", "service URL must be absolute HTTP(S)", status=503
            )
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise DomainError(
                "SERVICE_URL_INVALID", "credentials, query and fragment are forbidden", status=503
            )
        if len(token) < 32:
            raise DomainError(
                "INTERNAL_TOKEN_WEAK", "internal service token is too short", status=503
            )
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout_seconds = timeout_seconds

    def request(
        self, method: str, path: str, payload: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        if not path.startswith("/") or path.startswith("//"):
            raise DomainError(
                "SERVICE_PATH_INVALID", "only absolute local service paths are allowed"
            )
        data = canonical_json(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Internal-Token": self.token,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(1_048_577)
        except urllib.error.HTTPError as error:
            raw = error.read(65_537)
            try:
                problem = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                problem = {}
            raise DomainError(
                str(problem.get("code", "DEPENDENCY_REJECTED")),
                str(problem.get("detail", "internal dependency rejected the request")),
                problem.get("details", {}),
                status=error.code,
            ) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE",
                "internal dependency is unavailable",
                {"dependency": urlsplit(self.base_url).hostname},
                status=503,
            ) from error
        if len(raw) > 1_048_576:
            raise DomainError(
                "DEPENDENCY_RESPONSE_TOO_LARGE", "internal response exceeded 1 MiB", status=502
            )
        try:
            result = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise DomainError(
                "DEPENDENCY_RESPONSE_INVALID", "internal response was not JSON", status=502
            ) from error
        if not isinstance(result, dict):
            raise DomainError(
                "DEPENDENCY_RESPONSE_INVALID", "internal response must be an object", status=502
            )
        return result


class ActionServiceClient:
    """Control-plane port for the separately networked action executor."""

    def __init__(self, base_url: str, token: str) -> None:
        self.http = FixedJsonClient(base_url, token)

    def execute(
        self,
        request: ActionRequest,
        workspace_id: str,
        _verifier: Callable[[Any], tuple[str, tuple[str, ...]]],
    ) -> ActionResult:
        result = self.http.request(
            "POST",
            "/internal/v1/actions",
            {"workspace_id": workspace_id, "request": asdict(request)},
        )
        result["evidence_refs"] = tuple(result.get("evidence_refs", ()))
        try:
            return ActionResult(**result)
        except TypeError as error:
            raise DomainError(
                "ACTION_SERVICE_RESPONSE_INVALID",
                "action service returned an invalid result",
                status=502,
            ) from error


class SimulatorServiceClient:
    """Typed simulator-only adapter; arbitrary URLs and arbitrary node writes are impossible."""

    def __init__(self, base_url: str, token: str, simulator_id: str) -> None:
        self.http = FixedJsonClient(base_url, token)
        if not simulator_id or "/" in simulator_id or ".." in simulator_id:
            raise DomainError("SIMULATOR_ID_INVALID", "simulator ID is invalid", status=503)
        self.simulator_id = simulator_id
        self.prefix = f"/internal/v1/simulators/{simulator_id}"

    def identity(self) -> dict[str, Any]:
        return self.http.request("GET", self.prefix + "/identity")

    def state(self) -> dict[str, Any]:
        return self.http.request("GET", self.prefix + "/state")

    def snapshot(self, reason: str, run_id: str, *, protected: bool = True) -> dict[str, Any]:
        return self.http.request(
            "POST",
            self.prefix + "/snapshots",
            {"reason": reason, "run_id": run_id, "protected": protected},
        )

    def restore(self, snapshot_id: str) -> dict[str, Any]:
        return self.http.request("POST", self.prefix + "/restore", {"snapshot_id": snapshot_id})

    def execute_action(self, name: str, parameters: Mapping[str, float | str]) -> dict[str, Any]:
        return self.http.request(
            "POST", self.prefix + f"/actions/{name}", {"parameters": dict(parameters)}
        )


class RemoteActionExecutor:
    """Approval-bound, exactly-once, snapshot-first execution against an attested simulator."""

    def __init__(
        self,
        store: Any,
        approvals: ApprovalService,
        simulator: SimulatorServiceClient,
        expected_simulator_digest: str,
    ) -> None:
        self.store = store
        self.approvals = approvals
        self.simulator = simulator
        self.expected_simulator_digest = expected_simulator_digest

    def _result_from_row(self, row: Mapping[str, Any]) -> ActionResult | None:
        if not row.get("result_json"):
            return None
        value = json.loads(str(row["result_json"]))
        value["evidence_refs"] = tuple(value.get("evidence_refs", ()))
        return ActionResult(**value)

    def execute(
        self,
        request: ActionRequest,
        workspace_id: str,
        _verifier: Callable[[Any], tuple[str, tuple[str, ...]]],
    ) -> ActionResult:
        if request.simulator_digest != self.expected_simulator_digest:
            raise DomainError(
                "SIMULATOR_ATTESTATION_FAILED",
                "action request is bound to a different simulator digest",
                status=403,
            )
        identity = self.simulator.identity()
        if (
            identity.get("environment_type") != "simulator"
            or identity.get("identity_digest") != self.expected_simulator_digest
        ):
            raise DomainError(
                "SIMULATOR_ATTESTATION_FAILED", "simulator identity changed", status=403
            )
        numeric_parameters = {
            key: float(value)
            for key, value in request.parameters.items()
            if isinstance(value, (int, float))
        }
        self.approvals.verify(
            approval_id=request.approval_id,
            workspace_id=workspace_id,
            plan_hash=request.plan_hash,
            step_id=request.step_id,
            simulator_digest=request.simulator_digest,
            parameters=numeric_parameters,
        )
        existing = self.store.query(
            "SELECT * FROM action_executions WHERE idempotency_key=?", (request.idempotency_key,)
        )
        if existing:
            completed = self._result_from_row(existing[0])
            if completed:
                return completed
            return self._recover_interrupted(existing[0])

        action_id = new_id("action")
        pre = self.simulator.snapshot("pre-action", request.run_id)
        pre_id = str(pre["snapshot_id"])
        now = utc_now()
        self.store.execute(
            """INSERT INTO action_executions
               (action_id,run_id,approval_id,plan_hash,idempotency_key,state,request_json,
                pre_snapshot_id,created_at,updated_at)
               VALUES (?,?,?,?,?,'CLAIMED',?,?,?,?)""",
            (
                action_id,
                request.run_id,
                request.approval_id,
                request.plan_hash,
                request.idempotency_key,
                canonical_json(asdict(request)),
                pre_id,
                now,
                now,
            ),
        )
        self.store.execute(
            "UPDATE action_executions SET state='STARTED',updated_at=? WHERE action_id=?",
            (utc_now(), action_id),
        )
        post_id: str | None = None
        rollback_id: str | None = None
        evidence: tuple[str, ...] = ()
        try:
            action = self.simulator.execute_action(request.action_name, request.parameters)
            outcome = str(action.get("outcome", "UNCHANGED"))
            evidence = tuple(str(item) for item in action.get("evidence_refs", ()))
            post = self.simulator.snapshot("post-action", request.run_id)
            post_id = str(post["snapshot_id"])
            if outcome in {"WORSE", "EXECUTION_FAILED"}:
                self.simulator.restore(pre_id)
                rollback = self.simulator.snapshot("rollback-verified", request.run_id)
                rollback_id = str(rollback["snapshot_id"])
                state = "ROLLED_BACK"
            else:
                state = "COMPLETED"
        except Exception:  # noqa: BLE001 - dependency failures must trigger rollback
            try:
                self.simulator.restore(pre_id)
                rollback = self.simulator.snapshot("rollback-after-failure", request.run_id)
                rollback_id = str(rollback["snapshot_id"])
            except Exception as rollback_error:
                self.store.execute(
                    "UPDATE action_executions SET state='RECOVERY_REQUIRED',updated_at=? WHERE action_id=?",
                    (utc_now(), action_id),
                )
                VIRTUAL_ACTIONS.labels("RECOVERY_REQUIRED", "EXECUTION_FAILED").inc()
                raise DomainError(
                    "ACTION_RECOVERY_REQUIRED",
                    "action failed and automatic rollback could not be verified",
                    {"action_id": action_id, "rollback_error": type(rollback_error).__name__},
                    status=503,
                ) from rollback_error
            outcome = "EXECUTION_FAILED"
            state = "ROLLED_BACK"
            evidence = ()
        result = self._finish(
            action_id,
            state,
            outcome,
            pre_id,
            post_id,
            rollback_id,
            evidence,
        )
        return result

    def _recover_interrupted(self, row: Mapping[str, Any]) -> ActionResult:
        pre_id = str(row.get("pre_snapshot_id") or "")
        if not pre_id:
            raise DomainError(
                "ACTION_RECOVERY_REQUIRED",
                "interrupted action has no pre-action snapshot",
                {"action_id": row["action_id"]},
                status=503,
            )
        self.simulator.restore(pre_id)
        rollback = self.simulator.snapshot("rollback-interrupted-action", str(row["run_id"]))
        return self._finish(
            str(row["action_id"]),
            "ROLLED_BACK",
            "EXECUTION_FAILED",
            pre_id,
            row.get("post_snapshot_id"),
            str(rollback["snapshot_id"]),
            (),
        )

    def _finish(
        self,
        action_id: str,
        state: str,
        outcome: str,
        pre_snapshot_id: str,
        post_snapshot_id: str | None,
        rollback_snapshot_id: str | None,
        evidence_refs: tuple[str, ...],
    ) -> ActionResult:
        provisional = {
            "action_id": action_id,
            "state": state,
            "outcome": outcome,
            "pre_snapshot_id": pre_snapshot_id,
            "post_snapshot_id": post_snapshot_id,
            "rollback_snapshot_id": rollback_snapshot_id,
            "evidence_refs": evidence_refs,
            "result_digest": "",
        }
        result = ActionResult(**{**provisional, "result_digest": canonical_digest(provisional)})
        self.store.execute(
            """UPDATE action_executions SET state=?,result_json=?,post_snapshot_id=?,
               rollback_snapshot_id=?,updated_at=? WHERE action_id=?""",
            (
                state,
                canonical_json(asdict(result)),
                post_snapshot_id,
                rollback_snapshot_id,
                utc_now(),
                action_id,
            ),
        )
        return result
