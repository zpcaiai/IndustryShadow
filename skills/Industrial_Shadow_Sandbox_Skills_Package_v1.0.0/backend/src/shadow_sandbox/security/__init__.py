from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from shadow_sandbox.common import ActorContext, DomainError, Store
from shadow_sandbox.common.models import canonical_json

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "Viewer": frozenset({"run:view", "report:view"}),
    "Engineer": frozenset({"run:view", "run:create", "model:edit", "scenario:edit", "report:view"}),
    "Approver": frozenset({"run:view", "approval:view", "approval:decide", "report:view"}),
    "PackAuthor": frozenset(
        {"run:view", "pack:edit", "model:publish", "scenario:publish", "report:view"}
    ),
    "Admin": frozenset(
        {"run:view", "admin:manage", "endpoint:manage", "policy:manage", "report:view"}
    ),
    "Auditor": frozenset({"run:view", "audit:view", "report:view", "gold:metadata"}),
    "EvaluatorService": frozenset({"gold:resolve", "evaluation:execute"}),
    "ActionExecutorService": frozenset({"action:execute"}),
    "CollectorService": frozenset({"event:ingest"}),
}


def authorize(actor: ActorContext, permission: str) -> None:
    allowed = set().union(*(ROLE_PERMISSIONS.get(role, frozenset()) for role in actor.roles))
    if permission not in allowed:
        raise DomainError("FORBIDDEN", f"permission denied: {permission}", status=403)


SENSITIVE_KEYS = {"password", "token", "secret", "private_key", "gold", "ciphertext", "raw_value"}


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if str(key).lower() in SENSITIVE_KEYS else redact(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class LocalIdentityToken:
    actor_id: str
    tenant_id: str
    workspace_id: str
    roles: tuple[str, ...]
    expires_at: str
    service: bool = False


class LocalTokenCodec:
    """Development-only HMAC token codec; production uses validated OIDC JWTs."""

    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("development token key must be at least 32 bytes")
        self.key = key

    def encode(self, token: LocalIdentityToken) -> str:
        body = canonical_json(asdict(token)).encode("utf-8")
        signature = hmac.new(self.key, body, hashlib.sha256).digest()
        return (
            base64.urlsafe_b64encode(body).decode()
            + "."
            + base64.urlsafe_b64encode(signature).decode()
        )

    def decode(self, encoded: str) -> ActorContext:
        try:
            body_text, signature_text = encoded.split(".", 1)
            body = base64.urlsafe_b64decode(body_text)
            signature = base64.urlsafe_b64decode(signature_text)
        except Exception as exc:
            raise DomainError("TOKEN_INVALID", "malformed identity token", status=401) from exc
        expected = hmac.new(self.key, body, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise DomainError("TOKEN_INVALID", "identity signature invalid", status=401)
        data = json.loads(body)
        import datetime as dt

        if dt.datetime.fromisoformat(data["expires_at"]) <= dt.datetime.now(
            dt.UTC
        ):
            raise DomainError("TOKEN_EXPIRED", "identity token expired", status=401)
        return ActorContext(
            data["actor_id"],
            data["tenant_id"],
            data["workspace_id"],
            frozenset(data["roles"]),
            bool(data["service"]),
        )


class RetentionService:
    PROTECTED_KINDS = frozenset(
        {"gold", "evidence", "snapshot", "report", "audit", "certification"}
    )

    def __init__(self, store: Store) -> None:
        self.store = store

    def preview(self, workspace_id: str, before: str) -> dict[str, int]:
        rows = self.store.query(
            """SELECT kind, COUNT(*) AS count FROM artifacts
               WHERE workspace_id=? AND created_at<? GROUP BY kind""",
            (workspace_id, before),
        )
        return {row["kind"]: int(row["count"]) for row in rows}

    def delete_unprotected(self, workspace_id: str, before: str, legal_hold: bool = False) -> int:
        if legal_hold:
            raise DomainError("LEGAL_HOLD", "retention deletion blocked by legal hold", status=409)
        placeholders = ",".join("?" for _ in self.PROTECTED_KINDS)
        cursor = self.store.execute(
            f"""DELETE FROM artifacts WHERE workspace_id=? AND created_at<? AND sealed=0
                 AND kind NOT IN ({placeholders})""",
            (workspace_id, before, *sorted(self.PROTECTED_KINDS)),
        )
        return cursor.rowcount
