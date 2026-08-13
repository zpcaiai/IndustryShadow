from __future__ import annotations

import dataclasses
import datetime as dt
import enum
import hashlib
import json
import math
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, cast

SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$")


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _json_value(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return _json_value(dataclasses.asdict(cast(Any, value)))
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_value(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, set):
        return sorted((_json_value(item) for item in value), key=repr)
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            raise ValueError("naive datetimes are forbidden")
        return value.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite numbers are forbidden")
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    return json.dumps(_json_value(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def validate_identifier(value: str, field_name: str = "identifier") -> str:
    if not SAFE_ID.fullmatch(value):
        raise DomainError("INVALID_IDENTIFIER", f"invalid {field_name}", {"field": field_name})
    return value


class DomainError(Exception):
    def __init__(
        self,
        code: str,
        detail: str,
        context: Mapping[str, Any] | None = None,
        status: int = 400,
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.context = dict(context or {})
        self.status = status

    def problem(self, instance: str | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": f"urn:industrial-shadow:problem:{self.code.lower()}",
            "title": self.code.replace("_", " ").title(),
            "status": self.status,
            "detail": self.detail,
            "code": self.code,
        }
        if instance:
            result["instance"] = instance
        if self.context:
            result["context"] = self.context
        return result


@dataclass(frozen=True, slots=True)
class ActorContext:
    actor_id: str
    tenant_id: str
    workspace_id: str
    roles: frozenset[str] = field(default_factory=frozenset)
    service: bool = False
    trace_id: str = field(default_factory=lambda: new_id("trace"))

    def require_role(self, *allowed: str) -> None:
        if not self.roles.intersection(allowed):
            raise DomainError("FORBIDDEN", "actor lacks required role", status=403)


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    event_type: str
    payload: Mapping[str, Any]
    tenant_id: str
    workspace_id: str
    run_id: str | None = None
    trace_id: str | None = None
    schema_version: int = 1
    event_id: str = field(default_factory=lambda: new_id("evt"))
    occurred_at: str = field(default_factory=utc_now)

    @property
    def digest(self) -> str:
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    code: str
    reason: str
    policy_digest: str
    decision_id: str = field(default_factory=lambda: new_id("policy"))
