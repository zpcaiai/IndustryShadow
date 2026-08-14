from __future__ import annotations

import datetime as dt
import json
import math
import os
import re
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json, utc_now

STATUSES = frozenset({"PASSED", "FAILED", "NOT_RUN"})
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
DIGEST = re.compile(r"^[a-f0-9]{64}$")
SENSITIVE_NAMES = frozenset(
    {
        "access_key",
        "api_key",
        "authorization",
        "authorization_header",
        "bearer",
        "bearer_value",
        "bearer_values",
        "connection_string",
        "cookie",
        "credential",
        "credentials",
        "database_url",
        "dsn",
        "password",
        "private_key",
        "secret",
        "token",
    }
)
SENSITIVE_VALUE_SUFFIXES = frozenset(
    {"b64", "contents", "data", "plaintext", "raw", "text", "value", "values"}
)
SAFE_OPAQUE_NAMES = frozenset(
    {"checksum", "digest", "fingerprint", "hash", "public_key", "signature"}
)
URI_USERINFO = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s?#@]+(?::[^/\s?#@]*)?@")
BEARER_VALUE = re.compile(r"(?i)(?:^|[\s\"'=,:])bearer\s+[A-Za-z0-9._~+/=-]{16,}")
JWT_VALUE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\."
    r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
KNOWN_SECRET_VALUE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})|"
    r"(?:sk-|dckr_pat_|xox[baprs]-)[A-Za-z0-9_-]{20,})"
)
PRIVATE_KEY_VALUE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
OPAQUE_VALUE = re.compile(r"[A-Za-z0-9_+/=-]{32,}")
HEX_VALUE = re.compile(r"[A-Fa-f0-9]{64}")


def _normalized_name(value: str) -> str:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", separated.lower()).strip("_")


def _sensitive_name(value: str) -> bool:
    normalized = _normalized_name(value)
    if normalized in SENSITIVE_NAMES or any(
        normalized.endswith("_" + name) for name in SENSITIVE_NAMES
    ):
        return True
    return any(
        normalized == f"{name}_{suffix}"
        for name in SENSITIVE_NAMES
        for suffix in SENSITIVE_VALUE_SUFFIXES
    )


def _safe_opaque_name(value: str | None) -> bool:
    if value is None:
        return False
    normalized = _normalized_name(value)
    return any(
        normalized == name or normalized.endswith("_" + name) for name in SAFE_OPAQUE_NAMES
    ) or normalized.endswith(("_sha256", "_sha512"))


def _entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _sensitive_value(value: str, field_name: str | None) -> str | None:
    stripped = value.strip()
    if URI_USERINFO.search(stripped):
        return "uri_userinfo"
    if BEARER_VALUE.search(stripped):
        return "bearer_value"
    if JWT_VALUE.search(stripped):
        return "jwt_value"
    if PRIVATE_KEY_VALUE.search(stripped) or KNOWN_SECRET_VALUE.search(stripped):
        return "secret_key_value"
    if _safe_opaque_name(field_name):
        return None
    if HEX_VALUE.fullmatch(stripped):
        if _entropy(stripped) >= 3.5:
            return "high_entropy_value"
        return None
    if not OPAQUE_VALUE.fullmatch(stripped):
        return None
    character_classes = sum(
        (
            any(character.islower() for character in stripped),
            any(character.isupper() for character in stripped),
            any(character.isdigit() for character in stripped),
            any(character in "_+/=-" for character in stripped),
        )
    )
    if character_classes >= 2 and _entropy(stripped) >= 4.3:
        return "high_entropy_value"
    return None


def _assert_redacted(value: Any, path: str = "$", field_name: str | None = None) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if _sensitive_name(str(key)):
                raise DomainError(
                    "EVIDENCE_SECRET_FORBIDDEN",
                    "production evidence must not contain secret-bearing fields",
                    {"path": f"{path}.{key}"},
                )
            _assert_redacted(child, f"{path}.{key}", str(key))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _assert_redacted(child, f"{path}[{index}]", field_name)
    elif isinstance(value, str):
        reason = _sensitive_value(value, field_name)
        if reason is not None:
            raise DomainError(
                "EVIDENCE_SECRET_FORBIDDEN",
                "production evidence must not contain secret-bearing values",
                {"path": path, "reason": reason},
            )


@dataclass(frozen=True, slots=True)
class GateCheck:
    name: str
    passed: bool
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GateEvidence:
    schema_version: int
    gate: str
    status: str
    target_digest: str
    started_at: str
    completed_at: str
    checks: tuple[GateCheck, ...]
    metrics: Mapping[str, float | int | str]
    limitations: tuple[str, ...]
    tool_version: str = "production-gate-v1"
    acceptance_run_id: str = ""
    release_digest: str = ""
    digest: str = ""

    def __post_init__(self) -> None:
        if self.schema_version not in {1, 2} or self.status not in STATUSES or not self.gate:
            raise DomainError("GATE_EVIDENCE_INVALID", "gate evidence contract is invalid")
        if not DIGEST.fullmatch(self.target_digest):
            raise DomainError("GATE_EVIDENCE_INVALID", "target digest is invalid")
        try:
            started = dt.datetime.fromisoformat(self.started_at)
            completed = dt.datetime.fromisoformat(self.completed_at)
        except ValueError as error:
            raise DomainError("GATE_EVIDENCE_INVALID", "gate timestamps are invalid") from error
        if started.tzinfo is None or completed.tzinfo is None or completed < started:
            raise DomainError("GATE_EVIDENCE_INVALID", "gate time range is invalid")
        names = [item.name for item in self.checks]
        if any(not name for name in names) or len(names) != len(set(names)):
            raise DomainError("GATE_EVIDENCE_INVALID", "gate check names must be unique")
        if self.schema_version == 1 and (self.acceptance_run_id or self.release_digest):
            raise DomainError(
                "GATE_EVIDENCE_INVALID", "version 1 evidence cannot carry acceptance binding"
            )
        if self.schema_version == 2 and (
            not RUN_ID.fullmatch(self.acceptance_run_id)
            or not DIGEST.fullmatch(self.release_digest)
        ):
            raise DomainError(
                "GATE_EVIDENCE_INVALID",
                "version 2 evidence requires an acceptance run and release digest",
            )
        if self.status == "PASSED" and (
            not self.checks or not all(item.passed for item in self.checks)
        ):
            raise DomainError(
                "GATE_EVIDENCE_INVALID", "PASSED evidence requires every check to pass"
            )
        if self.status == "NOT_RUN" and self.checks:
            raise DomainError("GATE_EVIDENCE_INVALID", "NOT_RUN evidence cannot contain checks")
        if self.status == "NOT_RUN" and not self.limitations:
            raise DomainError("GATE_EVIDENCE_INVALID", "NOT_RUN evidence requires a limitation")
        if self.status == "FAILED" and (
            not self.checks or all(item.passed for item in self.checks)
        ):
            raise DomainError("GATE_EVIDENCE_INVALID", "FAILED evidence requires a failed check")
        _assert_redacted(asdict(self))

    @property
    def computed_digest(self) -> str:
        payload = asdict(self)
        payload["digest"] = ""
        return canonical_digest(payload)

    def sealed(self) -> GateEvidence:
        payload = asdict(self)
        payload["digest"] = self.computed_digest
        return GateEvidence(
            **{
                **payload,
                "checks": tuple(GateCheck(**item) for item in payload["checks"]),
            }
        )

    def verify(self) -> None:
        if not self.digest or self.digest != self.computed_digest:
            raise DomainError("GATE_EVIDENCE_DIGEST_INVALID", "gate evidence digest mismatch")


def target_digest(coordinates: Mapping[str, Any]) -> str:
    """Bind evidence to non-secret target coordinates without storing their values."""
    _assert_redacted(coordinates)
    return canonical_digest(coordinates)


def not_run(
    gate: str, limitation: str, coordinates: Mapping[str, Any] | None = None
) -> GateEvidence:
    now = utc_now()
    return GateEvidence(
        1,
        gate,
        "NOT_RUN",
        target_digest(coordinates or {"gate": gate}),
        now,
        now,
        (),
        {},
        (limitation,),
    ).sealed()


def complete(
    gate: str,
    *,
    started_at: str,
    coordinates: Mapping[str, Any],
    checks: Sequence[GateCheck],
    metrics: Mapping[str, float | int | str] | None = None,
    limitations: Sequence[str] = (),
    completed_at: str | None = None,
) -> GateEvidence:
    status = "PASSED" if checks and all(item.passed for item in checks) else "FAILED"
    return GateEvidence(
        1,
        gate,
        status,
        target_digest(coordinates),
        started_at,
        completed_at or utc_now(),
        tuple(checks),
        dict(metrics or {}),
        tuple(limitations),
    ).sealed()


def bind_to_acceptance_run(
    evidence: GateEvidence, *, run_id: str, release_digest: str
) -> GateEvidence:
    """Bind otherwise valid evidence to one immutable production acceptance run."""
    evidence.verify()
    return replace(
        evidence,
        schema_version=2,
        tool_version="production-gate-v2",
        acceptance_run_id=run_id,
        release_digest=release_digest,
        digest="",
    ).sealed()


def failed_execution(
    gate: str,
    *,
    started_at: str,
    error_code: str,
    run_id: str,
    release_digest: str,
) -> GateEvidence:
    """Persist a redacted failure record even when a probe aborts before checks run."""
    safe_code = error_code if re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", error_code) else "UNEXPECTED"
    evidence = complete(
        gate,
        started_at=started_at,
        coordinates={"gate": gate, "acceptance_run_id": run_id},
        checks=(GateCheck("execution_completed", False, {"error_code": safe_code}),),
        limitations=("gate_execution_failed",),
    )
    return bind_to_acceptance_run(evidence, run_id=run_id, release_digest=release_digest)


def write_evidence(path: str | Path, evidence: GateEvidence) -> Path:
    evidence.verify()
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".gate-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(canonical_json(asdict(evidence)) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return destination


def read_evidence(path: str | Path) -> GateEvidence:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    payload["checks"] = tuple(GateCheck(**item) for item in payload.get("checks", ()))
    evidence = GateEvidence(**payload)
    evidence.verify()
    return evidence
