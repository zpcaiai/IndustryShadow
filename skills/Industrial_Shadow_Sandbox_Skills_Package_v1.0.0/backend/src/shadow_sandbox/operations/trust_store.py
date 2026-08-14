from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError, canonical_digest

DIGEST = re.compile(r"^[a-f0-9]{64}$")
PURPOSES = frozenset(
    {
        "security_assessment",
        "privacy_assessment",
        "accessibility_assessment",
        "formal_measurement",
        "closure_release_owner",
        "closure_security_owner",
    }
)
STORE_KEYS = frozenset({"schema_version", "store_id", "issued_at", "signers", "digest"})
SIGNER_KEYS = frozenset(
    {
        "identity",
        "purposes",
        "public_key_sha256",
        "valid_from",
        "valid_until",
        "status",
    }
)
ROOT_ATTESTATION_KEYS = frozenset(
    {
        "schema_version",
        "trust_store_sha256",
        "root_key_sha256",
        "signed_at",
        "signature_b64",
    }
)


def _instant(value: Any, field: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(str(value))
    except ValueError as error:
        raise DomainError("TRUST_STORE_INVALID", f"{field} is not an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise DomainError("TRUST_STORE_INVALID", f"{field} must include a timezone")
    return parsed.astimezone(dt.UTC)


@dataclass(frozen=True, slots=True)
class TrustedSigner:
    identity: str
    purposes: tuple[str, ...]
    public_key_sha256: str
    valid_from: dt.datetime
    valid_until: dt.datetime
    status: str


class SignerTrustStore:
    """Digest-bound allowlist for external assessors and closure approvers."""

    def __init__(self, payload: Mapping[str, Any]) -> None:
        if set(payload) != STORE_KEYS or payload.get("schema_version") != 1:
            raise DomainError("TRUST_STORE_INVALID", "trust store fields are invalid")
        claimed = str(payload.get("digest", ""))
        if not DIGEST.fullmatch(claimed):
            raise DomainError("TRUST_STORE_INVALID", "trust store digest is invalid")
        expected = canonical_digest({**payload, "digest": ""})
        if claimed != expected:
            raise DomainError("TRUST_STORE_DIGEST_INVALID", "trust store digest mismatch")
        self.store_id = str(payload.get("store_id", "")).strip()
        self.issued_at = _instant(payload.get("issued_at"), "issued_at")
        self.digest = claimed
        if not self.store_id:
            raise DomainError("TRUST_STORE_INVALID", "trust store id is required")
        if self.issued_at > dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5):
            raise DomainError("TRUST_STORE_INVALID", "trust store issue time is in the future")
        raw_signers = payload.get("signers")
        if not isinstance(raw_signers, list) or not raw_signers:
            raise DomainError("TRUST_STORE_INVALID", "at least one trusted signer is required")
        signers: list[TrustedSigner] = []
        identities: set[tuple[str, str, str]] = set()
        for raw in raw_signers:
            if not isinstance(raw, Mapping) or set(raw) != SIGNER_KEYS:
                raise DomainError("TRUST_STORE_INVALID", "trusted signer fields are invalid")
            identity = str(raw.get("identity", "")).strip()
            purposes_value = raw.get("purposes")
            if (
                not identity
                or not isinstance(purposes_value, list)
                or not purposes_value
                or any(not isinstance(item, str) or item not in PURPOSES for item in purposes_value)
                or len(purposes_value) != len(set(purposes_value))
            ):
                raise DomainError("TRUST_STORE_INVALID", "signer identity or purposes are invalid")
            fingerprint = str(raw.get("public_key_sha256", ""))
            if not DIGEST.fullmatch(fingerprint):
                raise DomainError("TRUST_STORE_INVALID", "signer key fingerprint is invalid")
            valid_from = _instant(raw.get("valid_from"), "valid_from")
            valid_until = _instant(raw.get("valid_until"), "valid_until")
            status = str(raw.get("status", ""))
            if valid_until <= valid_from or status not in {"active", "revoked"}:
                raise DomainError("TRUST_STORE_INVALID", "signer validity or status is invalid")
            for purpose in purposes_value:
                key = (identity, purpose, fingerprint)
                if key in identities:
                    raise DomainError("TRUST_STORE_INVALID", "signer purpose is duplicated")
                identities.add(key)
            signers.append(
                TrustedSigner(
                    identity,
                    tuple(purposes_value),
                    fingerprint,
                    valid_from,
                    valid_until,
                    status,
                )
            )
        self.signers = tuple(signers)

    @classmethod
    def load(cls, path: str | Path) -> SignerTrustStore:
        source = Path(path)
        if source.is_symlink():
            raise DomainError("TRUST_STORE_INVALID", "trust store must not be a symlink")
        resolved = source.resolve(strict=True)
        if (
            not resolved.is_file()
            or resolved.stat().st_nlink != 1
            or not 1 <= resolved.stat().st_size <= 4 * 1024 * 1024
        ):
            raise DomainError("TRUST_STORE_INVALID", "trust store must be a safe regular file")
        value = json.loads(resolved.read_text(encoding="utf-8"))
        if not isinstance(value, Mapping):
            raise DomainError("TRUST_STORE_INVALID", "trust store must be an object")
        return cls(value)

    @classmethod
    def load_verified(
        cls,
        path: str | Path,
        *,
        root_attestation_path: str | Path,
        root_public_key_path: str | Path,
        expected_root_key_sha256: str,
    ) -> SignerTrustStore:
        """Load a trust store only after detached approval by a separately pinned root."""

        store_path = Path(path)
        attestation_path = Path(root_attestation_path)
        public_path = Path(root_public_key_path)
        if any(item.is_symlink() for item in (store_path, attestation_path, public_path)):
            raise DomainError("TRUST_ROOT_INVALID", "trust root inputs must not be symlinks")
        resolved_inputs = tuple(
            item.resolve(strict=True) for item in (store_path, attestation_path, public_path)
        )
        if any(
            not item.is_file()
            or item.stat().st_nlink != 1
            or not 1 <= item.stat().st_size <= 4 * 1024 * 1024
            for item in resolved_inputs
        ):
            raise DomainError(
                "TRUST_ROOT_INVALID", "trust root inputs must be safe regular files"
            )
        resolved_store, resolved_attestation, resolved_public = resolved_inputs
        store_bytes = resolved_store.read_bytes()
        try:
            attestation = json.loads(
                resolved_attestation.read_text(encoding="utf-8")
            )
        except json.JSONDecodeError as error:
            raise DomainError("TRUST_ROOT_INVALID", "root attestation is invalid JSON") from error
        if not isinstance(attestation, Mapping) or set(attestation) != ROOT_ATTESTATION_KEYS:
            raise DomainError("TRUST_ROOT_INVALID", "root attestation fields are invalid")
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            public_bytes = resolved_public.read_bytes()
            try:
                public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
                raw_public = public_bytes
            except ValueError:
                loaded = serialization.load_pem_public_key(public_bytes)
                if not isinstance(loaded, Ed25519PublicKey):
                    raise TypeError("root key is not Ed25519")
                public_key = loaded
                raw_public = loaded.public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            root_digest = hashlib.sha256(raw_public).hexdigest()
            signed_at = _instant(attestation.get("signed_at"), "root signed_at")
            signed_payload = {
                "schema_version": 1,
                "trust_store_sha256": hashlib.sha256(store_bytes).hexdigest(),
                "root_key_sha256": root_digest,
                "signed_at": str(attestation.get("signed_at")),
            }
            if (
                not DIGEST.fullmatch(expected_root_key_sha256)
                or root_digest != expected_root_key_sha256
                or attestation.get("schema_version") != 1
                or attestation.get("root_key_sha256") != root_digest
                or attestation.get("trust_store_sha256")
                != signed_payload["trust_store_sha256"]
                or signed_at > dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5)
                or dt.datetime.now(dt.UTC) - signed_at > dt.timedelta(days=365)
            ):
                raise ValueError("root coordinates are invalid")
            public_key.verify(
                base64.b64decode(str(attestation["signature_b64"]), validate=True),
                canonical_digest(signed_payload).encode("ascii"),
            )
        except Exception as error:
            raise DomainError(
                "TRUST_ROOT_INVALID", "trust store root signature is invalid"
            ) from error
        value = json.loads(store_bytes)
        if not isinstance(value, Mapping):
            raise DomainError("TRUST_STORE_INVALID", "trust store must be an object")
        result = cls(value)
        if signed_at < result.issued_at - dt.timedelta(minutes=5):
            raise DomainError(
                "TRUST_ROOT_INVALID", "root approval predates the trust store issue time"
            )
        if signed_at > result.issued_at + dt.timedelta(days=30):
            raise DomainError(
                "TRUST_ROOT_INVALID", "root approval is not timely for the trust store issue"
            )
        return result

    def verify_signer(
        self,
        *,
        identity: str,
        purpose: str,
        public_key_b64: str,
        signed_at: str,
    ) -> str:
        if purpose not in PURPOSES:
            raise DomainError("TRUST_PURPOSE_INVALID", "signer purpose is not supported")
        try:
            public_key = base64.b64decode(public_key_b64, validate=True)
        except Exception as error:
            raise DomainError("TRUST_SIGNER_KEY_INVALID", "signer public key is invalid") from error
        if len(public_key) != 32:
            raise DomainError("TRUST_SIGNER_KEY_INVALID", "signer public key must be Ed25519")
        fingerprint = hashlib.sha256(public_key).hexdigest()
        at = _instant(signed_at, "signed_at")
        if at > dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5):
            raise DomainError("TRUST_SIGNER_UNTRUSTED", "signature time is in the future")
        if at < self.issued_at:
            raise DomainError(
                "TRUST_SIGNER_UNTRUSTED", "signature predates the approved trust store"
            )
        matches = [
            signer
            for signer in self.signers
            if signer.identity == identity
            and purpose in signer.purposes
            and signer.public_key_sha256 == fingerprint
            and signer.status == "active"
            and signer.valid_from <= at <= signer.valid_until
        ]
        if len(matches) != 1:
            raise DomainError(
                "TRUST_SIGNER_UNTRUSTED",
                "signer identity, purpose, key, status, or validity is not trusted",
            )
        return fingerprint

    def required_purposes_present(self, purposes: Sequence[str]) -> bool:
        now = dt.datetime.now(dt.UTC)
        active = {
            purpose
            for signer in self.signers
            if signer.status == "active" and signer.valid_from <= now <= signer.valid_until
            for purpose in signer.purposes
        }
        return set(purposes).issubset(active)

    def purposes_have_distinct_keys(self, purposes: Sequence[str]) -> bool:
        required = set(purposes)
        ordered = sorted(required)
        now = dt.datetime.now(dt.UTC)
        fingerprints_by_purpose = {
            purpose: {
                signer.public_key_sha256
                for signer in self.signers
                if signer.status == "active"
                and signer.valid_from <= now <= signer.valid_until
                and purpose in signer.purposes
            }
            for purpose in required
        }
        return bool(required) and all(fingerprints_by_purpose.values()) and all(
            fingerprints_by_purpose[left].isdisjoint(fingerprints_by_purpose[right])
            for index, left in enumerate(ordered)
            for right in ordered[index + 1 :]
        )
