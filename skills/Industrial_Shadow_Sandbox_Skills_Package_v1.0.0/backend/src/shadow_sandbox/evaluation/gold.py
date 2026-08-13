from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from shadow_sandbox.common import ActorContext, DomainError, Store
from shadow_sandbox.common.models import canonical_digest, canonical_json, utc_now


@dataclass(frozen=True, slots=True)
class GoldSpec:
    gold_id: str
    version: int
    scenario_ref: str
    root_causes: tuple[str, ...]
    expected_symptoms: tuple[str, ...]
    required_checks: tuple[Mapping[str, Any], ...]
    critical_safety_steps: tuple[str, ...]
    forbidden_actions: tuple[str, ...]
    provenance: Mapping[str, Any]

    def validate(self) -> None:
        if self.version <= 0 or not self.root_causes:
            raise DomainError("GOLD_INVALID", "Gold requires a positive version and root cause")
        if not self.expected_symptoms or not self.required_checks:
            raise DomainError("GOLD_INVALID", "Gold requires symptoms and checks")
        weight = sum(float(item.get("weight", 0)) for item in self.required_checks)
        if weight <= 0:
            raise DomainError("GOLD_INVALID", "required check weights must be positive")
        if not self.provenance.get("labeler"):
            raise DomainError("GOLD_PROVENANCE_REQUIRED", "Gold labeler provenance is required")

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


class Cipher(Protocol):
    key_ref: str

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> tuple[bytes, bytes]: ...

    def decrypt(self, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes: ...


class AesGcmCipher:
    def __init__(self, key: bytes, key_ref: str) -> None:
        if len(key) not in {16, 24, 32}:
            raise ValueError("AES-GCM key must contain 16, 24, or 32 bytes")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import (
                AESGCM,  # type: ignore[import-not-found]
            )
        except ImportError as exc:
            raise DomainError(
                "CRYPTOGRAPHY_DEPENDENCY_UNAVAILABLE",
                "cryptography is required for the Gold Vault",
                status=503,
            ) from exc
        self._cipher = AESGCM(key)
        self.key_ref = key_ref

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        return nonce, self._cipher.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
        return self._cipher.decrypt(nonce, ciphertext, associated_data)


class GoldVault:
    def __init__(self, store: Store, cipher: Cipher) -> None:
        self.store = store
        self.cipher = cipher

    @staticmethod
    def _require_evaluator(actor: ActorContext) -> None:
        if not actor.service or "EvaluatorService" not in actor.roles:
            raise DomainError("GOLD_ACCESS_DENIED", "Gold is evaluator-service only", status=403)

    def seal(self, actor: ActorContext, gold: GoldSpec) -> str:
        self._require_evaluator(actor)
        gold.validate()
        associated = canonical_json(
            [actor.workspace_id, gold.gold_id, gold.version, gold.scenario_ref, self.cipher.key_ref]
        ).encode("utf-8")
        nonce, ciphertext = self.cipher.encrypt(
            canonical_json(asdict(gold)).encode("utf-8"), associated
        )
        self.store.execute(
            """INSERT INTO gold_vault
               (gold_id, workspace_id, version, scenario_ref, key_ref, nonce,
                ciphertext, digest, sealed, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
            (
                gold.gold_id,
                actor.workspace_id,
                gold.version,
                gold.scenario_ref,
                self.cipher.key_ref,
                nonce,
                ciphertext,
                gold.digest,
                utc_now(),
            ),
        )
        self.store.audit(
            actor_id=actor.actor_id,
            tenant_id=actor.tenant_id,
            workspace_id=actor.workspace_id,
            action="gold.seal",
            target=f"{gold.gold_id}@{gold.version}",
            result="allowed",
            trace_id=actor.trace_id,
            details={"digest": gold.digest, "scenario_ref": gold.scenario_ref},
        )
        return gold.digest

    def resolve(self, actor: ActorContext, gold_id: str, version: int) -> GoldSpec:
        try:
            self._require_evaluator(actor)
        except DomainError:
            self.store.audit(
                actor_id=actor.actor_id,
                tenant_id=actor.tenant_id,
                workspace_id=actor.workspace_id,
                action="gold.resolve",
                target=f"{gold_id}@{version}",
                result="denied",
                trace_id=actor.trace_id,
            )
            raise
        rows = self.store.query(
            """SELECT * FROM gold_vault
               WHERE gold_id=? AND workspace_id=? AND version=?""",
            (gold_id, actor.workspace_id, version),
        )
        if not rows:
            raise DomainError("GOLD_NOT_FOUND", "Gold version not found", status=404)
        row = rows[0]
        associated = canonical_json(
            [actor.workspace_id, gold_id, version, row["scenario_ref"], row["key_ref"]]
        ).encode("utf-8")
        plaintext = self.cipher.decrypt(row["nonce"], row["ciphertext"], associated)
        data = json.loads(plaintext)
        result = GoldSpec(
            gold_id=data["gold_id"],
            version=data["version"],
            scenario_ref=data["scenario_ref"],
            root_causes=tuple(data["root_causes"]),
            expected_symptoms=tuple(data["expected_symptoms"]),
            required_checks=tuple(data["required_checks"]),
            critical_safety_steps=tuple(data["critical_safety_steps"]),
            forbidden_actions=tuple(data["forbidden_actions"]),
            provenance=data["provenance"],
        )
        if result.digest != row["digest"]:
            raise DomainError("GOLD_TAMPERED", "Gold digest mismatch")
        return result

    def metadata(self, actor: ActorContext, gold_id: str, version: int) -> dict[str, Any]:
        rows = self.store.query(
            """SELECT gold_id, version, scenario_ref, key_ref, digest, sealed, created_at
               FROM gold_vault WHERE gold_id=? AND workspace_id=? AND version=?""",
            (gold_id, actor.workspace_id, version),
        )
        if not rows:
            raise DomainError("GOLD_NOT_FOUND", "Gold version not found", status=404)
        return rows[0]
