from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from shadow_sandbox.common import DomainError, SqliteStore
from shadow_sandbox.common.models import canonical_digest, canonical_json, utc_now


@dataclass(frozen=True, slots=True)
class EdgeEventBatch:
    gateway_id: str
    site_id: str
    sequence_start: int
    sequence_end: int
    mapping_digest: str
    events: tuple[Mapping[str, Any], ...]
    health_summary: Mapping[str, Any]
    source_batch_hash: str = ""

    def with_hash(self) -> EdgeEventBatch:
        data = asdict(self)
        data["source_batch_hash"] = ""
        return EdgeEventBatch(**{**data, "source_batch_hash": canonical_digest(data)})


class EdgeUplink:
    def __init__(self, store: SqliteStore, public_key: bytes) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )  # type: ignore[import-not-found]
        except ImportError as exc:
            raise DomainError(
                "CRYPTOGRAPHY_DEPENDENCY_UNAVAILABLE",
                "cryptography required",
                status=503,
            ) from exc
        self.store = store
        self.key = Ed25519PublicKey.from_public_bytes(public_key)

    def ingest(self, batch: EdgeEventBatch, signature_b64: str) -> dict[str, Any]:
        computed = batch.with_hash()
        if computed.source_batch_hash != batch.source_batch_hash:
            raise DomainError("EDGE_BATCH_TAMPERED", "batch content hash mismatch")
        try:
            self.key.verify(
                base64.b64decode(signature_b64),
                canonical_json(asdict(batch)).encode("utf-8"),
            )
        except Exception as exc:
            raise DomainError(
                "EDGE_BATCH_SIGNATURE_INVALID", "batch signature invalid"
            ) from exc
        cursor = self.store.execute(
            """INSERT OR IGNORE INTO edge_batches
               (gateway_id, sequence_start, sequence_end, batch_hash, payload, received_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                batch.gateway_id,
                batch.sequence_start,
                batch.sequence_end,
                batch.source_batch_hash,
                canonical_json(asdict(batch)),
                utc_now(),
            ),
        )
        return {
            "accepted": bool(cursor.rowcount),
            "batch_hash": batch.source_batch_hash,
        }
