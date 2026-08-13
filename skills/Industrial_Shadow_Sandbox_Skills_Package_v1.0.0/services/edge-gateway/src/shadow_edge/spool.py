from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Self

from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now


class EncryptedSpool:
    def __init__(self, path: str | Path, key: bytes, max_bytes: int) -> None:
        if len(key) not in {16, 24, 32}:
            raise DomainError("EDGE_SPOOL_KEY_INVALID", "AES-GCM key must contain 16, 24, or 32 bytes")
        if max_bytes < 64:
            raise DomainError("EDGE_SPOOL_CAPACITY_INVALID", "encrypted spool capacity is too small")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import (
                AESGCM,  # type: ignore[import-not-found]
            )
        except ImportError as exc:
            raise DomainError(
                "CRYPTOGRAPHY_DEPENDENCY_UNAVAILABLE",
                "cryptography required",
                status=503,
            ) from exc
        self.cipher = AESGCM(key)
        self.max_bytes = max_bytes
        self.connection = sqlite3.connect(path)
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS spool (
               sequence INTEGER PRIMARY KEY, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
               payload_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL)"""
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def _size(self) -> int:
        row = self.connection.execute(
            "SELECT COALESCE(SUM(length(nonce) + length(ciphertext)), 0) FROM spool"
        ).fetchone()
        return int(row[0])

    def append(self, sequence: int, payload: bytes) -> str:
        if sequence <= 0:
            raise DomainError("EDGE_SEQUENCE_INVALID", "edge spool sequence must be positive")
        if not payload:
            raise DomainError("EDGE_PAYLOAD_INVALID", "edge spool payload must not be empty")
        digest = canonical_digest(payload.hex())
        existing = self.connection.execute(
            "SELECT payload_hash FROM spool WHERE sequence=?", (sequence,)
        ).fetchone()
        if existing:
            if str(existing[0]) == digest:
                return digest
            raise DomainError(
                "EDGE_SEQUENCE_CONFLICT", "edge spool sequence is already bound to another payload"
            )
        replay = self.connection.execute(
            "SELECT sequence FROM spool WHERE payload_hash=?", (digest,)
        ).fetchone()
        if replay:
            raise DomainError(
                "EDGE_PAYLOAD_REPLAY", "edge spool payload is already bound to another sequence"
            )
        if self._size() + len(payload) + 28 > self.max_bytes:
            raise DomainError(
                "EDGE_SPOOL_FULL", "encrypted offline spool reached bounded capacity"
            )
        nonce = os.urandom(12)
        associated = str(sequence).encode()
        ciphertext = self.cipher.encrypt(nonce, payload, associated)
        try:
            self.connection.execute(
                "INSERT INTO spool(sequence, nonce, ciphertext, payload_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (sequence, nonce, ciphertext, digest, utc_now()),
            )
            self.connection.commit()
        except sqlite3.IntegrityError as exc:
            self.connection.rollback()
            raise DomainError(
                "EDGE_SPOOL_CONFLICT", "concurrent edge spool sequence or payload conflict"
            ) from exc
        return digest

    def pending(self) -> Iterator[tuple[int, bytes, str]]:
        for sequence, nonce, ciphertext, digest in self.connection.execute(
            "SELECT sequence, nonce, ciphertext, payload_hash FROM spool ORDER BY sequence"
        ):
            yield (
                sequence,
                self.cipher.decrypt(nonce, ciphertext, str(sequence).encode()),
                digest,
            )

    def acknowledge_through(self, sequence: int) -> int:
        cursor = self.connection.execute(
            "DELETE FROM spool WHERE sequence<=?", (sequence,)
        )
        self.connection.commit()
        return cursor.rowcount
