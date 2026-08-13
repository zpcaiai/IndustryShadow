from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from shadow_sandbox.common import (
    DomainError,
    LocalObjectStorage,
    ObjectStorage,
    Store,
)
from shadow_sandbox.common.models import (
    canonical_digest,
    canonical_json,
    new_id,
    utc_now,
)

from .model import OperatingMode, ProcessCommand, ProcessState, SimulatorEngine


def _lists(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_lists(item) for item in value]
    if isinstance(value, list):
        return [_lists(item) for item in value]
    if isinstance(value, dict):
        return {key: _lists(child) for key, child in value.items()}
    return value


def _tuples(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(_tuples(item) for item in value)
    if isinstance(value, dict):
        return {key: _tuples(child) for key, child in value.items()}
    return value


@dataclass(frozen=True, slots=True)
class SnapshotEnvelope:
    snapshot_id: str
    simulator_id: str
    run_id: str | None
    reason: str
    simulation_time: float
    model_digest: str
    parameter_digest: str
    asset_model_digest: str
    simulator_build_digest: str
    state: Mapping[str, Any]
    command: Mapping[str, Any]
    rng_state: Any
    active_faults: Mapping[str, Any]
    pending_events: tuple[Mapping[str, Any], ...]
    source_sequence: int
    codec_version: int = 1
    parent_snapshot_id: str | None = None
    content_hash: str = ""

    def with_hash(self) -> SnapshotEnvelope:
        data = asdict(self)
        data["content_hash"] = ""
        return SnapshotEnvelope(**{**data, "content_hash": canonical_digest(data)})


class SnapshotService:
    def __init__(
        self,
        store: Store,
        directory: str | Path,
        object_storage: ObjectStorage | None = None,
    ) -> None:
        self.store = store
        self.directory = Path(directory)
        self.storage = object_storage or LocalObjectStorage(self.directory)

    def create(
        self,
        simulator_id: str,
        engine: SimulatorEngine,
        reason: str,
        run_id: str | None = None,
        parent_snapshot_id: str | None = None,
        protected: bool = False,
    ) -> SnapshotEnvelope:
        snapshot_id = new_id("snapshot")
        with engine.synchronized():
            faults = (
                engine.fault_runtime.snapshot_state() if engine.fault_runtime else {}
            )
            envelope = SnapshotEnvelope(
                snapshot_id,
                simulator_id,
                run_id,
                reason,
                engine.simulation_time,
                engine.model_digest,
                engine.parameters.digest,
                engine.asset_model_digest,
                engine.simulator_build_digest,
                asdict(engine.state),
                asdict(engine.last_command),
                _lists(engine.rng.getstate()),
                faults,
                tuple(engine.pending_events),
                engine.sequence,
                parent_snapshot_id=parent_snapshot_id,
            ).with_hash()
        encoded = canonical_json(asdict(envelope)).encode("utf-8")
        self.storage.put_bytes(
            f"snapshots/{envelope.content_hash}.snapshot.json",
            encoded,
            content_type="application/vnd.industrial-shadow.snapshot+json",
        )
        self.store.execute(
            """INSERT INTO snapshots
               (snapshot_id, simulator_id, run_id, reason, content_hash, envelope,
                protected, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                snapshot_id,
                simulator_id,
                run_id,
                reason,
                envelope.content_hash,
                encoded.decode("utf-8"),
                protected,
                utc_now(),
            ),
        )
        return envelope

    def load(self, snapshot_id: str) -> SnapshotEnvelope:
        rows = self.store.query(
            "SELECT envelope FROM snapshots WHERE snapshot_id=?", (snapshot_id,)
        )
        if not rows:
            raise DomainError("SNAPSHOT_NOT_FOUND", "snapshot not found", status=404)
        encoded = str(rows[0]["envelope"]).encode("utf-8")
        # The envelope's own hash is verified below; object equality additionally
        # detects partial database/object-store restore combinations.
        raw_data = json.loads(encoded)
        object_bytes = self.storage.get_bytes(
            f"snapshots/{raw_data['content_hash']}.snapshot.json",
            maximum_bytes=16 * 1024 * 1024,
        )
        if object_bytes != encoded:
            raise DomainError(
                "SNAPSHOT_STORAGE_MISMATCH", "snapshot replicas differ", status=503
            )
        data = raw_data
        content_hash = data.pop("content_hash")
        actual = canonical_digest({**data, "content_hash": ""})
        if actual != content_hash:
            raise DomainError("SNAPSHOT_CORRUPT", "snapshot content hash mismatch")
        return SnapshotEnvelope(**{**data, "content_hash": content_hash})

    def restore(self, engine: SimulatorEngine, snapshot_id: str) -> SnapshotEnvelope:
        envelope = self.load(snapshot_id)
        if envelope.model_digest != engine.model_digest:
            raise DomainError(
                "SNAPSHOT_INCOMPATIBLE", "model digest differs", status=409
            )
        with engine.synchronized():
            old = (
                engine.state,
                engine.last_command,
                engine.simulation_time,
                engine.sequence,
                engine.rng.getstate(),
                list(engine.pending_events),
                engine.fault_runtime.snapshot_state() if engine.fault_runtime else None,
            )
            try:
                state_data = dict(envelope.state)
                state_data["mode"] = OperatingMode(state_data["mode"])
                engine.state = ProcessState(**state_data)
                engine.last_command = ProcessCommand(**envelope.command)
                engine.simulation_time = envelope.simulation_time
                engine.sequence = envelope.source_sequence
                engine.rng.setstate(_tuples(envelope.rng_state))
                engine.pending_events = [dict(item) for item in envelope.pending_events]
                if engine.fault_runtime:
                    engine.fault_runtime.restore_state(envelope.active_faults)
            except Exception:
                (
                    engine.state,
                    engine.last_command,
                    engine.simulation_time,
                    engine.sequence,
                    rng,
                    engine.pending_events,
                    fault_state,
                ) = old
                engine.rng.setstate(rng)
                if engine.fault_runtime and fault_state is not None:
                    engine.fault_runtime.restore_state(fault_state)
                raise
        return envelope
