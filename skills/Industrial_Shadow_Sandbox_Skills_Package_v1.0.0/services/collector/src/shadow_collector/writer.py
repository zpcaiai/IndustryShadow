from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict
from pathlib import Path

from shadow_sandbox.common import DomainError, Store
from shadow_sandbox.common.models import canonical_digest, canonical_json
from shadow_sandbox.common.tenant_scope import workspace_scope
from shadow_sandbox.observability.metrics import INGESTION_LAST_RECEIVED

from .models import RawSignalEvent


class RawEventWriter:
    def __init__(self, store: Store) -> None:
        self.store = store

    def persist(self, events: Iterable[RawSignalEvent]) -> int:
        batch = tuple(events)
        if not batch:
            return 0
        workspace_ids = {event.workspace_id for event in batch}
        if len(workspace_ids) != 1:
            raise DomainError(
                "MIXED_WORKSPACE_BATCH",
                "raw event writes must contain exactly one workspace",
            )
        inserted = 0
        with workspace_scope(workspace_ids.pop()), self.store.transaction() as tx:
                for event in batch:
                    cursor = tx.execute(
                        """INSERT OR IGNORE INTO raw_signal_events
                           (logical_id, tenant_id, workspace_id, run_id, scenario_id,
                            endpoint_id, node_id, signal_key, data_type, value_json,
                            source_timestamp, server_timestamp, received_timestamp,
                            status_code, sequence, flags_json, event_digest)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            event.logical_id,
                            event.tenant_id,
                            event.workspace_id,
                            event.run_id,
                            event.scenario_id,
                            event.endpoint_id,
                            event.node_id,
                            event.signal_key,
                            event.data_type,
                            canonical_json(event.value),
                            event.source_timestamp,
                            event.server_timestamp,
                            event.received_timestamp,
                            event.status_code,
                            event.sequence,
                            canonical_json(event.flags),
                            event.digest,
                        ),
                    )
                    inserted += cursor.rowcount
                    if cursor.rowcount:
                        INGESTION_LAST_RECEIVED.labels(
                            event.endpoint_id
                        ).set_to_current_time()
        return inserted

    def query(self, run_id: str, signal_key: str | None = None) -> list[RawSignalEvent]:
        sql = "SELECT * FROM raw_signal_events WHERE run_id=?"
        params: list[object] = [run_id]
        if signal_key:
            sql += " AND signal_key=?"
            params.append(signal_key)
        sql += " ORDER BY source_timestamp, sequence"
        rows = self.store.query(sql, params)
        return [
            RawSignalEvent(
                tenant_id=row["tenant_id"],
                workspace_id=row["workspace_id"],
                run_id=row["run_id"],
                scenario_id=row["scenario_id"],
                endpoint_id=row["endpoint_id"],
                node_id=row["node_id"],
                signal_key=row["signal_key"],
                data_type=row["data_type"],
                value=json.loads(row["value_json"]),
                source_timestamp=row["source_timestamp"],
                server_timestamp=row["server_timestamp"],
                received_timestamp=row["received_timestamp"],
                status_code=row["status_code"],
                sequence=row["sequence"],
                flags=tuple(json.loads(row["flags_json"])),
            )
            for row in rows
        ]

    def export_parquet(
        self, run_id: str, output_directory: str | Path
    ) -> dict[str, object]:
        try:
            import pyarrow as pa  # type: ignore[import-not-found]
            import pyarrow.parquet as pq  # type: ignore[import-not-found]
        except ImportError as exc:
            raise DomainError(
                "PARQUET_DEPENDENCY_UNAVAILABLE",
                "PyArrow is required for lossless Parquet export",
                status=503,
            ) from exc
        events = self.query(run_id)
        records = [asdict(event) for event in events]
        table = pa.Table.from_pylist(records)
        output = Path(output_directory)
        output.mkdir(parents=True, exist_ok=True)
        content_digest = canonical_digest(records)
        path = output / f"{content_digest}.parquet"
        pq.write_table(table, path, compression="zstd", use_dictionary=True)
        file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        return {
            "path": str(path),
            "row_count": len(records),
            "content_digest": content_digest,
            "file_digest": file_hash,
        }
