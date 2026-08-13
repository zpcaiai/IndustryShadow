from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError, utc_now

from .evidence import GateCheck, GateEvidence


@dataclass(frozen=True, slots=True)
class SloDefinition:
    sli: str
    target: float
    window: str
    owner: str
    alert: str
    runbook: str


DEFAULT_SLOS = (
    SloDefinition(
        "ingestion_freshness",
        0.99,
        "30d",
        "data-platform",
        "collector-stale",
        "collector-outage.md",
    ),
    SloDefinition("run_success", 0.99, "30d", "runtime", "run-failure", "worker-recovery.md"),
    SloDefinition(
        "diagnosis_latency", 0.95, "30d", "diagnosis", "diagnosis-slow", "diagnosis-latency.md"
    ),
    SloDefinition(
        "report_success", 0.99, "30d", "reporting", "report-failure", "report-recovery.md"
    ),
    SloDefinition(
        "safety_policy_violations",
        1.0,
        "always",
        "security",
        "policy-violation",
        "policy-violation.md",
    ),
)


class BackupService:
    def backup_sqlite(self, source: str | Path, destination: str | Path) -> dict[str, Any]:
        source_path = Path(source)
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        with (
            closing(sqlite3.connect(source_path)) as source_db,
            closing(sqlite3.connect(destination_path)) as destination_db,
        ):
            source_db.backup(destination_db)
        digest = hashlib.sha256(destination_path.read_bytes()).hexdigest()
        return {"path": str(destination_path), "sha256": digest, "created_at": utc_now()}

    def verify_restore(self, backup: str | Path) -> dict[str, Any]:
        with closing(sqlite3.connect(backup)) as connection:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            migrations = connection.execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()[0]
        if integrity != "ok":
            raise DomainError("BACKUP_CORRUPT", "restored database integrity check failed")
        return {"integrity": integrity, "migration_version": migrations}


class RecertificationPolicy:
    TRACKED_COORDINATES = frozenset(
        {"build", "dependency", "process_model", "domain_pack", "prompt", "policy", "schema"}
    )

    def requires_recertification(
        self, previous: Mapping[str, str], current: Mapping[str, str]
    ) -> tuple[str, ...]:
        return tuple(
            sorted(key for key in self.TRACKED_COORDINATES if previous.get(key) != current.get(key))
        )


__all__ = [
    "DEFAULT_SLOS",
    "BackupService",
    "GateCheck",
    "GateEvidence",
    "RecertificationPolicy",
    "SloDefinition",
]
