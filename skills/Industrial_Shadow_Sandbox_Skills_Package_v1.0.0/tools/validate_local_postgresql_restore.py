from __future__ import annotations

import argparse
import os
from pathlib import Path
from urllib.parse import urlsplit

from shadow_sandbox.common.models import DomainError
from shadow_sandbox.operations.evidence import write_evidence
from shadow_sandbox.operations.restore_drill import PostgreSqlRestoreDrill


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise DomainError("LOCAL_RESTORE_CONFIG_MISSING", f"{name} is required")
    return value


def _local_database_url(name: str) -> str:
    value = _required(name)
    hostname = urlsplit(value.replace("postgresql+psycopg://", "postgresql://", 1)).hostname
    if hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise DomainError(
            "LOCAL_RESTORE_TARGET_FORBIDDEN",
            f"{name} must identify a loopback PostgreSQL endpoint",
        )
    return value


def _positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise DomainError("LOCAL_RESTORE_CONFIG_INVALID", f"{name} must be an integer") from error
    if value < 1:
        raise DomainError("LOCAL_RESTORE_CONFIG_INVALID", f"{name} must be positive")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a destructive restore only against an explicitly disposable local target"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/local-postgresql-restore-evidence.json"),
    )
    args = parser.parse_args()
    evidence = PostgreSqlRestoreDrill(
        _local_database_url("SHADOW_TEST_POSTGRESQL_URL"),
        _local_database_url("SHADOW_TEST_RESTORE_POSTGRESQL_URL"),
        allow_restore=os.environ.get("SHADOW_ALLOW_LOCAL_RESTORE_DRILL") == "true",
        maximum_restore_seconds=_positive_int(
            "SHADOW_LOCAL_RESTORE_MAXIMUM_SECONDS", 300
        ),
        maximum_archive_bytes=_positive_int(
            "SHADOW_LOCAL_RESTORE_MAXIMUM_ARCHIVE_BYTES", 1024**3
        ),
        managed_provider="local-disposable-postgresql",
        require_managed_coordinates=False,
    ).run()
    write_evidence(args.output, evidence)
    metrics = evidence.metrics
    print(
        "Local disposable PostgreSQL restore passed: "
        f"{metrics['tables']} tables, {metrics['rows']} rows, "
        f"{metrics['rls_policies']} RLS policies, "
        f"restore {metrics['restore_seconds']}s."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
