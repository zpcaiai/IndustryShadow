from __future__ import annotations

import argparse
import datetime as dt
import signal
import time
from collections.abc import Sequence
from pathlib import Path

from shadow_sandbox.approvals import ApprovalService
from shadow_sandbox.common import DomainError, Store
from shadow_sandbox.common.config import Settings
from shadow_sandbox.common.db import open_store


class MaintenanceWorker:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.running = True

    def stop(self, *_args: object) -> None:
        self.running = False

    def tick(self) -> dict[str, int]:
        expired = ApprovalService(self.store).expire_due()
        now = dt.datetime.now(dt.UTC)
        interrupted = self.store.execute(
            """UPDATE action_executions SET state='RECOVERY_REQUIRED', updated_at=?
                 WHERE state IN ('CLAIMED','STARTED') AND updated_at<?""",
            (
                now.isoformat().replace("+00:00", "Z"),
                (now - dt.timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            ),
        ).rowcount
        return {"expired_approvals": expired, "interrupted_actions": interrupted}

    def run(self, interval_seconds: float = 5.0) -> None:
        while self.running:
            self.tick()
            time.sleep(interval_seconds)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run approval-expiry and interrupted-action maintenance"
    )
    parser.add_argument("--interval-seconds", type=float, default=5.0)
    args = parser.parse_args(argv)
    if args.interval_seconds <= 0:
        parser.error("--interval-seconds must be greater than zero")
    settings = Settings.from_environment()
    settings.validate_worker()
    store = open_store(
        settings.database_url,
        Path(__file__).resolve().parents[3] / "migrations",
        migrate=settings.auto_migrate,
    )
    if settings.environment == "production":
        rows = store.query(
            """SELECT rolbypassrls AS bypass
                 FROM pg_roles WHERE rolname=current_user"""
        )
        if not rows or not bool(rows[0]["bypass"]):
            store.close()
            raise DomainError(
                "WORKER_DATABASE_ROLE_INVALID",
                "cross-workspace maintenance requires a dedicated BYPASSRLS role",
                status=503,
            )
    worker = MaintenanceWorker(store)
    signal.signal(signal.SIGTERM, worker.stop)
    signal.signal(signal.SIGINT, worker.stop)
    try:
        worker.run(args.interval_seconds)
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
