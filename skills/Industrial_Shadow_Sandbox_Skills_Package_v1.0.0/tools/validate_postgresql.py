from __future__ import annotations

import os
import uuid
from contextlib import closing
from dataclasses import asdict
from pathlib import Path

from shadow_sandbox.asset_registry import pump_tank_model
from shadow_sandbox.common import ActorContext, DomainError, ResourceRepository
from shadow_sandbox.common.db import open_store
from shadow_sandbox.common.tenant_scope import workspace_scope
from shadow_sandbox.runtime import RunManifest, RunOrchestrator

try:
    from .postgresql_test_roles import temporary_postgresql_test_role
except ImportError:  # pragma: no cover - direct script execution
    from postgresql_test_roles import temporary_postgresql_test_role

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    database_url = os.environ.get("SHADOW_TEST_POSTGRESQL_URL")
    if not database_url:
        raise SystemExit("SHADOW_TEST_POSTGRESQL_URL is required")
    suffix = uuid.uuid4().hex
    role = f"shadow_rls_probe_{suffix}"
    password = uuid.uuid4().hex
    admin_store = open_store(database_url, ROOT / "migrations")
    try:
        with temporary_postgresql_test_role(
            admin_store,
            role=role,
            password=password,
        ):
            identifier = f'"{role}"'
            admin_store.execute(f"GRANT USAGE ON SCHEMA public TO {identifier}")
            admin_store.execute(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public "
                f"TO {identifier}"
            )
            from sqlalchemy.engine import make_url

            role_url = (
                make_url(database_url)
                .set(username=role, password=password)
                .render_as_string(hide_password=False)
            )
            with closing(
                open_store(role_url, ROOT / "migrations", migrate=False)
            ) as store:
                first = ActorContext(
                    "postgres-validator",
                    "tenant-a",
                    f"workspace-a-{suffix}",
                    frozenset({"Admin"}),
                )
                second = ActorContext(
                    "postgres-validator",
                    "tenant-b",
                    f"workspace-b-{suffix}",
                    frozenset({"Admin"}),
                )
                repository = ResourceRepository(store)
                model = asdict(pump_tank_model())
                manifest = RunManifest(
                    *(character * 64 for character in "abcdefghij"),
                    seed=17,
                    clock_policy="deterministic-v1",
                    endpoint_identity="postgresql-validator",
                )
                with workspace_scope(first.workspace_id):
                    created = repository.create(
                        first, "migration_probe", f"probe-{suffix}", model
                    )
                    if (
                        repository.get(
                            first, "migration_probe", created.resource_id
                        ).digest
                        != created.digest
                    ):
                        raise SystemExit("PostgreSQL resource round trip failed")
                    first_run = RunOrchestrator(store).create(
                        first, manifest, "shared-key"
                    )
                with workspace_scope(second.workspace_id):
                    try:
                        repository.get(second, "migration_probe", created.resource_id)
                    except DomainError as error:
                        if error.code != "RESOURCE_NOT_FOUND":
                            raise
                    else:
                        raise SystemExit("cross-workspace resource became visible")
                    second_run = RunOrchestrator(store).create(
                        second, manifest, "shared-key"
                    )
                    if first_run["run_id"] == second_run["run_id"]:
                        raise SystemExit("idempotency key leaked across workspaces")
                    if (
                        RunOrchestrator(store).create(second, manifest, "shared-key")
                        != second_run
                    ):
                        raise SystemExit("workspace-scoped idempotency replay failed")
                if store.query("SELECT * FROM domain_resources"):
                    raise SystemExit(
                        "unscoped PostgreSQL role bypassed row-level security"
                    )
                if store.query("SELECT * FROM runs") or store.query(
                    "SELECT * FROM outbox"
                ):
                    raise SystemExit(
                        "unscoped PostgreSQL role exposed run or outbox records"
                    )
            rows = admin_store.query(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
            versions = [int(row["version"]) for row in rows]
            if versions != list(range(1, max(versions) + 1)):
                raise SystemExit(f"migration versions are not contiguous: {versions}")
    finally:
        admin_store.close()
    print(
        "PostgreSQL migrations, non-owner RLS denial, tenant-scoped resources, "
        f"child rows, outbox, and idempotency passed at head {versions[-1]}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
