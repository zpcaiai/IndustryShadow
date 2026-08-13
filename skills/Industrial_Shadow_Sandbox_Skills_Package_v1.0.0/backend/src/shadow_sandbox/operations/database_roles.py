from __future__ import annotations

import os
import re
from collections.abc import Sequence
from pathlib import Path

from shadow_sandbox.common.models import DomainError
from shadow_sandbox.common.sqlalchemy_store import SqlAlchemyStore

ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def _roles(value: str) -> tuple[str, ...]:
    roles = tuple(dict.fromkeys(item.strip() for item in value.split(",") if item.strip()))
    if not roles or any(not ROLE_NAME.fullmatch(item) for item in roles):
        raise DomainError("DATABASE_ROLE_INVALID", "database role list is invalid")
    return roles


def _one_role(value: str) -> str:
    roles = _roles(value)
    if len(roles) != 1:
        raise DomainError("DATABASE_ROLE_INVALID", "exactly one database role is required")
    return roles[0]


class DatabaseRoleConfigurator:
    """Apply least-privilege grants to pre-created login roles after migrations/restores."""

    def __init__(
        self,
        store: SqlAlchemyStore,
        *,
        tenant_roles: Sequence[str],
        maintenance_role: str,
        backup_role: str,
    ) -> None:
        values = (*tenant_roles, maintenance_role, backup_role)
        if len(set(values)) != len(values) or any(not ROLE_NAME.fullmatch(item) for item in values):
            raise DomainError("DATABASE_ROLE_INVALID", "database roles must be distinct names")
        self.store = store
        self.tenant_roles = tuple(tenant_roles)
        self.maintenance_role = maintenance_role
        self.backup_role = backup_role

    def configure(self) -> dict[str, object]:
        names = (*self.tenant_roles, self.maintenance_role, self.backup_role)
        placeholders = ",".join("?" for _item in names)
        rows = self.store.query(
            f"""SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication,
                         rolbypassrls, rolcanlogin
                  FROM pg_roles WHERE rolname IN ({placeholders})""",
            names,
        )
        by_name = {str(row["rolname"]): row for row in rows}
        missing = sorted(set(names) - set(by_name))
        if missing:
            raise DomainError(
                "DATABASE_ROLE_MISSING",
                "pre-created database roles are missing",
                {"roles": missing},
            )
        current = str(self.store.query("SELECT current_user AS role")[0]["role"])
        if current in names:
            raise DomainError(
                "DATABASE_MIGRATION_ROLE_INVALID",
                "migration owner must be distinct from runtime roles",
            )
        memberships = self.store.query(
            f"""SELECT member.rolname AS member, parent.rolname AS parent
                  FROM pg_auth_members membership
                  JOIN pg_roles member ON member.oid=membership.member
                  JOIN pg_roles parent ON parent.oid=membership.roleid
                 WHERE member.rolname IN ({placeholders})""",
            names,
        )
        if memberships:
            raise DomainError(
                "DATABASE_ROLE_MEMBERSHIP_INVALID",
                "runtime roles must not inherit privileges from other roles",
                {"memberships": len(memberships)},
            )
        for name in self.tenant_roles:
            role = by_name[name]
            if (
                role["rolsuper"]
                or role["rolcreatedb"]
                or role["rolcreaterole"]
                or role["rolreplication"]
                or role["rolbypassrls"]
                or not role["rolcanlogin"]
            ):
                raise DomainError(
                    "DATABASE_RUNTIME_ROLE_PRIVILEGED",
                    "tenant runtime roles must be login roles without administrative privileges",
                    {"role": name},
                )
        maintenance = by_name[self.maintenance_role]
        if (
            maintenance["rolsuper"]
            or maintenance["rolcreatedb"]
            or maintenance["rolcreaterole"]
            or maintenance["rolreplication"]
            or not maintenance["rolbypassrls"]
            or not maintenance["rolcanlogin"]
        ):
            raise DomainError(
                "DATABASE_MAINTENANCE_ROLE_INVALID",
                "maintenance role must use BYPASSRLS without superuser/role-admin privileges",
            )
        backup = by_name[self.backup_role]
        if (
            backup["rolsuper"]
            or backup["rolcreatedb"]
            or backup["rolcreaterole"]
            or backup["rolreplication"]
            or not backup["rolbypassrls"]
            or not backup["rolcanlogin"]
        ):
            raise DomainError(
                "DATABASE_BACKUP_ROLE_INVALID",
                "backup role must use BYPASSRLS without administrative privileges",
            )
        database = str(self.store.query("SELECT current_database() AS database")[0]["database"])
        quoted_database = database.replace('"', '""')
        self.store.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        self.store.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC")
        self.store.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC")
        for name in names:
            self.store.execute(f'GRANT CONNECT ON DATABASE "{quoted_database}" TO "{name}"')
            self.store.execute(f'GRANT USAGE ON SCHEMA public TO "{name}"')
        for name in self.tenant_roles:
            self.store.execute(
                f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "{name}"'
            )
            self.store.execute(
                f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "{name}"'
            )
            self.store.execute(f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{name}"')
            self.store.execute(
                f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO "{name}"'
            )
        self.store.execute(
            f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "{self.maintenance_role}"'
        )
        self.store.execute(
            f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "{self.maintenance_role}"'
        )
        self.store.execute(
            f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{self.maintenance_role}"'
        )
        self.store.execute(
            f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO "{self.maintenance_role}"'
        )
        self.store.execute(
            f'REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public FROM "{self.backup_role}"'
        )
        self.store.execute(f'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{self.backup_role}"')
        self.store.execute(
            f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO "{self.backup_role}"'
        )
        return {
            "database": database,
            "migration_role": current,
            "tenant_roles": len(self.tenant_roles),
            "maintenance_bypass_rls": True,
            "backup_read_only": True,
            "backup_bypass_rls": True,
        }


def main() -> int:
    database_url = os.environ.get("SHADOW_DATABASE_URL", "")
    if not database_url.startswith(("postgresql://", "postgresql+psycopg://")):
        raise DomainError("POSTGRESQL_REQUIRED", "database role setup requires PostgreSQL")
    tenant_roles = _roles(os.environ.get("SHADOW_DATABASE_TENANT_ROLES", ""))
    maintenance_role = _one_role(os.environ.get("SHADOW_DATABASE_MAINTENANCE_ROLE", ""))
    backup_role = _one_role(os.environ.get("SHADOW_DATABASE_BACKUP_ROLE", ""))
    store = SqlAlchemyStore(database_url)
    try:
        store.migrate_all(Path(__file__).resolve().parents[4] / "migrations")
        result = DatabaseRoleConfigurator(
            store,
            tenant_roles=tenant_roles,
            maintenance_role=maintenance_role,
            backup_role=backup_role,
        ).configure()
    finally:
        store.close()
    import json

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
