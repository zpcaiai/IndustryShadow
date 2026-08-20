from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError
from shadow_sandbox.common.sqlalchemy_store import SqlAlchemyStore

ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

ROLE_ACCESS_MATRIX_SQL = """WITH requested(role_name) AS (VALUES (?)),
                                  public_sequences AS MATERIALIZED (
                                    SELECT sequence.oid
                                      FROM pg_class sequence
                                      JOIN pg_namespace namespace
                                        ON namespace.oid=sequence.relnamespace
                                     WHERE namespace.nspname='public'
                                       AND sequence.relkind='S'
                                  )
           SELECT has_database_privilege(role_name, current_database(), 'CONNECT')
                    AS database_connect,
                  has_database_privilege(role_name, current_database(), 'TEMP')
                    AS database_temp,
                  has_schema_privilege(role_name, 'public', 'USAGE') AS schema_usage,
                  has_schema_privilege(role_name, 'public', 'CREATE') AS schema_create,
                  (SELECT COUNT(*) FROM pg_class relation
                    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
                   WHERE namespace.nspname='public'
                     AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')) AS table_count,
                  (SELECT COUNT(*) FROM pg_class relation
                    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
                   WHERE namespace.nspname='public'
                     AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
                     AND has_table_privilege(role_name, relation.oid, 'SELECT'))
                    AS table_select,
                  (SELECT COUNT(*) FROM pg_class relation
                    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
                   WHERE namespace.nspname='public'
                     AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
                     AND has_table_privilege(role_name, relation.oid, 'INSERT'))
                    AS table_insert,
                  (SELECT COUNT(*) FROM pg_class relation
                    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
                   WHERE namespace.nspname='public'
                     AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
                     AND has_table_privilege(role_name, relation.oid, 'UPDATE'))
                    AS table_update,
                  (SELECT COUNT(*) FROM pg_class relation
                    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
                   WHERE namespace.nspname='public'
                     AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
                     AND has_table_privilege(role_name, relation.oid, 'DELETE'))
                    AS table_delete,
                  (SELECT COUNT(*) FROM pg_class relation
                    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
                   WHERE namespace.nspname='public'
                     AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
                     AND (has_table_privilege(role_name, relation.oid, 'TRUNCATE')
                       OR has_table_privilege(role_name, relation.oid, 'REFERENCES')
                       OR has_table_privilege(role_name, relation.oid, 'TRIGGER')))
                    AS table_elevated,
                  (SELECT COUNT(*) FROM public_sequences) AS sequence_count,
                  (SELECT COUNT(*) FROM public_sequences sequence
                    WHERE has_sequence_privilege(role_name, sequence.oid, 'USAGE'))
                    AS sequence_usage,
                  (SELECT COUNT(*) FROM public_sequences sequence
                    WHERE has_sequence_privilege(role_name, sequence.oid, 'SELECT'))
                    AS sequence_select,
                  (SELECT COUNT(*) FROM public_sequences sequence
                    WHERE has_sequence_privilege(role_name, sequence.oid, 'UPDATE'))
                    AS sequence_update,
                  (SELECT COUNT(*) FROM pg_proc routine
                    JOIN pg_namespace namespace ON namespace.oid=routine.pronamespace
                   WHERE namespace.nspname='public'
                     AND has_function_privilege(role_name, routine.oid, 'EXECUTE'))
                    AS routine_execute
             FROM requested"""


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


def role_access_matrix(store: SqlAlchemyStore, role: str) -> dict[str, Any]:
    return store.query(ROLE_ACCESS_MATRIX_SQL, (role,))[0]


def role_matrix_is_exact(row: Mapping[str, Any], *, read_write: bool) -> bool:
    table_count = int(row["table_count"])
    sequence_count = int(row["sequence_count"])
    return (
        bool(row["database_connect"])
        and not bool(row["database_temp"])
        and bool(row["schema_usage"])
        and not bool(row["schema_create"])
        and int(row["table_select"]) == table_count
        and int(row["table_insert"]) == (table_count if read_write else 0)
        and int(row["table_update"]) == (table_count if read_write else 0)
        and int(row["table_delete"]) == (table_count if read_write else 0)
        and int(row["table_elevated"]) == 0
        and int(row["sequence_select"]) == sequence_count
        and int(row["sequence_usage"]) == (sequence_count if read_write else 0)
        and int(row["sequence_update"]) == 0
        and int(row["routine_execute"]) == 0
    )


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
        ownership_placeholders = ",".join("?" for _item in names)
        ownership = self.store.query(
            f"""SELECT COUNT(*) AS count
                   FROM (
                         SELECT relation_object.oid
                           FROM pg_class relation_object
                           JOIN pg_namespace namespace_object
                             ON namespace_object.oid=relation_object.relnamespace
                           JOIN pg_roles owner ON owner.oid=relation_object.relowner
                          WHERE namespace_object.nspname='public'
                            AND owner.rolname IN ({ownership_placeholders})
                         UNION ALL
                         SELECT routine_object.oid
                           FROM pg_proc routine_object
                           JOIN pg_namespace namespace_object
                             ON namespace_object.oid=routine_object.pronamespace
                           JOIN pg_roles owner ON owner.oid=routine_object.proowner
                          WHERE namespace_object.nspname='public'
                            AND owner.rolname IN ({ownership_placeholders})
                         UNION ALL
                         SELECT namespace_object.oid
                           FROM pg_namespace namespace_object
                           JOIN pg_roles owner ON owner.oid=namespace_object.nspowner
                          WHERE namespace_object.nspname='public'
                            AND owner.rolname IN ({ownership_placeholders})
                         UNION ALL
                         SELECT database_object.oid
                           FROM pg_database database_object
                           JOIN pg_roles owner ON owner.oid=database_object.datdba
                          WHERE database_object.datname=current_database()
                            AND owner.rolname IN ({ownership_placeholders})
                        ) AS owned""",
            (*names, *names, *names, *names),
        )[0]
        if int(ownership["count"]):
            raise DomainError(
                "DATABASE_ROLE_OWNERSHIP_INVALID",
                "runtime roles must not own the database, schema, relations, or functions",
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
        self.store.execute(f'REVOKE CONNECT, TEMPORARY ON DATABASE "{quoted_database}" FROM PUBLIC')
        self.store.execute("REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC")
        self.store.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC")
        self.store.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC")
        self.store.execute("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC")
        self.store.execute(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC"
        )
        self.store.execute(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC"
        )
        self.store.execute(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM PUBLIC"
        )
        for name in names:
            self.store.execute(
                f'REVOKE ALL PRIVILEGES ON DATABASE "{quoted_database}" FROM "{name}"'
            )
            self.store.execute(f'REVOKE ALL PRIVILEGES ON SCHEMA public FROM "{name}"')
            self.store.execute(
                f'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM "{name}"'
            )
            self.store.execute(
                f'REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM "{name}"'
            )
            self.store.execute(
                f'REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM "{name}"'
            )
            self.store.execute(
                f'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM "{name}"'
            )
            self.store.execute(
                f'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM "{name}"'
            )
            self.store.execute(
                f'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM "{name}"'
            )
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
        self.store.execute(
            f'GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO "{self.backup_role}"'
        )
        self.store.execute(
            f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO "{self.backup_role}"'
        )
        matrices = {name: role_access_matrix(self.store, name) for name in names}
        invalid = [
            name
            for name, matrix in matrices.items()
            if not role_matrix_is_exact(matrix, read_write=name != self.backup_role)
        ]
        if invalid:
            raise DomainError(
                "DATABASE_ROLE_MATRIX_INVALID",
                "database grants do not match the exact runtime role matrix",
                {"roles": invalid},
            )
        return {
            "database": database,
            "migration_role": current,
            "tenant_roles": len(self.tenant_roles),
            "maintenance_bypass_rls": True,
            "backup_read_only": True,
            "backup_bypass_rls": True,
            "existing_privileges_reset": True,
            "role_matrix_verified": True,
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
