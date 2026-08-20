from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Protocol

from shadow_sandbox.common import DomainError

ROLE_PATTERN = re.compile(r"[a-z_][a-z0-9_]{0,62}")
PASSWORD_PATTERN = re.compile(r"[a-f0-9]{32}")


class AdministrativeStore(Protocol):
    def execute(self, sql: str, parameters: Sequence[object] = ()) -> object: ...


@contextmanager
def temporary_postgresql_test_role(
    admin_store: AdministrativeStore,
    *,
    role: str,
    password: str,
    bypass_rls: bool = False,
) -> Iterator[None]:
    """Create a bounded disposable login role and remove all local grants on exit."""

    if (
        ROLE_PATTERN.fullmatch(role) is None
        or PASSWORD_PATTERN.fullmatch(password) is None
    ):
        raise DomainError(
            "POSTGRESQL_TEST_ROLE_INVALID",
            "generated PostgreSQL test-role credentials are invalid",
        )
    identifier = f'"{role}"'
    bypass_clause = "BYPASSRLS" if bypass_rls else "NOBYPASSRLS"
    admin_store.execute(
        f"CREATE ROLE {identifier} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
        f"NOREPLICATION {bypass_clause} PASSWORD '{password}'"
    )
    try:
        yield
    finally:
        admin_store.execute(f"DROP OWNED BY {identifier}")
        admin_store.execute(f"DROP ROLE {identifier}")
