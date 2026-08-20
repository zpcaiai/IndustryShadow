from __future__ import annotations

import os
import sys
import unittest
from collections.abc import Sequence
from unittest.mock import patch

from shadow_sandbox.common import DomainError
from shadow_sandbox.operations.database_roles import ROLE_ACCESS_MATRIX_SQL

from tools.postgresql_test_roles import temporary_postgresql_test_role
from tools.validate_local_postgresql_restore import (
    _cluster_identifier,
    _database_role_url,
    _require_disposable_database_names,
)
from tools.validate_local_postgresql_restore import main as local_restore_main


class _RecordingAdminStore:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def execute(self, sql: str, parameters: Sequence[object] = ()) -> object:
        del parameters
        self.statements.append(sql)
        return object()


class _ClusterStore:
    def __init__(self, identifier: object) -> None:
        self.identifier = identifier

    def query(
        self, sql: str, parameters: Sequence[object] = ()
    ) -> list[dict[str, object]]:
        del sql, parameters
        return [{"identifier": self.identifier}]


class PostgreSqlValidatorCleanupTests(unittest.TestCase):
    def test_sequence_privilege_checks_only_use_materialized_sequence_oids(
        self,
    ) -> None:
        self.assertIn("public_sequences AS MATERIALIZED", ROLE_ACCESS_MATRIX_SQL)
        self.assertEqual(1, ROLE_ACCESS_MATRIX_SQL.count("FROM pg_class sequence"))
        self.assertEqual(4, ROLE_ACCESS_MATRIX_SQL.count("FROM public_sequences"))
        self.assertEqual(3, ROLE_ACCESS_MATRIX_SQL.count("has_sequence_privilege"))

    def test_confirmation_is_required_before_opening_either_database(self) -> None:
        environment = {
            "SHADOW_TEST_POSTGRESQL_URL": (
                "postgresql+psycopg://admin@127.0.0.1:5432/shadow_test?sslmode=disable"
            ),
            "SHADOW_TEST_RESTORE_POSTGRESQL_URL": (
                "postgresql+psycopg://admin@127.0.0.1:5433/"
                "shadow_restore_drill?sslmode=disable"
            ),
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(sys, "argv", ["validate_local_postgresql_restore.py"]),
            patch(
                "tools.validate_local_postgresql_restore.SqlAlchemyStore",
                side_effect=AssertionError("database opened before confirmation"),
            ) as constructor,
            self.assertRaisesRegex(DomainError, "confirmation"),
        ):
            local_restore_main()
        constructor.assert_not_called()

    def test_disposable_database_names_are_required_before_role_mutation(self) -> None:
        _require_disposable_database_names(
            "postgresql://admin@127.0.0.1/shadow_test",
            "postgresql://admin@127.0.0.1/shadow_restore_drill",
        )
        with self.assertRaises(DomainError):
            _require_disposable_database_names(
                "postgresql://admin@127.0.0.1/customer_data",
                "postgresql://admin@127.0.0.1/shadow_restore_drill",
            )
        with self.assertRaises(DomainError):
            _require_disposable_database_names(
                "postgresql://admin@127.0.0.1/shadow_test",
                "postgresql://admin@127.0.0.1/customer_data",
            )

    def test_cluster_identifier_is_strict_and_canonical(self) -> None:
        self.assertEqual("123456789", _cluster_identifier(_ClusterStore("123456789")))
        for value in (None, 123456789, "not-a-cluster-id"):
            with self.subTest(value=value), self.assertRaises(DomainError):
                _cluster_identifier(_ClusterStore(value))

    def test_role_url_preserves_the_explicit_local_tls_mode(self) -> None:
        value = _database_role_url(
            "postgresql+psycopg://admin:old@127.0.0.1:5432/shadow_test?sslmode=disable",
            role="shadow_local_backup",
            password="f" * 32,
        )
        self.assertIn("shadow_local_backup", value)
        self.assertIn("sslmode=disable", value)
        self.assertNotIn("admin:old", value)

    def test_probe_role_is_removed_after_success(self) -> None:
        store = _RecordingAdminStore()
        role = "shadow_rls_probe_" + "a" * 32

        with temporary_postgresql_test_role(store, role=role, password="b" * 32):
            self.assertEqual(1, len(store.statements))

        self.assertEqual(
            [
                f'CREATE ROLE "{role}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                "NOREPLICATION NOBYPASSRLS PASSWORD '" + "b" * 32 + "'",
                f'DROP OWNED BY "{role}"',
                f'DROP ROLE "{role}"',
            ],
            store.statements,
        )

    def test_probe_role_is_removed_after_validation_failure(self) -> None:
        store = _RecordingAdminStore()
        role = "shadow_rls_probe_" + "c" * 32

        with (
            self.assertRaisesRegex(RuntimeError, "probe failed"),
            temporary_postgresql_test_role(store, role=role, password="d" * 32),
        ):
            raise RuntimeError("probe failed")

        self.assertEqual(f'DROP OWNED BY "{role}"', store.statements[-2])
        self.assertEqual(f'DROP ROLE "{role}"', store.statements[-1])

    def test_probe_role_rejects_unbounded_identifiers(self) -> None:
        store = _RecordingAdminStore()
        with (
            self.assertRaises(DomainError),
            temporary_postgresql_test_role(
                store,
                role='shadow_probe"; DROP DATABASE shadow_test; --',
                password="e" * 32,
            ),
        ):
            pass
        self.assertEqual([], store.statements)

    def test_bypass_role_uses_the_explicit_bounded_attribute(self) -> None:
        store = _RecordingAdminStore()
        role = "shadow_local_backup_" + "f" * 32

        with temporary_postgresql_test_role(
            store,
            role=role,
            password="a" * 32,
            bypass_rls=True,
        ):
            pass

        self.assertIn(" NOREPLICATION BYPASSRLS ", store.statements[0])
