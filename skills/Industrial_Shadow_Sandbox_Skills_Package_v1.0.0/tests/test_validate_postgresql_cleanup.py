from __future__ import annotations

import os
import sys
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from unittest.mock import patch

from shadow_sandbox.common import DomainError
from shadow_sandbox.operations.database_roles import ROLE_ACCESS_MATRIX_SQL
from shadow_sandbox.operations.restore_drill import (
    CATALOG_QUERIES,
    CATALOG_SECURITY_QUERIES,
)

from tools.postgresql_test_roles import temporary_postgresql_test_role
from tools.validate_local_postgresql_restore import (
    _append_github_environment,
    _cluster_identifier,
    _database_role_url,
    _local_database_url,
    _require_disposable_database_names,
    _require_source_mutation_confirmation,
    _source_mutation_confirmation,
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


class _ReadOnlyClusterStore:
    def __init__(self, identifier: str) -> None:
        self.identifier = identifier
        self.queries: list[str] = []
        self.closed = False

    def query(
        self, sql: str, parameters: Sequence[object] = ()
    ) -> list[dict[str, object]]:
        del parameters
        self.queries.append(sql)
        if "pg_control_system()" not in sql:
            raise AssertionError("query executed before source mutation confirmation")
        return [{"identifier": self.identifier}]

    def execute(self, sql: str, parameters: Sequence[object] = ()) -> object:
        del sql, parameters
        raise AssertionError("database mutated before source mutation confirmation")

    def close(self) -> None:
        self.closed = True


class PostgreSqlValidatorCleanupTests(unittest.TestCase):
    def test_catalog_queries_do_not_use_collation_as_a_table_alias(self) -> None:
        catalog_sql = "\n".join(
            sql for _name, sql in (*CATALOG_QUERIES, *CATALOG_SECURITY_QUERIES)
        )
        self.assertNotIn("collation.collname", catalog_sql)
        self.assertEqual(2, catalog_sql.count("collation_object.collname"))

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

    def test_source_mutation_confirmation_is_run_and_cluster_bound(self) -> None:
        run_id = "11111111-2222-4333-8444-555555555555"
        source_url = "postgresql://admin@127.0.0.1:5432/shadow_test"
        target_url = "postgresql://admin@127.0.0.1:5433/shadow_restore_drill"
        expected = _source_mutation_confirmation(
            run_id=run_id,
            source_url=source_url,
            source_cluster_identifier="123456789",
            target_url=target_url,
            target_cluster_identifier="987654321",
        )
        self.assertEqual(
            "local-postgresql-source-acl-mutation/v1:"
            f"{run_id}:shadow_test@123456789:shadow_restore_drill@987654321",
            expected,
        )
        with patch.dict(
            os.environ,
            {
                "SHADOW_LOCAL_RESTORE_RUN_ID": run_id,
                "SHADOW_CONFIRM_LOCAL_RESTORE_SOURCE_MUTATION": expected,
            },
            clear=True,
        ):
            _require_source_mutation_confirmation(
                source_url=source_url,
                source_cluster_identifier="123456789",
                target_url=target_url,
                target_cluster_identifier="987654321",
            )
            with self.assertRaises(DomainError):
                _require_source_mutation_confirmation(
                    source_url=source_url,
                    source_cluster_identifier="123456789",
                    target_url=target_url,
                    target_cluster_identifier="987654322",
                )

    def test_source_confirmation_precedes_role_acl_and_backup_mutation(self) -> None:
        source = _ReadOnlyClusterStore("123456789")
        target = _ReadOnlyClusterStore("987654321")
        environment = {
            "SHADOW_ALLOW_LOCAL_RESTORE_DRILL": "true",
            "SHADOW_TEST_POSTGRESQL_URL": (
                "postgresql+psycopg://admin@127.0.0.1:5432/shadow_test?sslmode=disable"
            ),
            "SHADOW_TEST_RESTORE_POSTGRESQL_URL": (
                "postgresql+psycopg://admin@127.0.0.1:5433/"
                "shadow_restore_drill?sslmode=disable"
            ),
            "SHADOW_LOCAL_RESTORE_RUN_ID": "11111111-2222-4333-8444-555555555555",
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(sys, "argv", ["validate_local_postgresql_restore.py"]),
            patch(
                "tools.validate_local_postgresql_restore.SqlAlchemyStore",
                side_effect=(source, target),
            ),
            self.assertRaises(DomainError) as raised,
        ):
            local_restore_main()
        self.assertEqual(
            "LOCAL_RESTORE_SOURCE_CONFIRMATION_REQUIRED", raised.exception.code
        )
        self.assertEqual(1, len(source.queries))
        self.assertEqual(1, len(target.queries))
        self.assertTrue(source.closed)
        self.assertTrue(target.closed)

    def test_prepare_mode_emits_exact_fresh_confirmation_without_mutation(self) -> None:
        source = _ReadOnlyClusterStore("123456789")
        target = _ReadOnlyClusterStore("987654321")
        environment = {
            "SHADOW_ALLOW_LOCAL_RESTORE_DRILL": "true",
            "SHADOW_TEST_POSTGRESQL_URL": (
                "postgresql+psycopg://admin@127.0.0.1:5432/shadow_test?sslmode=disable"
            ),
            "SHADOW_TEST_RESTORE_POSTGRESQL_URL": (
                "postgresql+psycopg://admin@127.0.0.1:5433/"
                "shadow_restore_drill?sslmode=disable"
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            github_environment = Path(directory) / "github-env"
            github_environment.write_text("EXISTING=value\n", encoding="utf-8")
            with (
                patch.dict(os.environ, environment, clear=True),
                patch.object(
                    sys,
                    "argv",
                    [
                        "validate_local_postgresql_restore.py",
                        "--prepare-source-confirmation-github-env",
                        str(github_environment),
                    ],
                ),
                patch(
                    "tools.validate_local_postgresql_restore.SqlAlchemyStore",
                    side_effect=(source, target),
                ),
            ):
                self.assertEqual(0, local_restore_main())
            values = dict(
                line.split("=", 1)
                for line in github_environment.read_text(encoding="utf-8").splitlines()
            )
        run_id = values["SHADOW_LOCAL_RESTORE_RUN_ID"]
        self.assertEqual(
            _source_mutation_confirmation(
                run_id=run_id,
                source_url=environment["SHADOW_TEST_POSTGRESQL_URL"],
                source_cluster_identifier="123456789",
                target_url=environment["SHADOW_TEST_RESTORE_POSTGRESQL_URL"],
                target_cluster_identifier="987654321",
            ),
            values["SHADOW_CONFIRM_LOCAL_RESTORE_SOURCE_MUTATION"],
        )
        self.assertEqual(
            [
                "EXISTING",
                "SHADOW_LOCAL_RESTORE_RUN_ID",
                "SHADOW_CONFIRM_LOCAL_RESTORE_SOURCE_MUTATION",
            ],
            list(values),
        )
        self.assertEqual(1, len(source.queries))
        self.assertEqual(1, len(target.queries))
        self.assertTrue(source.closed)
        self.assertTrue(target.closed)

    def test_confirmation_output_rejects_relative_and_symlink_paths(self) -> None:
        values = {"SHADOW_LOCAL_RESTORE_RUN_ID": "11111111-2222-4333-8444-555555555555"}
        with self.assertRaises(DomainError):
            _append_github_environment(Path("relative-github-env"), values)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("preserve\n", encoding="utf-8")
            link = Path(directory) / "github-env"
            link.symlink_to(target)
            with self.assertRaises(DomainError):
                _append_github_environment(link, values)
            self.assertEqual("preserve\n", target.read_text(encoding="utf-8"))

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
        with self.assertRaises(DomainError):
            _require_disposable_database_names(
                "postgresql://admin@127.0.0.1/shadow_test%3Aunsafe",
                "postgresql://admin@127.0.0.1/shadow_restore_drill",
            )

    def test_loopback_source_and_target_ports_remain_supported(self) -> None:
        source = "postgresql+psycopg://admin@127.0.0.1:5432/shadow_test?sslmode=disable"
        target = (
            "postgresql+psycopg://admin@localhost:5433/"
            "shadow_restore_drill?sslmode=disable"
        )
        with patch.dict(
            os.environ,
            {
                "SHADOW_TEST_POSTGRESQL_URL": source,
                "SHADOW_TEST_RESTORE_POSTGRESQL_URL": target,
            },
            clear=True,
        ):
            self.assertEqual(source, _local_database_url("SHADOW_TEST_POSTGRESQL_URL"))
            self.assertEqual(
                target, _local_database_url("SHADOW_TEST_RESTORE_POSTGRESQL_URL")
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
