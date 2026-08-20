from __future__ import annotations

import datetime as dt
import inspect
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from shadow_sandbox.common import DomainError
from shadow_sandbox.common.models import canonical_digest
from shadow_sandbox.common.object_storage import ObjectRef, ObjectRetention
from shadow_sandbox.operations.aws_resource_arns import (
    parse_kms_key_arn,
    parse_rds_database_arn,
    require_same_aws_coordinates,
)
from shadow_sandbox.operations.backup_job import (
    PostgreSqlBackupSnapshot,
    _archive_sequence_states,
    _finalize_snapshot_fingerprint,
    _require_exact_version_retention,
    _snapshot_role_binding,
    create_backup,
)
from shadow_sandbox.operations.managed_postgresql_probe import (
    AwsRdsControlPlaneProbe,
    DatabaseEndpoint,
)
from shadow_sandbox.operations.postgres_coordinates import postgres_environment
from shadow_sandbox.operations.restore_drill import (
    CATALOG_QUERIES,
    CATALOG_SECURITY_QUERIES,
    BackupObjectVersion,
    PostgreSqlRestoreDrill,
)


def base_catalog() -> dict[str, object]:
    empty = {"count": 0, "sha256": "1" * 64}
    sections = {
        name: dict(empty)
        for name, _sql in (*CATALOG_QUERIES, *CATALOG_SECURITY_QUERIES)
    }
    sections["sequence_runtime_state"] = dict(empty)
    return {
        "sha256": canonical_digest(sections),
        "objects": 0,
        "sections": sections,
    }


class PostgreSqlBackupSnapshotTests(unittest.TestCase):
    def test_production_backup_rejects_all_local_test_overrides(self) -> None:
        with patch.dict(
            os.environ, {"SHADOW_ENVIRONMENT": "production"}, clear=True
        ), self.assertRaises(DomainError) as raised:
            create_backup(database_url_override="postgresql://local/test")
        self.assertEqual("PRODUCTION_BACKUP_OVERRIDE_FORBIDDEN", raised.exception.code)

    def test_backup_object_version_rejects_control_characters(self) -> None:
        with self.assertRaises(DomainError) as raised:
            BackupObjectVersion.parse(
                {
                    "key": "postgres/2026-08-20/" + "1" * 64 + ".dump",
                    "size": 1,
                    "sha256": "1" * 64,
                    "version_id": "version\nattacker",
                    "encryption": "aws:kms",
                },
                field="archive",
            )
        self.assertEqual("BACKUP_RECEIPT_INVALID", raised.exception.code)

    def test_postgresql_coordinate_rejects_an_explicit_zero_port(self) -> None:
        with self.assertRaises(DomainError) as raised:
            postgres_environment(
                "postgresql://shadow_backup@db.example.internal:0/shadow?sslmode=require"
            )
        self.assertEqual("DATABASE_URL_INVALID", raised.exception.code)

    def test_snapshot_connection_clears_ambient_libpq_role_options(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SHADOW_ENVIRONMENT": "test",
                "PGOPTIONS": "-c role=ambient_administrator",
                "PGPASSWORD": "ambient-password",
            },
            clear=True,
        ):
            snapshot = PostgreSqlBackupSnapshot(
                "postgresql://shadow_backup:explicit-password@db.example.internal/shadow"
                "?sslmode=require"
            )
        self.assertEqual("", snapshot.connection_parameters["options"])
        self.assertEqual("shadow_backup", snapshot.connection_parameters["user"])
        self.assertEqual("explicit-password", snapshot.connection_parameters["password"])

    def test_backup_role_rejects_role_administration_even_when_data_is_read_only(self) -> None:
        class AdministrativeSnapshot:
            @staticmethod
            def query(_sql: str) -> list[dict[str, object]]:
                return [
                    {
                        "role": "shadow_backup",
                        "superuser": False,
                        "create_database": False,
                        "create_role": True,
                        "replication": False,
                        "bypass": True,
                        "can_login": True,
                        "inherits_membership": False,
                        "owns_tables": False,
                        "owns_routines": False,
                    }
                ]

        with (
            patch(
                "shadow_sandbox.operations.backup_job.role_access_matrix",
                return_value={},
            ),
            patch(
                "shadow_sandbox.operations.backup_job.role_matrix_is_exact",
                return_value=True,
            ),
            self.assertRaises(DomainError) as raised,
        ):
            _snapshot_role_binding(
                AdministrativeSnapshot(),  # type: ignore[arg-type]
                expected_role="shadow_backup",
            )
        self.assertEqual("DATABASE_BACKUP_ROLE_INVALID", raised.exception.code)

    def test_production_backup_rejects_unshared_connection_options(self) -> None:
        with (
            patch.dict(os.environ, {"SHADOW_ENVIRONMENT": "production"}, clear=True),
            self.assertRaises(DomainError) as raised,
        ):
            postgres_environment(
                "postgresql://shadow_backup@db.example.internal/shadow"
                "?sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Froot.pem"
                "&options=-c%20role%3Ddifferent_role"
            )
        self.assertEqual(
            "PRODUCTION_DATABASE_PARAMETER_INVALID",
            raised.exception.code,
        )

    def test_backup_requires_object_lock_on_each_exact_uploaded_version(self) -> None:
        class RetainedVersions:
            def __init__(self) -> None:
                self.requests: list[tuple[str, str]] = []

            def get_version_retention(
                self, key: str, *, version_id: str
            ) -> ObjectRetention:
                self.requests.append((key, version_id))
                return ObjectRetention(
                    "COMPLIANCE",
                    (dt.datetime.now(dt.UTC) + dt.timedelta(days=30)).isoformat(),
                )

        storage = RetainedVersions()
        references = tuple(
            ObjectRef(
                f"postgres/2026-08-20/{index:064x}.dump{suffix}",
                1,
                f"{index:064x}",
                "application/octet-stream",
                "etag",
                version,
                "aws:kms",
            )
            for index, suffix, version in (
                (1, "", "archive-v1"),
                (2, ".manifest.json", "manifest-v2"),
                (3, ".receipt.json", "receipt-v3"),
            )
        )
        for field, reference in zip(
            ("backup archive", "backup manifest", "sealed backup receipt"),
            references,
            strict=True,
        ):
            _require_exact_version_retention(
                storage,  # type: ignore[arg-type]
                reference,
                field=field,
            )
        self.assertEqual(
            [(reference.key, str(reference.version_id)) for reference in references],
            storage.requests,
        )

        expired = ObjectRetention(
            "GOVERNANCE",
            (dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)).isoformat(),
        )
        with (
            patch.object(storage, "get_version_retention", return_value=expired),
            self.assertRaises(DomainError) as raised,
        ):
            _require_exact_version_retention(
                storage,  # type: ignore[arg-type]
                references[0],
                field="backup archive",
            )
        self.assertEqual("DATABASE_BACKUP_RETENTION_INVALID", raised.exception.code)

    def test_archive_sequence_state_replaces_non_mvcc_catalog_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "database.dump"
            archive.write_bytes(b"custom-archive")
            toc = root / "database.toc"
            toc.write_text(
                "101; 0 0 SEQUENCE SET public event_id_seq shadow_migration\n"
                "102; 0 0 SEQUENCE SET public MixedName shadow_migration\n",
                encoding="utf-8",
            )

            def restore(
                command: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                output = Path(command[command.index("--file") + 1])
                output.write_text(
                    "SELECT pg_catalog.setval('public.event_id_seq', 41, true);\n"
                    "SELECT pg_catalog.setval('public.\"MixedName\"', 7, false);\n",
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(command, 0)

            with patch(
                "shadow_sandbox.operations.backup_job.subprocess.run",
                side_effect=restore,
            ):
                states = _archive_sequence_states(
                    archive,
                    toc_path=toc,
                    sequence_names=("event_id_seq", "MixedName"),
                )
        self.assertEqual(
            (
                {
                    "sequence_name": "event_id_seq",
                    "last_value": "41",
                    "is_called": True,
                },
                {
                    "sequence_name": "MixedName",
                    "last_value": "7",
                    "is_called": False,
                },
            ),
            states,
        )
        fingerprint = _finalize_snapshot_fingerprint(
            {
                "schema_version": 1,
                "capture_method": "pg-export-snapshot-v1",
                "tables": {"events": {"count": 1, "sha256": "2" * 64}},
                "rls_policies": {"count": 1, "sha256": "3" * 64},
                "catalog": base_catalog(),
                "migration_versions": [1],
                "backup_role": {
                    "name": "shadow_backup",
                    "bypass_rls": True,
                    "owns_tables": False,
                    "owns_routines": False,
                    "matrix_exact_read_only": True,
                },
            },
            archive_sequence_states=states,
        )
        self.assertEqual(64, len(str(fingerprint["snapshot_digest"])))
        sections = fingerprint["catalog"]["sections"]  # type: ignore[index]
        self.assertEqual(2, sections["sequence_runtime_state"]["count"])

    def test_restore_has_no_live_source_store_comparison(self) -> None:
        source = inspect.getsource(PostgreSqlRestoreDrill.run)
        self.assertNotIn("SqlAlchemyStore(self.source_url)", source)
        self.assertIn("backup_snapshot.tables", source)
        self.assertIn("backup_snapshot.catalog", source)
        self.assertIn("backup_snapshot.migration_versions", source)

    def test_restore_recomputes_rpo_at_end_of_full_validation(self) -> None:
        source = inspect.getsource(PostgreSqlRestoreDrill.run)
        self.assertEqual(2, source.count("receipt.age_seconds()"))
        self.assertLess(
            source.index("backup_age_at_start_seconds = receipt.age_seconds()"),
            source.index("target = SqlAlchemyStore(self.target_url)"),
        )
        self.assertLess(
            source.index("restore_seconds = time.monotonic() - restore_started"),
            source.index("backup_age_seconds = receipt.age_seconds()"),
        )

    def test_aws_partitions_are_exact_and_coordinate_bound(self) -> None:
        examples = (
            ("aws", "us-east-1"),
            ("aws-us-gov", "us-gov-west-1"),
            ("aws-cn", "cn-north-1"),
        )
        for partition, region in examples:
            kms = parse_kms_key_arn(
                f"arn:{partition}:kms:{region}:123456789012:key/1234-abcd"
            )
            rds = parse_rds_database_arn(
                f"arn:{partition}:rds:{region}:123456789012:db:shadow-source"
            )
            require_same_aws_coordinates(
                kms,
                rds,
                include_region=True,
                code="TEST_COORDINATES_INVALID",
            )
        with self.assertRaises(DomainError):
            parse_kms_key_arn(
                "arn:aws:kms:cn-north-1:123456789012:key/partition-confusion"
            )
        with self.assertRaises(DomainError):
            parse_kms_key_arn(
                "arn:aws:kms:us-iso-east-1:123456789012:key/unsupported-partition"
            )
        with self.assertRaises(DomainError):
            require_same_aws_coordinates(
                parse_kms_key_arn("arn:aws:kms:us-east-1:123456789012:key/one"),
                parse_rds_database_arn(
                    "arn:aws:rds:us-east-1:210987654321:db:shadow-source"
                ),
                include_region=True,
                code="TEST_COORDINATES_INVALID",
            )

    def test_rds_rejects_a_cross_partition_live_kms_key(self) -> None:
        source_url = "postgresql://backup@source.example.internal/shadow"
        restore_url = (
            "postgresql://migration@restore.example.internal/shadow_restore_drill"
        )
        source_arn = "arn:aws:rds:us-east-1:123456789012:db:shadow-source"
        restore_arn = "arn:aws:rds:us-east-1:123456789012:db:shadow-restore"

        class CrossPartitionRds:
            def describe_db_instances(
                self, *, DBInstanceIdentifier: str
            ) -> dict[str, object]:
                source = DBInstanceIdentifier == "shadow-source"
                return {
                    "DBInstances": [
                        {
                            "DBInstanceArn": source_arn if source else restore_arn,
                            "Endpoint": {
                                "Address": (
                                    "source.example.internal"
                                    if source
                                    else "restore.example.internal"
                                ),
                                "Port": 5432,
                            },
                            "DBInstanceStatus": "available",
                            "StorageEncrypted": True,
                            "PubliclyAccessible": False,
                            "KmsKeyId": (
                                "arn:aws-cn:kms:cn-north-1:123456789012:key/wrong-partition"
                            ),
                            "CACertificateIdentifier": "rds-ca-rsa2048-g1",
                            "DbiResourceId": "db-source" if source else "db-restore",
                            "BackupRetentionPeriod": 7,
                            "DeletionProtection": True,
                        }
                    ]
                }

        with self.assertRaises(DomainError) as raised:
            AwsRdsControlPlaneProbe(
                source_url,
                restore_url,
                source_resource_arn=source_arn,
                restore_resource_arn=restore_arn,
                expected_account_id="123456789012",
                expected_region="us-east-1",
                expected_source_resource_digest=canonical_digest(
                    {"provider": "aws-rds", "resource_arn": source_arn}
                ),
                expected_restore_resource_digest=canonical_digest(
                    {"provider": "aws-rds", "resource_arn": restore_arn}
                ),
                expected_source_coordinate_digest=DatabaseEndpoint.parse(
                    source_url
                ).digest,
                expected_restore_coordinate_digest=DatabaseEndpoint.parse(
                    restore_url
                ).digest,
                client=CrossPartitionRds(),
            ).run()
        self.assertEqual(
            "MANAGED_POSTGRESQL_CONTROL_PLANE_INVALID", raised.exception.code
        )

    def test_restore_rejects_a_different_configured_s3_kms_key(self) -> None:
        class BoundStorage:
            region = "us-east-1"
            expected_bucket_owner = "123456789012"
            kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/storage-key"

        with self.assertRaises(DomainError) as raised:
            PostgreSqlRestoreDrill(
                "postgresql://backup@source.example.internal/shadow",
                "postgresql://migration@restore.example.internal/shadow_restore_drill",
                allow_restore=True,
                object_storage=BoundStorage(),  # type: ignore[arg-type]
                backup_receipt_path="receipt.json",
                kms_key_id="arn:aws:kms:us-east-1:123456789012:key/other-key",
                require_immutable_backup=True,
            )
        self.assertEqual("IMMUTABLE_BACKUP_REQUIRED", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
