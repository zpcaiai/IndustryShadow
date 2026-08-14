from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from shadow_sandbox.common import DomainError
from shadow_sandbox.common.models import canonical_digest, canonical_json, utc_now
from shadow_sandbox.common.object_storage import (
    LocalObjectStorage,
    ObjectRef,
    S3ObjectStorage,
    sha256_file,
)
from shadow_sandbox.operations.backup_job import create_backup, postgres_environment
from shadow_sandbox.operations.restore_drill import (
    BackupRestoreReceipt,
    PostgreSqlRestoreDrill,
)
from shadow_sandbox.operations.storage_probe import S3KmsProbe, workload_session
from test_production_closure import FakeS3

TLS = "?sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Fpostgres-root.pem"


class RecordingStorage:
    def __init__(
        self, *, version_id: str | None = "version-1", encryption: str = "aws:kms"
    ) -> None:
        self.files: list[tuple[str, str]] = []
        self.bytes: list[str] = []
        self.version_id = version_id
        self.encryption = encryption

    def put_file(self, key: str, source: str | Path, *, content_type: str) -> ObjectRef:
        digest, size = sha256_file(source)
        self.files.append((key, content_type))
        return ObjectRef(
            key,
            size,
            digest,
            content_type,
            "etag",
            self.version_id,
            self.encryption,
        )

    def put_bytes(self, key: str, data: bytes, *, content_type: str) -> ObjectRef:
        self.bytes.append(key)
        digest = hashlib.sha256(data).hexdigest()
        return ObjectRef(
            key, len(data), digest, content_type, "etag", "version-2", "aws:kms"
        )


class MultipartS3:
    kms_key = "arn:aws:kms:us-east-1:123456789012:key/test-key"

    def __init__(self) -> None:
        self.data = b""
        self.extra: dict[str, object] = {}

    def put_object(self, **kwargs: object) -> dict[str, object]:
        handle = kwargs["Body"]
        if not hasattr(handle, "read"):
            raise TypeError("body must be a file-like object")
        self.extra = kwargs
        chunks: list[bytes] = []
        while chunk := handle.read(257):  # type: ignore[union-attr]
            chunks.append(chunk)
        self.data = b"".join(chunks)
        return {"VersionId": "version-1", "ETag": '"etag"'}

    def head_object(self, **_kwargs: object) -> dict[str, object]:
        return {
            "ContentLength": len(self.data),
            "Metadata": self.extra["Metadata"],
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": self.kms_key,
            "ETag": '"etag"',
            "VersionId": "version-1",
            "ContentType": self.extra.get("ContentType", "application/octet-stream"),
        }

    def get_object(self, **_kwargs: object) -> dict[str, object]:
        return {
            **self.head_object(),
            "Body": io.BytesIO(self.data),
            "ContentType": "application/octet-stream",
        }


class MissingRetentionS3(FakeS3):
    def get_object_retention(self, **_kwargs: object) -> dict[str, object]:
        return {"Retention": {}}


class ImmutableRestoreStorage:
    def __init__(self, objects: dict[tuple[str, str], tuple[bytes, str]]) -> None:
        self.objects = objects
        self.requests: list[tuple[str, str]] = []

    def get_file(
        self,
        key: str,
        destination: str | Path,
        *,
        maximum_bytes: int,
        expected_sha256: str | None = None,
        version_id: str | None = None,
    ) -> ObjectRef:
        if version_id is None:
            raise AssertionError("an exact version is required")
        self.requests.append((key, version_id))
        data, encryption = self.objects[(key, version_id)]
        digest = hashlib.sha256(data).hexdigest()
        if len(data) > maximum_bytes or expected_sha256 != digest:
            raise DomainError("OBJECT_INTEGRITY_FAILED", "test object mismatch")
        Path(destination).write_bytes(data)
        return ObjectRef(
            key,
            len(data),
            digest,
            "application/octet-stream",
            "etag",
            version_id,
            encryption,
        )


class StorageRestoreHardeningTests(unittest.TestCase):
    def test_web_identity_session_requires_private_single_link_token(self) -> None:
        class FakeBoto3:
            class Session:
                def __init__(self, **_kwargs: object) -> None:
                    raise AssertionError("unsafe token must fail before session creation")

        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token.jwt"
            token.write_text("header.payload.signature", encoding="utf-8")
            token.chmod(0o644)
            config = {
                "method": "web_identity",
                "profile": "",
                "role_arn": "arn:aws:iam::123456789012:role/shadow-backup",
                "web_identity_token_file": str(token),
                "role_session_name": "shadow-backup-probe",
            }
            with self.assertRaises(DomainError) as public_token:
                workload_session(config, boto3_module=FakeBoto3)
            self.assertEqual(
                "WORKLOAD_IDENTITY_CONFIG_INVALID", public_token.exception.code
            )
            token.chmod(0o600)
            hardlink = Path(directory) / "token-hardlink.jwt"
            os.link(token, hardlink)
            config["web_identity_token_file"] = str(hardlink)
            with self.assertRaises(DomainError) as linked_token:
                workload_session(config, boto3_module=FakeBoto3)
            self.assertEqual(
                "WORKLOAD_IDENTITY_CONFIG_INVALID", linked_token.exception.code
            )

    def test_restore_urls_bind_all_roles_to_one_canonical_target(self) -> None:
        drill = PostgreSqlRestoreDrill(
            "postgresql+psycopg://shadow_backup@source.db.internal/source" + TLS,
            "postgresql://shadow_migration@RESTORE.DB.INTERNAL/shadow_restore_drill"
            + TLS,
            allow_restore=True,
            application_target_url=(
                "postgresql://shadow_api@restore.db.internal.:5432/shadow_restore_drill"
                + TLS
            ),
            backup_target_url=(
                "postgresql://shadow_backup@restore.db.internal/shadow_restore_drill"
                + TLS
            ),
            tenant_roles=("shadow_api", "shadow_action", "shadow_collector"),
            maintenance_role="shadow_worker",
            backup_role="shadow_backup",
            managed_provider="aws-rds",
            managed_instance_digest="a" * 64,
            require_managed_coordinates=True,
        )
        self.assertEqual("restore.db.internal", drill.target_coordinate.host)
        self.assertEqual(5432, drill.target_coordinate.port)

        with self.assertRaises(DomainError) as mismatch:
            PostgreSqlRestoreDrill(
                "postgresql://shadow_backup@source.db.internal/source" + TLS,
                "postgresql://shadow_migration@restore.db.internal/shadow_restore_drill"
                + TLS,
                allow_restore=True,
                application_target_url=(
                    "postgresql://shadow_api@other.db.internal/shadow_restore_drill"
                    + TLS
                ),
                backup_target_url=(
                    "postgresql://shadow_backup@restore.db.internal/shadow_restore_drill"
                    + TLS
                ),
                tenant_roles=("shadow_api",),
                maintenance_role="shadow_worker",
                backup_role="shadow_backup",
            )
        self.assertEqual("RESTORE_TARGET_BINDING_INVALID", mismatch.exception.code)

    def test_restore_rejects_equivalent_source_target_and_weak_managed_tls(
        self,
    ) -> None:
        with self.assertRaises(DomainError) as same:
            PostgreSqlRestoreDrill(
                "postgresql+psycopg://one@DB.INTERNAL/source?sslmode=require",
                "postgresql://two@db.internal.:5432/source?sslmode=verify-full",
                allow_restore=True,
            )
        self.assertEqual("RESTORE_TARGET_INVALID", same.exception.code)

        with self.assertRaises(DomainError) as tls:
            PostgreSqlRestoreDrill(
                "postgresql://shadow_backup@source.db.internal/source?sslmode=require",
                "postgresql://shadow_migration@restore.db.internal/shadow_restore_drill"
                + TLS,
                allow_restore=True,
                application_target_url=(
                    "postgresql://shadow_api@restore.db.internal/shadow_restore_drill"
                    + TLS
                ),
                backup_target_url=(
                    "postgresql://shadow_backup@restore.db.internal/shadow_restore_drill"
                    + TLS
                ),
                tenant_roles=("shadow_api",),
                maintenance_role="shadow_worker",
                backup_role="shadow_backup",
                managed_provider="aws-rds",
                managed_instance_digest="a" * 64,
                require_managed_coordinates=True,
            )
        self.assertEqual("MANAGED_POSTGRESQL_TLS_REQUIRED", tls.exception.code)

    def test_production_postgres_environment_requires_verify_full_and_is_minimal(
        self,
    ) -> None:
        with patch.dict(
            os.environ,
            {
                "SHADOW_ENVIRONMENT": "production",
                "PATH": "/usr/bin",
                "UNRELATED_SECRET": "must-not-reach-pg-dump",
            },
            clear=True,
        ):
            with self.assertRaises(DomainError) as tls:
                postgres_environment(
                    "postgresql://backup@db.internal/shadow?sslmode=require"
                )
            self.assertEqual("PRODUCTION_DATABASE_TLS_REQUIRED", tls.exception.code)
            with self.assertRaises(DomainError) as duplicate_root:
                postgres_environment(
                    "postgresql://backup@db.internal/shadow"
                    "?sslmode=verify-full&sslrootcert=%2Fca-one.pem"
                    "&sslrootcert=%2Fca-two.pem"
                )
            self.assertEqual(
                "PRODUCTION_DATABASE_TLS_REQUIRED", duplicate_root.exception.code
            )
            with self.assertRaises(DomainError) as blank_root:
                postgres_environment(
                    "postgresql://backup@db.internal/shadow"
                    "?sslmode=verify-full&sslrootcert=%20"
                )
            self.assertEqual(
                "PRODUCTION_DATABASE_TLS_REQUIRED", blank_root.exception.code
            )
            environment = postgres_environment(
                "postgresql://backup:password@db.internal/shadow" + TLS
            )
        self.assertEqual("verify-full", environment["PGSSLMODE"])
        self.assertEqual("/etc/ssl/postgres-root.pem", environment["PGSSLROOTCERT"])
        self.assertNotIn("UNRELATED_SECRET", environment)
        self.assertNotIn("SHADOW_ENVIRONMENT", environment)

    def test_local_and_s3_file_transfers_stream_without_path_read_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.bin"
            destination = root / "download.bin"
            source.write_bytes(os.urandom(2 * 1024 * 1024 + 17))
            local = LocalObjectStorage(root / "objects")
            with patch.object(
                Path, "read_bytes", side_effect=AssertionError("not streaming")
            ):
                reference = local.put_file(
                    "backups/source.bin",
                    source,
                    content_type="application/octet-stream",
                )
                downloaded = local.get_file(
                    "backups/source.bin",
                    destination,
                    maximum_bytes=3 * 1024 * 1024,
                    expected_sha256=reference.sha256,
                )
            self.assertEqual(reference.sha256, downloaded.sha256)
            self.assertEqual(sha256_file(source), sha256_file(destination))

            client = MultipartS3()
            s3 = S3ObjectStorage(
                "industrial-shadow-test",
                region="us-east-1",
                prefix="acceptance",
                kms_key_id=client.kms_key,
                client=client,
            )
            s3_reference = s3.put_file(
                "backups/source.bin", source, content_type="application/octet-stream"
            )
            s3_destination = root / "s3-download.bin"
            s3_download = s3.get_file(
                "backups/source.bin",
                s3_destination,
                maximum_bytes=3 * 1024 * 1024,
                expected_sha256=s3_reference.sha256,
                version_id=s3_reference.version_id,
            )
            self.assertEqual(s3_reference.sha256, s3_download.sha256)
            with self.assertRaises(DomainError) as wrong_version:
                s3.get_file(
                    "backups/source.bin",
                    root / "wrong-version.bin",
                    maximum_bytes=3 * 1024 * 1024,
                    version_id="version-2",
                )
            self.assertEqual("OBJECT_VERSION_INVALID", wrong_version.exception.code)

    def test_backup_job_uses_streaming_file_upload(self) -> None:
        storage = RecordingStorage()

        def run(
            command: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if command[0] == "pg_dump":
                output = Path(command[command.index("--file") + 1])
                output.write_bytes(b"postgres-custom-dump" * 1024)
            return subprocess.CompletedProcess(command, 0)

        environment = {
            "SHADOW_ENVIRONMENT": "test",
            "SHADOW_DATABASE_URL": "postgresql://backup@127.0.0.1/shadow?sslmode=disable",
            "SHADOW_OBJECT_STORAGE_BACKEND": "local",
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch(
                "shadow_sandbox.operations.backup_job.create_object_storage",
                return_value=storage,
            ),
            patch(
                "shadow_sandbox.operations.backup_job.subprocess.run", side_effect=run
            ),
        ):
            receipt = create_backup()
        self.assertEqual(1, len(storage.files))
        archive_receipt = receipt["archive"]
        self.assertIsInstance(archive_receipt, dict)
        if not isinstance(archive_receipt, dict):
            self.fail("backup receipt archive must be an object")
        self.assertEqual("version-1", archive_receipt["version_id"])
        self.assertTrue(storage.bytes[0].endswith(".manifest.json"))

    def test_restore_fetches_only_receipt_bound_kms_versions(self) -> None:
        archive = b"postgres-custom-dump"
        archive_digest = hashlib.sha256(archive).hexdigest()
        created_at = utc_now()
        source_url = "postgresql://shadow_backup@source.db.internal/source" + TLS
        source_digest = canonical_digest(
            {"host": "source.db.internal", "port": 5432, "database": "source"}
        )
        kms_key = "arn:aws:kms:us-east-1:123456789012:key/test-key"
        archive_descriptor = {
            "key": f"postgres/2026-08-13/{archive_digest}.dump",
            "size": len(archive),
            "sha256": archive_digest,
            "version_id": "archive-v7",
            "encryption": "aws:kms",
        }
        manifest: dict[str, object] = {
            "schema_version": 2,
            "created_at": created_at,
            "source_database_digest": source_digest,
            "archive": archive_descriptor,
            "kms_key_id_digest": canonical_digest({"kms_key_id": kms_key}),
            "format": "postgresql-custom",
            "verified_by": "pg_restore --list",
        }
        manifest["manifest_digest"] = canonical_digest(manifest)
        manifest_bytes = canonical_json(manifest).encode()
        manifest_descriptor = {
            "key": archive_descriptor["key"] + ".manifest.json",
            "size": len(manifest_bytes),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "version_id": "manifest-v9",
            "encryption": "aws:kms",
        }
        receipt: dict[str, object] = {
            "schema_version": 1,
            "created_at": created_at,
            "source_database_digest": source_digest,
            "archive": archive_descriptor,
            "manifest": manifest_descriptor,
            "manifest_digest": manifest["manifest_digest"],
        }
        receipt["receipt_digest"] = canonical_digest(receipt)
        storage = ImmutableRestoreStorage(
            {
                (str(archive_descriptor["key"]), "archive-v7"): (archive, "aws:kms"),
                (str(manifest_descriptor["key"]), "manifest-v9"): (
                    manifest_bytes,
                    "aws:kms",
                ),
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "receipt.json"
            receipt_path.write_text(canonical_json(receipt), encoding="utf-8")
            parsed = BackupRestoreReceipt.load(
                receipt_path, expected_source_database_digest=source_digest
            )
            drill = PostgreSqlRestoreDrill(
                source_url,
                "postgresql://shadow_migration@restore.db.internal/shadow_restore_drill"
                + TLS,
                allow_restore=True,
                object_storage=storage,  # type: ignore[arg-type]
                backup_receipt_path=receipt_path,
                kms_key_id=kms_key,
            )
            restored, manifest_ref, archive_ref, _seconds = (
                drill._fetch_immutable_backup(
                    Path(directory),
                    receipt=parsed,
                    kms_key_digest=canonical_digest({"kms_key_id": kms_key}),
                )
            )
            self.assertEqual(archive, restored.read_bytes())
            self.assertEqual("manifest-v9", manifest_ref.version_id)
            self.assertEqual("archive-v7", archive_ref.version_id)
            self.assertEqual(
                [
                    (str(manifest_descriptor["key"]), "manifest-v9"),
                    (str(archive_descriptor["key"]), "archive-v7"),
                ],
                storage.requests,
            )

            receipt["archive"] = {**archive_descriptor, "version_id": "attacker-v8"}
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaises(DomainError) as tampered:
                BackupRestoreReceipt.load(
                    receipt_path, expected_source_database_digest=source_digest
                )
            self.assertEqual("BACKUP_RECEIPT_INVALID", tampered.exception.code)

    def test_production_backup_requires_versioned_kms_object(self) -> None:
        storage = RecordingStorage(version_id=None)

        def run(
            command: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if command[0] == "pg_dump":
                output = Path(command[command.index("--file") + 1])
                output.write_bytes(b"postgres-custom-dump")
            return subprocess.CompletedProcess(command, 0)

        environment = {
            "SHADOW_ENVIRONMENT": "production",
            "SHADOW_DATABASE_URL": ("postgresql://backup@db.internal/shadow" + TLS),
            "SHADOW_OBJECT_STORAGE_BACKEND": "s3",
            "SHADOW_OBJECT_STORAGE_KMS_KEY_ID": (
                "arn:aws:kms:us-east-1:123456789012:key/test-key"
            ),
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch(
                "shadow_sandbox.operations.backup_job.create_object_storage",
                return_value=storage,
            ),
            patch(
                "shadow_sandbox.operations.backup_job.subprocess.run", side_effect=run
            ),
            self.assertRaises(DomainError) as raised,
        ):
            create_backup()
        self.assertEqual("DATABASE_BACKUP_STORAGE_INVALID", raised.exception.code)

    def test_tls_policy_lifecycle_and_actual_object_retention_are_scope_bound(
        self,
    ) -> None:
        storage = S3ObjectStorage(
            "industrial-shadow-test",
            region="us-east-1",
            prefix="acceptance",
            kms_key_id=FakeS3.kms_key,
            client=object(),
        )
        probe = S3KmsProbe(storage)
        policy = {
            "Statement": {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    "arn:aws:s3:::industrial-shadow-test",
                    "arn:aws:s3:::industrial-shadow-test/*",
                ],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        }
        self.assertTrue(probe._tls_only_policy(policy, storage.bucket))
        policy["Statement"]["Condition"]["StringEquals"] = {"scope": "partial"}
        self.assertFalse(probe._tls_only_policy(policy, storage.bucket))
        del policy["Statement"]["Condition"]["StringEquals"]
        policy["Statement"]["Resource"] = "arn:aws:s3:::another-bucket/*"
        self.assertFalse(probe._tls_only_policy(policy, storage.bucket))
        policy["Statement"]["Resource"] = [
            "arn:aws-us-gov:s3:::industrial-shadow-test",
            "arn:aws-us-gov:s3:::industrial-shadow-test/*",
        ]
        self.assertTrue(probe._tls_only_policy(policy, storage.bucket, "aws-us-gov"))

        rule = {
            "Status": "Enabled",
            "Filter": {"Prefix": "acceptance/production-probes/"},
            "Expiration": {"Days": 30},
            "NoncurrentVersionExpiration": {"NoncurrentDays": 30},
        }
        self.assertTrue(
            probe._lifecycle_rule_covers(rule, "acceptance/production-probes/value.bin")
        )
        self.assertFalse(probe._lifecycle_rule_covers(rule, "another-prefix/value.bin"))
        rule["Expiration"] = {"Days": True}
        self.assertFalse(
            probe._lifecycle_rule_covers(rule, "acceptance/production-probes/value.bin")
        )

        client = MissingRetentionS3()
        locked_storage = S3ObjectStorage(
            "industrial-shadow-test",
            prefix="acceptance",
            kms_key_id=client.kms_key,
            client=client,
        )
        evidence = S3KmsProbe(locked_storage, require_object_lock=True).run()
        self.assertEqual("FAILED", evidence.status)
        self.assertFalse(
            next(
                check.passed
                for check in evidence.checks
                if check.name == "probe_object_disposition"
            )
        )


if __name__ == "__main__":
    unittest.main()
