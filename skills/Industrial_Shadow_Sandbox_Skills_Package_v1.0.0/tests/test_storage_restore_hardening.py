from __future__ import annotations

import datetime as dt
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
from shadow_sandbox.operations.storage_probe import (
    S3KmsProbe,
    S3SentinelBinding,
    S3WorkloadIdentityProbe,
    s3_control_plane_mutation_confirmation,
    workload_session,
)
from test_production_closure import FakeS3

TLS = "?sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Fpostgres-root.pem"


class FakeBody(io.BytesIO):
    pass


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


class ProductionControlPlaneS3(FakeS3):
    backup_sentinel = "snapshot/signatures/forbidden-to-backup.bin"
    snapshot_sentinel = "backup/signatures/forbidden-to-snapshot.bin"

    def __init__(self, *, lifecycle_valid: bool = True) -> None:
        super().__init__()
        self.lifecycle_valid = lifecycle_valid
        self.calls: list[str] = []
        self.objects.update(
            {
                self.backup_sentinel: b"backup-forbidden-sentinel",
                self.snapshot_sentinel: b"snapshot-forbidden-sentinel",
            }
        )

    def get_bucket_versioning(self, **kwargs: object) -> dict[str, str]:
        self.calls.append("get_bucket_versioning")
        return super().get_bucket_versioning(**kwargs)

    def get_public_access_block(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("get_public_access_block")
        return super().get_public_access_block(**kwargs)

    def get_bucket_encryption(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("get_bucket_encryption")
        value = super().get_bucket_encryption(**kwargs)
        rules = value["ServerSideEncryptionConfiguration"]["Rules"]  # type: ignore[index]
        rules[0]["BucketKeyEnabled"] = True  # type: ignore[index]
        return value

    def get_bucket_lifecycle_configuration(
        self, **_kwargs: object
    ) -> dict[str, object]:
        self.calls.append("get_bucket_lifecycle_configuration")
        prefixes = [
            "acceptance/production-probes/",
            "snapshot/signatures/",
            "backup/signatures/",
        ]
        if not self.lifecycle_valid:
            prefixes.pop()
        return {
            "Rules": [
                {
                    "ID": f"retention-{index}",
                    "Status": "Enabled",
                    "Filter": {"Prefix": prefix},
                    "Expiration": {"Days": 30},
                    "NoncurrentVersionExpiration": {"NoncurrentDays": 30},
                }
                for index, prefix in enumerate(prefixes)
            ]
        }

    def get_bucket_location(self, **_kwargs: object) -> dict[str, object]:
        self.calls.append("get_bucket_location")
        return {"LocationConstraint": "us-east-1"}

    def get_bucket_policy_status(self, **_kwargs: object) -> dict[str, object]:
        self.calls.append("get_bucket_policy_status")
        return {"PolicyStatus": {"IsPublic": False}}

    def get_bucket_policy(self, **_kwargs: object) -> dict[str, object]:
        self.calls.append("get_bucket_policy")
        return {
            "Policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:*",
                            "Resource": [
                                "arn:aws:s3:::industrial-shadow-test",
                                "arn:aws:s3:::industrial-shadow-test/*",
                            ],
                            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                        }
                    ]
                }
            )
        }

    def get_object_lock_configuration(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("get_object_lock_configuration")
        return super().get_object_lock_configuration(**kwargs)

    def head_object(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("head_object")
        return super().head_object(**kwargs)

    def get_object(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("get_object")
        return super().get_object(**kwargs)

    def get_object_retention(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("get_object_retention")
        return super().get_object_retention(**kwargs)

    def list_object_versions(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("list_object_versions")
        return super().list_object_versions(**kwargs)

    def put_object(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("put_object")
        return super().put_object(**kwargs)

    def delete_object(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("delete_object")
        return super().delete_object(**kwargs)


class ProductionKms:
    def describe_key(self, *, KeyId: str) -> dict[str, object]:  # noqa: N803
        return {
            "KeyMetadata": {
                "Arn": KeyId,
                "KeyState": "Enabled",
                "Enabled": True,
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeySpec": "SYMMETRIC_DEFAULT",
            }
        }

    def get_key_rotation_status(self, *, KeyId: str) -> dict[str, object]:  # noqa: N803
        if KeyId != FakeS3.kms_key:
            raise AssertionError("unexpected KMS key")
        return {"KeyRotationEnabled": True}


class ProductionSts:
    def get_caller_identity(self) -> dict[str, str]:
        return {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/acceptance/control",
        }


class FakeAwsError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.response = {"Error": {"Code": code, "Message": message}}
        super().__init__(message)


class SentinelBoundaryS3:
    kms_key = "arn:aws:kms:us-east-1:123456789012:key/test-key"
    sentinel_key = "snapshot/signatures/cross-prefix.bin"
    sentinel_version = "sentinel-v7"
    sentinel_data = b"immutable-cross-prefix-sentinel"

    def __init__(
        self,
        *,
        deny_cross_prefix: bool = False,
        kms_only_denial: bool = False,
        deny_probe_delete: bool = False,
    ) -> None:
        self.deny_cross_prefix = deny_cross_prefix
        self.kms_only_denial = kms_only_denial
        self.deny_probe_delete = deny_probe_delete
        self.objects: dict[str, tuple[bytes, str]] = {}
        self.deleted: set[tuple[str, str]] = set()
        self.retention_calls = 0
        self.requests: list[tuple[str, dict[str, object]]] = []

    @staticmethod
    def _metadata(data: bytes) -> dict[str, str]:
        return {"sha256": hashlib.sha256(data).hexdigest()}

    def _deny(self) -> None:
        message = (
            "KMS AccessDenied: kms:Decrypt is not authorized"
            if self.kms_only_denial
            else "Access Denied by the S3 prefix policy"
        )
        raise FakeAwsError("AccessDenied", message)

    def put_object(self, **kwargs: object) -> dict[str, object]:
        key = str(kwargs["Key"])
        body = kwargs["Body"]
        if not isinstance(body, bytes):
            raise TypeError("test body must be bytes")
        self.objects[key] = (body, "probe-v1")
        return {"ETag": '"probe-etag"', "VersionId": "probe-v1"}

    def _object(self, key: str) -> tuple[bytes, str]:
        if key == self.sentinel_key:
            if self.deny_cross_prefix:
                self._deny()
            return self.sentinel_data, self.sentinel_version
        if key not in self.objects:
            raise FakeAwsError("NoSuchKey", "object not found")
        data, version = self.objects[key]
        if (key, version) in self.deleted:
            raise FakeAwsError("NoSuchVersion", "object version not found")
        return data, version

    def head_object(self, **kwargs: object) -> dict[str, object]:
        self.requests.append(("head_object", dict(kwargs)))
        key = str(kwargs["Key"])
        data, version = self._object(key)
        requested_version = kwargs.get("VersionId")
        if requested_version is not None and requested_version != version:
            raise FakeAwsError("NoSuchVersion", "object version not found")
        return {
            "ContentLength": len(data),
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": self.kms_key,
            "Metadata": self._metadata(data),
            "VersionId": version,
            "ETag": '"sentinel-etag"' if key == self.sentinel_key else '"probe-etag"',
        }

    def get_object(self, **kwargs: object) -> dict[str, object]:
        self.requests.append(("get_object", dict(kwargs)))
        result = self.head_object(**kwargs)
        data, _version = self._object(str(kwargs["Key"]))
        return {**result, "Body": FakeBody(data)}

    def list_objects_v2(self, **kwargs: object) -> dict[str, object]:
        self.requests.append(("list_objects_v2", dict(kwargs)))
        if (
            str(kwargs.get("Prefix", "")) == self.sentinel_key
            and self.deny_cross_prefix
        ):
            if self.kms_only_denial:
                return {"Contents": []}
            self._deny()
        return {"Contents": []}

    def list_object_versions(self, **kwargs: object) -> dict[str, object]:
        self.requests.append(("list_object_versions", dict(kwargs)))
        prefix = str(kwargs.get("Prefix", ""))
        if prefix == self.sentinel_key and self.deny_cross_prefix:
            if self.kms_only_denial:
                return {"Versions": []}
            self._deny()
        if prefix == self.sentinel_key:
            return {
                "Versions": [
                    {"Key": self.sentinel_key, "VersionId": self.sentinel_version}
                ]
            }
        return {"Versions": []}

    def get_object_retention(self, **kwargs: object) -> dict[str, object]:
        self.retention_calls += 1
        if str(kwargs.get("Key", "")) != self.sentinel_key:
            raise AssertionError("workload probe must not query object retention")
        return {
            "Retention": {
                "Mode": "COMPLIANCE",
                "RetainUntilDate": dt.datetime.now(dt.UTC) + dt.timedelta(days=30),
            }
        }

    def delete_object(self, **kwargs: object) -> dict[str, object]:
        key = str(kwargs["Key"])
        version = str(kwargs.get("VersionId", ""))
        if self.deny_probe_delete:
            raise FakeAwsError("AccessDenied", "retained version cannot be deleted")
        self.deleted.add((key, version))
        return {"VersionId": version}


class WorkloadSts:
    def __init__(self, role_name: str) -> None:
        self.role_name = role_name

    def get_caller_identity(self) -> dict[str, str]:
        return {
            "Account": "123456789012",
            "Arn": (
                "arn:aws:sts::123456789012:assumed-role/"
                f"{self.role_name}/production-probe"
            ),
        }


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
                    raise AssertionError(
                        "unsafe token must fail before session creation"
                    )

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
            token.unlink()
            hardlink.unlink()
            target = Path(directory) / "target.jwt"
            target.write_text("header.payload.signature", encoding="utf-8")
            target.chmod(0o600)
            symlink = Path(directory) / "token-symlink.jwt"
            symlink.symlink_to(target)
            config["web_identity_token_file"] = str(symlink)
            with self.assertRaises(DomainError) as symlink_token:
                workload_session(config, boto3_module=FakeBoto3)
            self.assertEqual(
                "WORKLOAD_IDENTITY_CONFIG_INVALID", symlink_token.exception.code
            )

    def test_web_identity_session_reads_the_private_token_from_one_descriptor(
        self,
    ) -> None:
        class FakeSts:
            def assume_role_with_web_identity(
                self, **kwargs: object
            ) -> dict[str, object]:
                if kwargs["WebIdentityToken"] != "header.payload.signature":
                    raise AssertionError("unexpected web identity token")
                return {
                    "Credentials": {
                        "AccessKeyId": "temporary-access-key",
                        "SecretAccessKey": "temporary-secret-key",
                        "SessionToken": "temporary-session-token",
                    }
                }

        class FakeBoto3:
            sessions: list[dict[str, object]] = []

            class Session:
                def __init__(self, **kwargs: object) -> None:
                    FakeBoto3.sessions.append(dict(kwargs))

                def client(self, name: str) -> FakeSts:
                    if name != "sts":
                        raise AssertionError("only STS is expected")
                    return FakeSts()

        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token.jwt"
            token.write_text("header.payload.signature\n", encoding="utf-8")
            token.chmod(0o400)
            session = workload_session(
                {
                    "method": "web_identity",
                    "profile": "",
                    "role_arn": "arn:aws:iam::123456789012:role/shadow-backup",
                    "web_identity_token_file": str(token),
                    "role_session_name": "shadow-backup-probe",
                },
                boto3_module=FakeBoto3,
            )
        self.assertIsInstance(session, FakeBoto3.Session)
        self.assertEqual({}, FakeBoto3.sessions[0])
        self.assertEqual(
            {
                "aws_access_key_id": "temporary-access-key",
                "aws_secret_access_key": "temporary-secret-key",
                "aws_session_token": "temporary-session-token",
            },
            FakeBoto3.sessions[1],
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

    def test_production_s3_binds_owner_region_and_rejects_custom_endpoints(
        self,
    ) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(DomainError) as owner:
                S3ObjectStorage(
                    "industrial-shadow-test",
                    region="us-east-1",
                    client=object(),
                    production=True,
                )
            self.assertEqual(
                "OBJECT_STORAGE_BUCKET_OWNER_REQUIRED", owner.exception.code
            )
            with self.assertRaises(DomainError) as endpoint:
                S3ObjectStorage(
                    "industrial-shadow-test",
                    region="us-east-1",
                    endpoint_url="https://s3-proxy.example.invalid",
                    kms_key_id=SentinelBoundaryS3.kms_key,
                    client=object(),
                    expected_bucket_owner="123456789012",
                    production=True,
                )
            self.assertEqual(
                "OBJECT_STORAGE_CUSTOM_ENDPOINT_FORBIDDEN", endpoint.exception.code
            )
            storage = S3ObjectStorage(
                "industrial-shadow-test",
                region="us-east-1",
                kms_key_id=SentinelBoundaryS3.kms_key,
                client=object(),
                expected_bucket_owner="123456789012",
                production=True,
            )
            derived_owner = S3ObjectStorage(
                "industrial-shadow-test",
                region="us-east-1",
                kms_key_id=SentinelBoundaryS3.kms_key,
                client=object(),
                production=True,
            )
        self.assertEqual("123456789012", derived_owner.expected_bucket_owner)
        self.assertEqual(
            {
                "Bucket": "industrial-shadow-test",
                "ExpectedBucketOwner": "123456789012",
                "Key": "backup/object.bin",
            },
            storage.bucket_request(Key="backup/object.bin"),
        )
        with self.assertRaises(DomainError) as replacement:
            storage.bucket_request(ExpectedBucketOwner="000000000000")
        self.assertEqual("OBJECT_STORAGE_REQUEST_INVALID", replacement.exception.code)

    @staticmethod
    def _control_plane_sentinel() -> S3SentinelBinding:
        client = SentinelBoundaryS3()
        storage = S3ObjectStorage(
            "industrial-shadow-test",
            region="us-east-1",
            prefix="acceptance",
            kms_key_id=client.kms_key,
            client=client,
            expected_bucket_owner="123456789012",
            production=False,
        )
        binding = S3KmsProbe(storage).bind_immutable_sentinel(client.sentinel_key)
        if client.retention_calls != 1:
            raise AssertionError("control plane must verify exact sentinel retention")
        return binding

    def test_control_plane_binds_retained_sentinel_and_rejects_tampering(self) -> None:
        binding = self._control_plane_sentinel()
        self.assertEqual(SentinelBoundaryS3.sentinel_version, binding.version_id)
        self.assertEqual(
            hashlib.sha256(SentinelBoundaryS3.sentinel_data).hexdigest(),
            binding.sha256,
        )
        restored = S3SentinelBinding.from_mapping(binding.to_mapping())
        self.assertEqual(binding, restored)
        tampered = dict(binding.to_mapping())
        tampered["version_id"] = "attacker-version"
        with self.assertRaises(DomainError) as invalid:
            S3SentinelBinding.from_mapping(tampered)
        self.assertEqual("S3_SENTINEL_BINDING_INVALID", invalid.exception.code)

        client = SentinelBoundaryS3()
        storage = S3ObjectStorage(
            "industrial-shadow-test",
            region="us-east-1",
            prefix="acceptance",
            kms_key_id=client.kms_key,
            client=client,
            production=False,
        )
        with (
            patch.object(
                client, "get_object_retention", return_value={"Retention": {}}
            ),
            self.assertRaises(DomainError) as unretained,
        ):
            S3KmsProbe(storage).bind_immutable_sentinel(client.sentinel_key)
        self.assertEqual("S3_SENTINEL_RETENTION_INVALID", unretained.exception.code)

    def test_workload_probe_uses_exact_cross_prefix_version_and_no_retention_api(
        self,
    ) -> None:
        binding = self._control_plane_sentinel()
        client = SentinelBoundaryS3(deny_cross_prefix=True)
        storage = S3ObjectStorage(
            "industrial-shadow-test",
            region="us-east-1",
            prefix="backup",
            kms_key_id=client.kms_key,
            client=client,
            expected_bucket_owner="123456789012",
            production=False,
        )
        with self.assertRaises(DomainError) as bare_key:
            S3WorkloadIdentityProbe(
                storage,
                identity="backup",
                sts_client=WorkloadSts("shadow-backup"),
                expected_role_arn="arn:aws:iam::123456789012:role/shadow-backup",
                forbidden_key=binding.key,
            )
        self.assertEqual("WORKLOAD_IDENTITY_CONFIG_INVALID", bare_key.exception.code)
        evidence = S3WorkloadIdentityProbe(
            storage,
            identity="backup",
            sts_client=WorkloadSts("shadow-backup"),
            expected_role_arn="arn:aws:iam::123456789012:role/shadow-backup",
            forbidden_sentinel=binding,
        ).run()
        self.assertEqual("PASSED", evidence.status)
        self.assertEqual(0, client.retention_calls)
        exact_cross_requests = [
            arguments
            for operation, arguments in client.requests
            if operation in {"get_object", "head_object"}
            and arguments.get("Key") == binding.key
        ]
        self.assertTrue(exact_cross_requests)
        self.assertTrue(
            all(
                request.get("VersionId") == binding.version_id
                and request.get("ExpectedBucketOwner") == "123456789012"
                for request in exact_cross_requests
            )
        )
        self.assertTrue(
            any(
                operation == "list_object_versions"
                and arguments.get("Prefix") == binding.key
                for operation, arguments in client.requests
            )
        )
        self.assertTrue(
            next(
                check.passed
                for check in evidence.checks
                if check.name == "cross_prefix_version_list_denied"
            )
        )
        self.assertTrue(
            next(
                check.passed
                for check in evidence.checks
                if check.name == "probe_object_disposition"
            )
        )

    def test_workload_probe_rejects_a_kms_only_cross_prefix_denial(self) -> None:
        binding = self._control_plane_sentinel()
        client = SentinelBoundaryS3(
            deny_cross_prefix=True,
            kms_only_denial=True,
        )
        storage = S3ObjectStorage(
            "industrial-shadow-test",
            region="us-east-1",
            prefix="backup",
            kms_key_id=client.kms_key,
            client=client,
            expected_bucket_owner="123456789012",
            production=False,
        )
        evidence = S3WorkloadIdentityProbe(
            storage,
            identity="backup",
            sts_client=WorkloadSts("shadow-backup"),
            expected_role_arn="arn:aws:iam::123456789012:role/shadow-backup",
            forbidden_sentinel=binding,
        ).run()
        self.assertEqual("FAILED", evidence.status)
        self.assertEqual(1, evidence.metrics["kms_denial_observed"])
        self.assertFalse(
            next(
                check.passed
                for check in evidence.checks
                if check.name == "cross_prefix_denial_not_kms_only"
            )
        )

    def test_locked_workload_probe_treats_delete_denial_as_disposition_without_retention_read(
        self,
    ) -> None:
        binding = self._control_plane_sentinel()
        client = SentinelBoundaryS3(
            deny_cross_prefix=True,
            deny_probe_delete=True,
        )
        storage = S3ObjectStorage(
            "industrial-shadow-test",
            region="us-east-1",
            prefix="backup",
            kms_key_id=client.kms_key,
            client=client,
            expected_bucket_owner="123456789012",
            production=False,
        )
        evidence = S3WorkloadIdentityProbe(
            storage,
            identity="backup",
            sts_client=WorkloadSts("shadow-backup"),
            expected_role_arn="arn:aws:iam::123456789012:role/shadow-backup",
            forbidden_sentinel=binding,
            require_object_lock=True,
        ).run()
        self.assertEqual("PASSED", evidence.status)
        self.assertEqual(0, client.retention_calls)

    def test_three_lifecycle_prefixes_are_exact_and_non_overlapping(self) -> None:
        storage = S3ObjectStorage(
            "industrial-shadow-test",
            region="us-east-1",
            prefix="acceptance",
            kms_key_id=SentinelBoundaryS3.kms_key,
            client=object(),
            production=False,
        )
        probe = S3KmsProbe(
            storage,
            lifecycle_prefixes={
                "acceptance": "acceptance/production-probes/",
                "snapshot": "snapshot/signatures/",
                "backup": "backup/signatures/",
            },
        )
        rules = [
            {
                "Status": "Enabled",
                "Filter": {"Prefix": prefix},
                "Expiration": {"Days": 30},
                "NoncurrentVersionExpiration": {"NoncurrentDays": 30},
            }
            for prefix in probe.lifecycle_prefixes.values()
        ]
        for name, prefix in probe.lifecycle_prefixes.items():
            self.assertTrue(
                any(
                    probe._lifecycle_rule_covers(rule, prefix + "signature.json")
                    for rule in rules
                ),
                name,
            )
        with self.assertRaises(DomainError) as nested:
            S3KmsProbe(
                storage,
                lifecycle_prefixes={
                    "acceptance": "acceptance/production-probes/",
                    "snapshot": "backup/snapshot/",
                    "backup": "backup/",
                },
            )
        self.assertEqual("S3_LIFECYCLE_PREFIX_INVALID", nested.exception.code)

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


class S3ControlPlaneMutationAuthorizationTests(unittest.TestCase):
    run_id = "24681012-3"
    target_profile_digest = "a" * 64

    @classmethod
    def _confirmation(cls) -> str:
        return s3_control_plane_mutation_confirmation(
            bucket="industrial-shadow-test",
            prefix="acceptance",
            acceptance_run_id=cls.run_id,
            signed_target_profile_digest=cls.target_profile_digest,
        )

    @classmethod
    def _probe(
        cls,
        client: ProductionControlPlaneS3,
        *,
        confirmation: str,
    ) -> S3KmsProbe:
        storage = S3ObjectStorage(
            "industrial-shadow-test",
            region="us-east-1",
            prefix="acceptance",
            kms_key_id=client.kms_key,
            client=client,
            expected_bucket_owner="123456789012",
            production=True,
        )
        return S3KmsProbe(
            storage,
            require_object_lock=True,
            kms_client=ProductionKms(),
            sts_client=ProductionSts(),
            expected_account_id="123456789012",
            require_cloud_control_plane=True,
            lifecycle_prefixes={
                "acceptance": "acceptance/production-probes/",
                "snapshot": "snapshot/signatures/",
                "backup": "backup/signatures/",
            },
            immutable_sentinel_keys={
                "backup": client.backup_sentinel,
                "snapshot": client.snapshot_sentinel,
            },
            acceptance_run_id=cls.run_id,
            signed_target_profile_digest=cls.target_profile_digest,
            mutation_confirmation=confirmation,
        )

    def test_confirmation_is_bound_to_bucket_prefix_run_and_signed_profile(
        self,
    ) -> None:
        expected = self._confirmation()
        variants = (
            {"bucket": "another-industrial-shadow-test"},
            {"prefix": "another-acceptance"},
            {"acceptance_run_id": "24681012-4"},
            {"signed_target_profile_digest": "b" * 64},
        )
        for overrides in variants:
            coordinates = {
                "bucket": "industrial-shadow-test",
                "prefix": "acceptance",
                "acceptance_run_id": self.run_id,
                "signed_target_profile_digest": self.target_profile_digest,
                **overrides,
            }
            self.assertNotEqual(
                expected,
                s3_control_plane_mutation_confirmation(**coordinates),
            )

    def test_invalid_confirmation_never_mutates_after_read_only_validation(
        self,
    ) -> None:
        client = ProductionControlPlaneS3()
        with self.assertRaises(DomainError) as rejected:
            self._probe(client, confirmation="0" * 64).run()
        self.assertEqual("S3_MUTATION_CONFIRMATION_REQUIRED", rejected.exception.code)
        self.assertNotIn("put_object", client.calls)
        self.assertNotIn("delete_object", client.calls)
        self.assertEqual(2, client.calls.count("get_object_retention"))

    def test_failed_lifecycle_control_never_mutates_even_with_confirmation(
        self,
    ) -> None:
        client = ProductionControlPlaneS3(lifecycle_valid=False)
        with self.assertRaises(DomainError) as rejected:
            self._probe(client, confirmation=self._confirmation()).run()
        self.assertEqual("S3_CONTROL_PLANE_INVALID", rejected.exception.code)
        self.assertNotIn("put_object", client.calls)
        self.assertNotIn("delete_object", client.calls)
        self.assertEqual(2, client.calls.count("get_object_retention"))

    def test_authorized_write_occurs_only_after_both_sentinels_are_bound(self) -> None:
        client = ProductionControlPlaneS3()
        evidence = self._probe(client, confirmation=self._confirmation()).run()
        self.assertEqual("PASSED", evidence.status)
        first_mutation = client.calls.index("put_object")
        retention_reads = [
            index
            for index, operation in enumerate(client.calls)
            if operation == "get_object_retention" and index < first_mutation
        ]
        self.assertEqual(2, len(retention_reads))
        self.assertTrue(all(index < first_mutation for index in retention_reads))
        self.assertEqual(1, evidence.metrics["mutation_authorizations_verified"])
        self.assertTrue(
            next(
                check.passed
                for check in evidence.checks
                if check.name == "mutation_authorization_bound"
            )
        )


if __name__ == "__main__":
    unittest.main()
