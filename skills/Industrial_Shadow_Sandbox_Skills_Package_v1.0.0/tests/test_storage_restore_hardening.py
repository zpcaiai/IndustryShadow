from __future__ import annotations

import copy
import datetime as dt
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import ClassVar, Self
from unittest.mock import patch

from shadow_sandbox.common import DomainError
from shadow_sandbox.common.models import canonical_digest, canonical_json, utc_now
from shadow_sandbox.common.object_storage import (
    LocalObjectStorage,
    ObjectRef,
    ObjectRetention,
    S3ObjectStorage,
    sha256_file,
)
from shadow_sandbox.operations.backup_job import create_backup, postgres_environment
from shadow_sandbox.operations.restore_drill import (
    CATALOG_QUERIES,
    CATALOG_SECURITY_QUERIES,
    BackupRestoreReceipt,
    PostgreSqlRestoreDrill,
)
from shadow_sandbox.operations.storage_probe import (
    AWS_STORAGE_POLICY_DIGEST_FIELDS,
    KMS_ADMIN_ACTIONS,
    PROTECTED_S3_MUTATION_ACTIONS,
    S3KmsProbe,
    S3SentinelBinding,
    S3WorkloadIdentityProbe,
    aws_policy_digest,
    aws_storage_policy_bundle_digest,
    bucket_policy_is_workload_bound,
    github_actions_caller_trust_contract,
    github_actions_caller_trust_is_exact,
    iam_control_plane_caller_permissions_are_least_privilege,
    iam_role_permissions_are_least_privilege,
    inspect_iam_control_plane_caller_role,
    inspect_iam_oidc_provider,
    inspect_iam_role_trust_policy,
    inspect_iam_storage_role,
    inspect_kms_policy_and_grants,
    normalize_aws_policy,
    s3_bucket_controls_digest,
    s3_control_plane_mutation_confirmation,
    workload_session,
)
from test_production_closure import FakeS3

from tools.collect_aws_storage_policy_digests import (
    collect_aws_storage_policy_digests,
)

TLS = "?sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Fpostgres-root.pem"


def backup_snapshot_fixture() -> dict[str, object]:
    empty = {"count": 0, "sha256": "1" * 64}
    sections = {
        name: dict(empty)
        for name, _sql in (*CATALOG_QUERIES, *CATALOG_SECURITY_QUERIES)
    }
    sections["sequence_runtime_state"] = dict(empty)
    catalog = {
        "sha256": canonical_digest(sections),
        "objects": 0,
        "sections": sections,
    }
    value: dict[str, object] = {
        "schema_version": 1,
        "capture_method": "pg-export-snapshot-v1",
        "tables": {"domain_resources": {"count": 0, "sha256": "2" * 64}},
        "rls_policies": {"count": 1, "sha256": "3" * 64},
        "catalog": catalog,
        "migration_versions": [1],
        "backup_role": {
            "name": "shadow_backup",
            "bypass_rls": True,
            "owns_tables": False,
            "owns_routines": False,
            "matrix_exact_read_only": True,
        },
    }
    value["snapshot_digest"] = canonical_digest(value)
    return value


class FakeBackupSnapshot:
    snapshot_id = "00000003-0000001B-1"

    def __init__(self, _database_url: str) -> None:
        self.created_at = utc_now()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_arguments: object) -> None:
        return None


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

    def __init__(self, *, fail_part_number: int | None = None) -> None:
        self.data = b""
        self.extra: dict[str, object] = {}
        self.parts: dict[int, bytes] = {}
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.fail_part_number = fail_part_number

    def put_object(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("put_object", dict(kwargs)))
        handle = kwargs["Body"]
        if not hasattr(handle, "read"):
            raise TypeError("body must be a file-like object")
        self.extra = kwargs
        chunks: list[bytes] = []
        while chunk := handle.read(257):  # type: ignore[union-attr]
            chunks.append(chunk)
        self.data = b"".join(chunks)
        return {"VersionId": "version-1", "ETag": '"etag"'}

    def create_multipart_upload(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("create_multipart_upload", dict(kwargs)))
        self.extra = dict(kwargs)
        return {"UploadId": "upload-1"}

    def upload_part(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("upload_part", dict(kwargs)))
        part_number = kwargs.get("PartNumber")
        body = kwargs.get("Body")
        if type(part_number) is not int or not isinstance(body, bytes):
            raise TypeError("multipart part contract is invalid")
        if part_number == self.fail_part_number:
            raise RuntimeError("injected multipart part failure")
        self.parts[part_number] = body
        return {"ETag": f'"part-{part_number}"'}

    def complete_multipart_upload(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("complete_multipart_upload", dict(kwargs)))
        self.data = b"".join(self.parts[number] for number in sorted(self.parts))
        return {"VersionId": "version-1", "ETag": '"multipart-etag"'}

    def abort_multipart_upload(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("abort_multipart_upload", dict(kwargs)))
        self.parts.clear()
        return {}

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


AWS_ACCOUNT_ID = "123456789012"
IRSA_PROVIDER_ARN = (
    "arn:aws:iam::123456789012:oidc-provider/"
    "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE1234567890"
)
STORAGE_ROLE_ARNS = {
    "backup": "arn:aws:iam::123456789012:role/shadow-backup",
    "snapshot": "arn:aws:iam::123456789012:role/shadow-snapshot",
}
STORAGE_PREFIXES = {
    "acceptance": "acceptance/production-probes/",
    "backup": "backup/signatures/",
    "snapshot": "snapshot/signatures/",
}
TRUST_SUBJECTS = {
    "backup": "system:serviceaccount:industrial-shadow:shadow-backup-storage",
    "snapshot": "system:serviceaccount:industrial-shadow:shadow-simulator-storage",
}
CONTROL_PLANE_CALLER_ARN = "arn:aws:iam::123456789012:role/acceptance"
KMS_ADMIN_ROLE_ARN = "arn:aws:iam::123456789012:role/shadow-kms-admin"
CALLER_TRUST_CONTRACT = github_actions_caller_trust_contract(
    account_id=AWS_ACCOUNT_ID,
    region="us-east-1",
    repository="industrial-shadow/industry-shadow",
    repository_owner_id="214596190",
    repository_id="24681012",
    ref="refs/heads/main",
    environment="production-acceptance",
    workflow="production-acceptance",
)


class ProductionControlPlaneS3(FakeS3):
    backup_sentinel = "snapshot/signatures/forbidden-to-backup.bin"
    snapshot_sentinel = "backup/signatures/forbidden-to-snapshot.bin"

    def __init__(
        self,
        *,
        lifecycle_valid: bool = True,
        extra_bucket_allow: bool = False,
        missing_mutation_guard: bool = False,
    ) -> None:
        super().__init__()
        self.lifecycle_valid = lifecycle_valid
        self.extra_bucket_allow = extra_bucket_allow
        self.missing_mutation_guard = missing_mutation_guard
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

    def get_bucket_ownership_controls(self, **_kwargs: object) -> dict[str, object]:
        self.calls.append("get_bucket_ownership_controls")
        return {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}}

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
                    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
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

    def bucket_policy(self) -> dict[str, object]:
        bucket_arn = "arn:aws:s3:::industrial-shadow-test"
        statements: list[dict[str, object]] = [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        ]
        for identity in ("backup", "snapshot"):
            if self.missing_mutation_guard and identity == "snapshot":
                continue
            statements.append(
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": sorted(PROTECTED_S3_MUTATION_ACTIONS),
                    "Resource": f"{bucket_arn}/{STORAGE_PREFIXES[identity]}*",
                    "Condition": {
                        "ArnNotEquals": {
                            "aws:PrincipalArn": STORAGE_ROLE_ARNS[identity]
                        }
                    },
                }
            )
        identity_arns = {"acceptance": CONTROL_PLANE_CALLER_ARN, **STORAGE_ROLE_ARNS}
        for identity in ("acceptance", "backup", "snapshot"):
            object_arn = f"{bucket_arn}/{STORAGE_PREFIXES[identity]}*"
            principal = {"AWS": identity_arns[identity]}
            statements.extend(
                (
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:PutObject",
                        "Resource": object_arn,
                        "Condition": {
                            "Null": {"s3:x-amz-server-side-encryption": "false"},
                            "StringNotEquals": {
                                "s3:x-amz-server-side-encryption": "aws:kms"
                            },
                        },
                    },
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:PutObject",
                        "Resource": object_arn,
                        "Condition": {
                            "Null": {
                                "s3:x-amz-server-side-encryption-aws-kms-key-id": (
                                    "false"
                                )
                            },
                            "StringNotEquals": {
                                "s3:x-amz-server-side-encryption-aws-kms-key-id": (
                                    self.kms_key
                                )
                            },
                        },
                    },
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:PutObject",
                        "Resource": object_arn,
                        "Condition": {
                            "StringEquals": {
                                "s3:x-amz-server-side-encryption": "aws:kms"
                            },
                            "Null": {
                                "s3:x-amz-server-side-encryption-aws-kms-key-id": (
                                    "true"
                                )
                            },
                        },
                    },
                )
            )
            statements.extend(
                (
                    {
                        "Effect": "Allow",
                        "Principal": principal,
                        "Action": (
                            ["s3:GetObjectRetention", "s3:GetObjectVersion"]
                            if identity == "acceptance"
                            else [
                                "s3:GetObject",
                                "s3:GetObjectRetention",
                                "s3:GetObjectVersion",
                            ]
                        ),
                        "Resource": object_arn,
                    },
                    {
                        "Effect": "Allow",
                        "Principal": principal,
                        "Action": "s3:PutObject",
                        "Resource": object_arn,
                    },
                )
            )
            if identity != "acceptance":
                statements.append(
                    {
                        "Effect": "Allow",
                        "Principal": principal,
                        "Action": "s3:AbortMultipartUpload",
                        "Resource": object_arn,
                    }
                )
        for identity in ("backup", "snapshot"):
            audit_resource = (
                f"{bucket_arn}/{STORAGE_PREFIXES['backup']}*"
                if identity == "backup"
                else f"{bucket_arn}/{self.backup_sentinel}"
            )
            statements.append(
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": CONTROL_PLANE_CALLER_ARN},
                    "Action": [
                        "s3:GetObject",
                        "s3:GetObjectRetention",
                        "s3:GetObjectVersion",
                    ],
                    "Resource": audit_resource,
                }
            )
        statements.append(
            {
                "Effect": "Allow",
                "Principal": {"AWS": CONTROL_PLANE_CALLER_ARN},
                "Action": "s3:ListBucketVersions",
                "Resource": bucket_arn,
                "Condition": {
                    "StringLike": {
                        "s3:prefix": f"{STORAGE_PREFIXES['acceptance']}*"
                    }
                },
            }
        )
        if self.extra_bucket_allow:
            statements.append(
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:GetObject",
                    "Resource": f"{bucket_arn}/*",
                }
            )
        return {"Version": "2012-10-17", "Statement": statements}

    def get_bucket_policy(self, **_kwargs: object) -> dict[str, object]:
        self.calls.append("get_bucket_policy")
        return {"Policy": json.dumps(self.bucket_policy())}

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


def production_bucket_controls_digest(
    client: ProductionControlPlaneS3,
    *,
    versioning: Mapping[str, object] | None = None,
    ownership_controls: Mapping[str, object] | None = None,
    public_access_block: Mapping[str, object] | None = None,
    encryption: Mapping[str, object] | None = None,
    object_lock: Mapping[str, object] | None = None,
    lifecycle: Mapping[str, object] | None = None,
    kms_key_arn: str = FakeS3.kms_key,
) -> str:
    request = {
        "Bucket": "industrial-shadow-test",
        "ExpectedBucketOwner": AWS_ACCOUNT_ID,
    }
    location = client.get_bucket_location(**request)
    return s3_bucket_controls_digest(
        bucket="industrial-shadow-test",
        expected_bucket_owner=AWS_ACCOUNT_ID,
        region="us-east-1",
        kms_key_arn=kms_key_arn,
        lifecycle_prefixes=STORAGE_PREFIXES,
        location_constraint=location.get("LocationConstraint"),
        versioning=(
            versioning
            if versioning is not None
            else client.get_bucket_versioning(**request)
        ),
        ownership_controls=(
            ownership_controls
            if ownership_controls is not None
            else client.get_bucket_ownership_controls(**request)
        ),
        public_access_block=(
            public_access_block
            if public_access_block is not None
            else client.get_public_access_block(**request)
        ),
        encryption=(
            encryption
            if encryption is not None
            else client.get_bucket_encryption(**request)
        ),
        object_lock=(
            object_lock
            if object_lock is not None
            else client.get_object_lock_configuration(**request)
        ),
        lifecycle=(
            lifecycle
            if lifecycle is not None
            else client.get_bucket_lifecycle_configuration(**request)
        ),
    )


class ProductionKms:
    def __init__(
        self,
        *,
        grants: list[dict[str, object]] | None = None,
        extra_policy_allow: bool = False,
        admin_forbidden_action: str | None = None,
    ) -> None:
        self.grants = list(grants or [])
        self.extra_policy_allow = extra_policy_allow
        self.admin_forbidden_action = admin_forbidden_action

    @staticmethod
    def key_policy() -> dict[str, object]:
        statements: list[dict[str, object]] = [
            {
                "Effect": "Allow",
                "Principal": {"AWS": CONTROL_PLANE_CALLER_ARN},
                "Action": [
                    "kms:DescribeKey",
                    "kms:GetKeyPolicy",
                    "kms:GetKeyRotationStatus",
                    "kms:ListGrants",
                    "kms:ListKeyPolicies",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": KMS_ADMIN_ROLE_ARN},
                "Action": sorted(KMS_ADMIN_ACTIONS),
                "Resource": "*",
            },
        ]
        identity_arns = {"acceptance": CONTROL_PLANE_CALLER_ARN, **STORAGE_ROLE_ARNS}
        for identity in ("acceptance", "backup", "snapshot"):
            purpose = "probe" if identity == "acceptance" else identity
            statements.append(
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": identity_arns[identity]},
                    "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "kms:CallerAccount": AWS_ACCOUNT_ID,
                            "kms:EncryptionContext:application": "industrial-shadow",
                            "kms:EncryptionContext:purpose": purpose,
                            "kms:EncryptionContext:aws:s3:arn": (
                                "arn:aws:s3:::industrial-shadow-test"
                            ),
                            "kms:ViaService": "s3.us-east-1.amazonaws.com",
                        },
                    },
                }
            )
        for identity in ("backup", "snapshot"):
            statements.append(
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": CONTROL_PLANE_CALLER_ARN},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "kms:CallerAccount": AWS_ACCOUNT_ID,
                            "kms:EncryptionContext:application": "industrial-shadow",
                            "kms:EncryptionContext:purpose": identity,
                            "kms:EncryptionContext:aws:s3:arn": (
                                "arn:aws:s3:::industrial-shadow-test"
                            ),
                            "kms:ViaService": "s3.us-east-1.amazonaws.com",
                        },
                    },
                }
            )
        return {"Version": "2012-10-17", "Statement": statements}

    def describe_key(self, *, KeyId: str) -> dict[str, object]:
        return {
            "KeyMetadata": {
                "Arn": KeyId,
                "KeyState": "Enabled",
                "Enabled": True,
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeySpec": "SYMMETRIC_DEFAULT",
            }
        }

    def get_key_rotation_status(self, *, KeyId: str) -> dict[str, object]:
        if KeyId != FakeS3.kms_key:
            raise AssertionError("unexpected KMS key")
        return {"KeyRotationEnabled": True}

    def list_key_policies(self, *, KeyId: str, Limit: int) -> dict[str, object]:
        if KeyId != FakeS3.kms_key or Limit != 100:
            raise AssertionError("unexpected KMS policy inventory request")
        return {"PolicyNames": ["default"], "Truncated": False}

    def get_key_policy(self, *, KeyId: str, PolicyName: str) -> dict[str, object]:
        if KeyId != FakeS3.kms_key or PolicyName != "default":
            raise AssertionError("unexpected KMS key policy request")
        policy = self.key_policy()
        if self.admin_forbidden_action is not None:
            statements = policy["Statement"]
            if not isinstance(statements, list):
                raise AssertionError("test KMS statement fixture is invalid")
            admin_statement = next(
                item
                for item in statements
                if isinstance(item, dict)
                and item.get("Principal") == {"AWS": KMS_ADMIN_ROLE_ARN}
            )
            actions = admin_statement["Action"]
            if not isinstance(actions, list):
                raise AssertionError("test KMS admin actions are invalid")
            actions.append(self.admin_forbidden_action)
        if self.extra_policy_allow:
            statements = policy["Statement"]
            if not isinstance(statements, list):
                raise AssertionError("test KMS statement fixture is invalid")
            statements.append(
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": STORAGE_ROLE_ARNS["backup"]},
                    "Action": "kms:ScheduleKeyDeletion",
                    "Resource": "*",
                }
            )
        return {"Policy": json.dumps(policy)}

    def list_grants(self, *, KeyId: str, Limit: int) -> dict[str, object]:
        if KeyId != FakeS3.kms_key or Limit != 100:
            raise AssertionError("unexpected KMS grant inventory request")
        return {"Grants": self.grants, "Truncated": False}


class ProductionIam:
    def __init__(
        self,
        *,
        broad_role: str | None = None,
        oidc_client_ids: list[str] | None = None,
        admin_trust_drift: bool = False,
        broad_caller: bool = False,
        caller_trust_drift: str | None = None,
        storage_attached_roles: frozenset[str] | None = None,
        caller_extra_managed_policy_arn: bool = False,
    ) -> None:
        self.broad_role = broad_role
        self.oidc_client_ids = list(oidc_client_ids or ["sts.amazonaws.com"])
        self.admin_trust_drift = admin_trust_drift
        self.broad_caller = broad_caller
        self.caller_trust_drift = caller_trust_drift
        self.storage_attached_roles = storage_attached_roles or frozenset()
        if not self.storage_attached_roles.issubset({"backup", "snapshot"}):
            raise ValueError("storage attached role fixture is invalid")
        self.caller_extra_managed_policy_arn = caller_extra_managed_policy_arn

    @staticmethod
    def _managed_policy_arn(identity: str) -> str:
        if identity not in {"backup", "snapshot"}:
            raise AssertionError("unexpected IAM managed policy identity")
        return (
            f"arn:aws:iam::{AWS_ACCOUNT_ID}:policy/"
            f"industrial-shadow-{identity}-storage"
        )

    @staticmethod
    def _identity(role_name: str) -> str:
        identities = {
            "shadow-backup": "backup",
            "shadow-snapshot": "snapshot",
        }
        if role_name not in identities:
            raise AssertionError("unexpected IAM role")
        return identities[role_name]

    @classmethod
    def trust_policy(cls, role_name: str) -> dict[str, object]:
        identity = cls._identity(role_name)
        provider = IRSA_PROVIDER_ARN.split("oidc-provider/", 1)[1]
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": IRSA_PROVIDER_ARN},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            f"{provider}:aud": "sts.amazonaws.com",
                            f"{provider}:sub": TRUST_SUBJECTS[identity],
                        }
                    },
                }
            ],
        }

    def admin_trust_policy(self) -> dict[str, object]:
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": (
                        "*"
                        if self.admin_trust_drift
                        else {
                            "AWS": (
                                "arn:aws:iam::123456789012:"
                                "role/security-operations"
                            )
                        }
                    ),
                    "Action": "sts:AssumeRole",
                }
            ],
        }

    def caller_trust_policy(self) -> dict[str, object]:
        provider = "token.actions.githubusercontent.com"
        policy: dict[str, object] = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": CALLER_TRUST_CONTRACT["provider_arn"]
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            f"{provider}:aud": CALLER_TRUST_CONTRACT["audience"],
                            f"{provider}:sub": CALLER_TRUST_CONTRACT["subject"],
                            f"{provider}:repository": CALLER_TRUST_CONTRACT[
                                "repository"
                            ],
                            f"{provider}:repository_owner_id": CALLER_TRUST_CONTRACT[
                                "repository_owner_id"
                            ],
                            f"{provider}:repository_id": CALLER_TRUST_CONTRACT[
                                "repository_id"
                            ],
                            f"{provider}:ref": CALLER_TRUST_CONTRACT["ref"],
                            f"{provider}:environment": CALLER_TRUST_CONTRACT[
                                "environment"
                            ],
                            f"{provider}:workflow": CALLER_TRUST_CONTRACT["workflow"],
                        }
                    },
                }
            ],
        }
        statements = policy["Statement"]
        if not isinstance(statements, list) or not isinstance(statements[0], dict):
            raise TypeError("caller trust fixture is invalid")
        statement = statements[0]
        if self.caller_trust_drift == "extra_statement":
            extra = copy.deepcopy(statement)
            extra["Sid"] = "UnexpectedSecondTrustPath"
            statements.append(extra)
        elif self.caller_trust_drift == "wildcard_principal":
            statement["Principal"] = {"Federated": "*"}
        elif self.caller_trust_drift == "string_like":
            condition = statement.pop("Condition")
            if not isinstance(condition, dict):
                raise AssertionError("caller trust condition fixture is invalid")
            statement["Condition"] = {"StringLike": condition["StringEquals"]}
        elif self.caller_trust_drift == "missing_audience":
            condition = statement["Condition"]
            if not isinstance(condition, dict):
                raise AssertionError("caller trust condition fixture is invalid")
            values = condition["StringEquals"]
            if not isinstance(values, dict):
                raise AssertionError("caller trust values fixture is invalid")
            del values[f"{provider}:aud"]
        elif self.caller_trust_drift == "extra_condition":
            condition = statement["Condition"]
            if not isinstance(condition, dict):
                raise AssertionError("caller trust condition fixture is invalid")
            condition["Bool"] = {"aws:MultiFactorAuthPresent": "true"}
        return policy

    def caller_permissions_policy(self) -> dict[str, object]:
        bucket_arn = "arn:aws:s3:::industrial-shadow-test"
        acceptance_arn = f"{bucket_arn}/{STORAGE_PREFIXES['acceptance']}*"
        sentinel_arns = [
            f"{bucket_arn}/{ProductionControlPlaneS3.backup_sentinel}",
            f"{bucket_arn}/{ProductionControlPlaneS3.snapshot_sentinel}",
        ]
        role_arns = [
            CONTROL_PLANE_CALLER_ARN,
            KMS_ADMIN_ROLE_ARN,
            STORAGE_ROLE_ARNS["backup"],
            STORAGE_ROLE_ARNS["snapshot"],
        ]

        def kms_condition(identity: str) -> dict[str, object]:
            purpose = "probe" if identity == "acceptance" else identity
            return {
                "StringEquals": {
                    "kms:CallerAccount": AWS_ACCOUNT_ID,
                    "kms:EncryptionContext:application": "industrial-shadow",
                    "kms:EncryptionContext:purpose": purpose,
                    "kms:EncryptionContext:aws:s3:arn": bucket_arn,
                    "kms:ViaService": "s3.us-east-1.amazonaws.com",
                },
            }

        statements: list[dict[str, object]] = [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketLocation",
                    "s3:GetBucketObjectLockConfiguration",
                    "s3:GetBucketOwnershipControls",
                    "s3:GetBucketPolicy",
                    "s3:GetBucketPolicyStatus",
                    "s3:GetBucketPublicAccessBlock",
                    "s3:GetBucketVersioning",
                    "s3:GetEncryptionConfiguration",
                    "s3:GetLifecycleConfiguration",
                ],
                "Resource": bucket_arn,
            },
            {
                "Effect": "Allow",
                "Action": "s3:ListBucketVersions",
                "Resource": bucket_arn,
                "Condition": {
                    "StringLike": {"s3:prefix": f"{STORAGE_PREFIXES['acceptance']}*"}
                },
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObjectRetention",
                    "s3:GetObjectVersion",
                    "s3:PutObject",
                ],
                "Resource": acceptance_arn,
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:GetObjectRetention",
                    "s3:GetObjectVersion",
                ],
                "Resource": sentinel_arns,
            },
            {
                "Effect": "Allow",
                "Action": sorted(
                    {
                        "kms:DescribeKey",
                        "kms:GetKeyPolicy",
                        "kms:GetKeyRotationStatus",
                        "kms:ListGrants",
                        "kms:ListKeyPolicies",
                    }
                ),
                "Resource": FakeS3.kms_key,
            },
            {
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                "Resource": FakeS3.kms_key,
                "Condition": kms_condition("acceptance"),
            },
            *(
                {
                    "Effect": "Allow",
                    "Action": "kms:Decrypt",
                    "Resource": FakeS3.kms_key,
                    "Condition": kms_condition(identity),
                }
                for identity in ("backup", "snapshot")
            ),
            {
                "Effect": "Allow",
                "Action": "iam:GetRole",
                "Resource": role_arns,
            },
            {
                "Effect": "Allow",
                "Action": [
                    "iam:GetRolePolicy",
                    "iam:ListAttachedRolePolicies",
                    "iam:ListRolePolicies",
                ],
                "Resource": [
                    CONTROL_PLANE_CALLER_ARN,
                    STORAGE_ROLE_ARNS["backup"],
                    STORAGE_ROLE_ARNS["snapshot"],
                ],
            },
            {
                "Effect": "Allow",
                "Action": "iam:GetOpenIDConnectProvider",
                "Resource": IRSA_PROVIDER_ARN,
            },
        ]
        managed_policy_arns = {
            self._managed_policy_arn(identity)
            for identity in self.storage_attached_roles
        }
        if self.caller_extra_managed_policy_arn:
            managed_policy_arns.add(
                f"arn:aws:iam::{AWS_ACCOUNT_ID}:policy/unrelated-read"
            )
        if managed_policy_arns:
            statements.append(
                {
                    "Effect": "Allow",
                    "Action": ["iam:GetPolicy", "iam:GetPolicyVersion"],
                    "Resource": sorted(managed_policy_arns),
                }
            )
        if self.broad_caller:
            statements.append(
                {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}
            )
        return {"Version": "2012-10-17", "Statement": statements}

    def permissions_policy(self, role_name: str) -> dict[str, object]:
        identity = self._identity(role_name)
        object_arn = (
            f"arn:aws:s3:::industrial-shadow-test/{STORAGE_PREFIXES[identity]}*"
        )
        statements: list[dict[str, object]] = [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:GetObjectRetention",
                    "s3:GetObjectVersion",
                ],
                "Resource": object_arn,
            },
            {
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": object_arn,
            },
            {
                "Effect": "Allow",
                "Action": "s3:AbortMultipartUpload",
                "Resource": object_arn,
            },
            {
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                "Resource": FakeS3.kms_key,
                "Condition": {
                    "StringEquals": {
                        "kms:CallerAccount": AWS_ACCOUNT_ID,
                        "kms:EncryptionContext:application": "industrial-shadow",
                        "kms:EncryptionContext:purpose": identity,
                        "kms:EncryptionContext:aws:s3:arn": (
                            "arn:aws:s3:::industrial-shadow-test"
                        ),
                        "kms:ViaService": "s3.us-east-1.amazonaws.com",
                    }
                },
            },
        ]
        if self.broad_role == identity:
            statements.append(
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*",
                }
            )
        return {"Version": "2012-10-17", "Statement": statements}

    def get_open_id_connect_provider(
        self, *, OpenIDConnectProviderArn: str
    ) -> dict[str, object]:
        if OpenIDConnectProviderArn != IRSA_PROVIDER_ARN:
            raise AssertionError("unexpected IAM OIDC provider")
        return {
            "Url": IRSA_PROVIDER_ARN.split("oidc-provider/", 1)[1],
            "ClientIDList": self.oidc_client_ids,
            "ThumbprintList": ["1" * 40],
        }

    def get_role(self, *, RoleName: str) -> dict[str, object]:
        if RoleName == "acceptance":
            return {
                "Role": {
                    "Arn": CONTROL_PLANE_CALLER_ARN,
                    "AssumeRolePolicyDocument": self.caller_trust_policy(),
                }
            }
        if RoleName == "shadow-kms-admin":
            return {
                "Role": {
                    "Arn": KMS_ADMIN_ROLE_ARN,
                    "AssumeRolePolicyDocument": self.admin_trust_policy(),
                }
            }
        identity = self._identity(RoleName)
        return {
            "Role": {
                "Arn": STORAGE_ROLE_ARNS[identity],
                "AssumeRolePolicyDocument": self.trust_policy(RoleName),
            }
        }

    def list_role_policies(self, *, RoleName: str, MaxItems: int) -> dict[str, object]:
        if MaxItems != 100:
            raise AssertionError("unexpected IAM inline policy bound")
        if RoleName == "acceptance":
            return {"PolicyNames": ["caller-access"], "IsTruncated": False}
        identity = self._identity(RoleName)
        if identity in self.storage_attached_roles:
            return {"PolicyNames": [], "IsTruncated": False}
        return {"PolicyNames": ["storage-access"], "IsTruncated": False}

    def list_attached_role_policies(
        self, *, RoleName: str, MaxItems: int
    ) -> dict[str, object]:
        if MaxItems != 100:
            raise AssertionError("unexpected IAM attached policy bound")
        if RoleName == "acceptance":
            return {"AttachedPolicies": [], "IsTruncated": False}
        identity = self._identity(RoleName)
        if identity in self.storage_attached_roles:
            policy_arn = self._managed_policy_arn(identity)
            return {
                "AttachedPolicies": [
                    {
                        "PolicyName": policy_arn.rsplit("/", 1)[-1],
                        "PolicyArn": policy_arn,
                    }
                ],
                "IsTruncated": False,
            }
        return {"AttachedPolicies": [], "IsTruncated": False}

    def get_role_policy(self, *, RoleName: str, PolicyName: str) -> dict[str, object]:
        if RoleName == "acceptance" and PolicyName == "caller-access":
            return {"PolicyDocument": self.caller_permissions_policy()}
        if PolicyName != "storage-access":
            raise AssertionError("unexpected IAM inline policy")
        return {"PolicyDocument": self.permissions_policy(RoleName)}

    def get_policy(self, *, PolicyArn: str) -> dict[str, object]:
        identities = {
            self._managed_policy_arn(identity): identity
            for identity in self.storage_attached_roles
        }
        if PolicyArn not in identities:
            raise AssertionError("unexpected IAM managed policy")
        return {
            "Policy": {
                "Arn": PolicyArn,
                "PolicyName": PolicyArn.rsplit("/", 1)[-1],
                "DefaultVersionId": "v1",
            }
        }

    def get_policy_version(
        self, *, PolicyArn: str, VersionId: str
    ) -> dict[str, object]:
        identities = {
            self._managed_policy_arn(identity): identity
            for identity in self.storage_attached_roles
        }
        if PolicyArn not in identities or VersionId != "v1":
            raise AssertionError("unexpected IAM managed policy version")
        return {
            "PolicyVersion": {
                "VersionId": "v1",
                "IsDefaultVersion": True,
                "Document": self.permissions_policy(
                    f"shadow-{identities[PolicyArn]}"
                ),
            }
        }


class ProductionSts:
    def __init__(
        self,
        caller_arn: str = "arn:aws:sts::123456789012:assumed-role/acceptance/control",
    ) -> None:
        self.caller_arn = caller_arn

    def get_caller_identity(self) -> dict[str, str]:
        return {
            "Account": "123456789012",
            "Arn": self.caller_arn,
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
        self.retention_requests: list[tuple[str, str]] = []

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

    def get_version_retention(self, key: str, *, version_id: str) -> ObjectRetention:
        if (key, version_id) not in self.objects:
            raise AssertionError("retention must bind a fetched exact version")
        self.retention_requests.append((key, version_id))
        return ObjectRetention(
            "COMPLIANCE",
            (dt.datetime.now(dt.UTC) + dt.timedelta(days=30)).isoformat(),
        )


class AwsStoragePolicyContractTests(unittest.TestCase):
    @staticmethod
    def _statements(policy: dict[str, object]) -> list[dict[str, object]]:
        values = policy.get("Statement")
        if not isinstance(values, list):
            raise TypeError("test policy statements must be a list")
        statements: list[dict[str, object]] = []
        for value in values:
            if not isinstance(value, dict) or any(
                not isinstance(key, str) for key in value
            ):
                raise AssertionError("test policy statement is invalid")
            statements.append({key: value[key] for key in value})
        return statements

    @staticmethod
    def _statement(
        policy: dict[str, object], *, action: str, effect: str = "Allow"
    ) -> dict[str, object]:
        values = policy.get("Statement")
        if not isinstance(values, list):
            raise TypeError("test policy statements must be a list")
        matches = [
            (index, value)
            for index, value in enumerate(values)
            if isinstance(value, dict)
            and value.get("Effect") == effect
            and value.get("Action") == action
        ]
        if len(matches) != 1:
            raise AssertionError("test policy action must identify one statement")
        index, value = matches[0]
        if any(not isinstance(key, str) for key in value):
            raise AssertionError("test policy statement keys are invalid")
        statement = {key: value[key] for key in value}
        values[index] = statement
        return statement

    @staticmethod
    def _role_policy_is_exact(policy: dict[str, object]) -> bool:
        return iam_role_permissions_are_least_privilege(
            (policy,),
            bucket="industrial-shadow-test",
            prefix=STORAGE_PREFIXES["backup"],
            kms_key_arn=FakeS3.kms_key,
            purpose="backup",
            region="us-east-1",
            account_id=AWS_ACCOUNT_ID,
        )

    @staticmethod
    def _bucket_policy_is_exact(policy: dict[str, object]) -> bool:
        return bucket_policy_is_workload_bound(
            policy,
            bucket="industrial-shadow-test",
            control_plane_caller_arn=CONTROL_PLANE_CALLER_ARN,
            role_arns=STORAGE_ROLE_ARNS,
            prefixes=STORAGE_PREFIXES,
            sentinel_keys={
                "backup": ProductionControlPlaneS3.backup_sentinel,
                "snapshot": ProductionControlPlaneS3.snapshot_sentinel,
            },
            kms_key_arn=FakeS3.kms_key,
        )

    @staticmethod
    def _caller_policy_is_exact(policy: dict[str, object]) -> bool:
        return iam_control_plane_caller_permissions_are_least_privilege(
            (policy,),
            bucket="industrial-shadow-test",
            prefixes=STORAGE_PREFIXES,
            sentinel_keys={
                "backup": ProductionControlPlaneS3.backup_sentinel,
                "snapshot": ProductionControlPlaneS3.snapshot_sentinel,
            },
            kms_key_arn=FakeS3.kms_key,
            caller_role_arn=CONTROL_PLANE_CALLER_ARN,
            kms_admin_role_arn=KMS_ADMIN_ROLE_ARN,
            storage_role_arns=STORAGE_ROLE_ARNS,
            oidc_provider_arn=IRSA_PROVIDER_ARN,
            attached_policy_arns=frozenset(),
            region="us-east-1",
            account_id=AWS_ACCOUNT_ID,
        )

    def test_exact_multipart_workload_role_policy_and_digest(self) -> None:
        policy = ProductionIam().permissions_policy("shadow-backup")
        statements = self._statements(policy)
        self.assertEqual(4, len(statements))
        self.assertTrue(self._role_policy_is_exact(policy))
        for action in ("s3:PutObject", "s3:AbortMultipartUpload"):
            statement = self._statement(policy, action=action)
            self.assertEqual({"Effect", "Action", "Resource"}, set(statement))
            self.assertEqual(
                "arn:aws:s3:::industrial-shadow-test/backup/signatures/*",
                statement["Resource"],
            )

        _trust_digest, permissions_digest, _provider, trust_exact, permissions_exact = (
            inspect_iam_storage_role(
                ProductionIam(),
                role_arn=STORAGE_ROLE_ARNS["backup"],
                expected_provider_arn=IRSA_PROVIDER_ARN,
                expected_subject=TRUST_SUBJECTS["backup"],
                bucket="industrial-shadow-test",
                prefix=STORAGE_PREFIXES["backup"],
                kms_key_arn=FakeS3.kms_key,
                purpose="backup",
                region="us-east-1",
                account_id=AWS_ACCOUNT_ID,
            )
        )
        self.assertTrue(trust_exact)
        self.assertTrue(permissions_exact)
        self.assertEqual(
            canonical_digest(
                {
                    "schema_version": 1,
                    "role_arn": STORAGE_ROLE_ARNS["backup"],
                    "permissions_boundary": None,
                    "inline_policies": [
                        {
                            "name": "storage-access",
                            "document": normalize_aws_policy(policy),
                        }
                    ],
                    "attached_policies": [],
                }
            ),
            permissions_digest,
        )

    def test_multipart_workload_role_policy_rejects_exact_contract_drift(self) -> None:
        exact = ProductionIam().permissions_policy("shadow-backup")
        missing_abort = copy.deepcopy(exact)
        values = missing_abort.get("Statement")
        if not isinstance(values, list):
            raise TypeError("test policy statements must be a list")
        missing_abort["Statement"] = [
            value
            for value in values
            if not (
                isinstance(value, dict)
                and value.get("Action") == "s3:AbortMultipartUpload"
            )
        ]

        extra_action = copy.deepcopy(exact)
        self._statement(extra_action, action="s3:PutObject")["Action"] = [
            "s3:PutObject",
            "s3:DeleteObject",
        ]

        wrong_prefix = copy.deepcopy(exact)
        self._statement(wrong_prefix, action="s3:AbortMultipartUpload")["Resource"] = (
            "arn:aws:s3:::industrial-shadow-test/backup/*"
        )

        legacy_sse_condition = copy.deepcopy(exact)
        self._statement(legacy_sse_condition, action="s3:PutObject")["Condition"] = {
            "StringEquals": {
                "s3:x-amz-server-side-encryption": "aws:kms",
                "s3:x-amz-server-side-encryption-aws-kms-key-id": FakeS3.kms_key,
            }
        }

        exact_digest = aws_policy_digest(exact)
        for name, policy in (
            ("missing_abort", missing_abort),
            ("extra_action", extra_action),
            ("wrong_prefix", wrong_prefix),
            ("legacy_sse_condition", legacy_sse_condition),
        ):
            with self.subTest(name=name):
                self.assertFalse(self._role_policy_is_exact(policy))
                self.assertNotEqual(exact_digest, aws_policy_digest(policy))

    def test_exact_bucket_policy_has_multipart_allows_and_header_guards(self) -> None:
        policy = ProductionControlPlaneS3().bucket_policy()
        statements = self._statements(policy)
        self.assertEqual(23, len(statements))
        self.assertTrue(self._bucket_policy_is_exact(policy))
        header_denies = [
            statement
            for statement in statements
            if statement.get("Effect") == "Deny"
            and statement.get("Action") == "s3:PutObject"
        ]
        self.assertEqual(9, len(header_denies))
        for action, expected_count in (
            ("s3:PutObject", 3),
            ("s3:AbortMultipartUpload", 2),
        ):
            allows = [
                statement
                for statement in statements
                if statement.get("Effect") == "Allow"
                and statement.get("Action") == action
            ]
            self.assertEqual(expected_count, len(allows))
            self.assertTrue(all("Condition" not in statement for statement in allows))

    def test_control_plane_caller_rejects_unused_object_mutations_and_reads(self) -> None:
        exact = ProductionIam().caller_permissions_policy()
        self.assertTrue(self._caller_policy_is_exact(exact))
        for extra_action in (
            "s3:AbortMultipartUpload",
            "s3:DeleteObject",
            "s3:DeleteObjectVersion",
            "s3:GetObject",
        ):
            drifted = copy.deepcopy(exact)
            actions: list[object] | None = None
            for statement in self._statements(drifted):
                candidate_actions = statement.get("Action")
                if (
                    statement.get("Resource")
                    == "arn:aws:s3:::industrial-shadow-test/acceptance/production-probes/*"
                    and isinstance(candidate_actions, list)
                    and "s3:PutObject" in candidate_actions
                ):
                    actions = candidate_actions
                    break
            if not isinstance(actions, list):
                raise TypeError("caller object actions must be a list")
            actions.append(extra_action)
            self.assertFalse(self._caller_policy_is_exact(drifted), extra_action)

    def test_caller_managed_policy_reads_match_storage_role_attached_union(self) -> None:
        attached_roles = frozenset({"backup", "snapshot"})
        exact_iam = ProductionIam(storage_attached_roles=attached_roles)
        fragment = collect_aws_storage_policy_digests(
            s3_client=ProductionControlPlaneS3(),
            kms_client=ProductionKms(),
            iam_client=exact_iam,
            sts_client=ProductionSts(),
            bucket="industrial-shadow-test",
            region="us-east-1",
            account_id=AWS_ACCOUNT_ID,
            kms_key_arn=FakeS3.kms_key,
            control_plane_caller_arn=CONTROL_PLANE_CALLER_ARN,
            kms_admin_role_arn=KMS_ADMIN_ROLE_ARN,
            oidc_provider_arn=IRSA_PROVIDER_ARN,
            role_arns=STORAGE_ROLE_ARNS,
            trust_subjects=TRUST_SUBJECTS,
            prefixes=STORAGE_PREFIXES,
            sentinel_keys={
                "backup": ProductionControlPlaneS3.backup_sentinel,
                "snapshot": ProductionControlPlaneS3.snapshot_sentinel,
            },
            caller_trust_repository="industrial-shadow/industry-shadow",
            caller_trust_repository_owner_id="214596190",
            caller_trust_repository_id="24681012",
            caller_trust_ref="refs/heads/main",
            caller_trust_environment="production-acceptance",
            caller_trust_workflow="production-acceptance",
        )
        self.assertEqual(
            AWS_STORAGE_POLICY_DIGEST_FIELDS,
            {
                name
                for name in fragment
                if name in AWS_STORAGE_POLICY_DIGEST_FIELDS
            },
        )

        drifted_iam = ProductionIam(
            storage_attached_roles=attached_roles,
            caller_extra_managed_policy_arn=True,
        )
        _trust, _permissions, trust_exact, permissions_exact = (
            inspect_iam_control_plane_caller_role(
                drifted_iam,
                role_arn=CONTROL_PLANE_CALLER_ARN,
                kms_admin_role_arn=KMS_ADMIN_ROLE_ARN,
                storage_role_arns=STORAGE_ROLE_ARNS,
                oidc_provider_arn=IRSA_PROVIDER_ARN,
                bucket="industrial-shadow-test",
                prefixes=STORAGE_PREFIXES,
                sentinel_keys={
                    "backup": ProductionControlPlaneS3.backup_sentinel,
                    "snapshot": ProductionControlPlaneS3.snapshot_sentinel,
                },
                kms_key_arn=FakeS3.kms_key,
                region="us-east-1",
                account_id=AWS_ACCOUNT_ID,
                trust_contract=CALLER_TRUST_CONTRACT,
            )
        )
        self.assertTrue(trust_exact)
        self.assertFalse(permissions_exact)

    def test_bucket_policy_limits_snapshot_audit_to_the_exact_sentinel(self) -> None:
        exact = ProductionControlPlaneS3().bucket_policy()
        self.assertTrue(self._bucket_policy_is_exact(exact))
        broad = copy.deepcopy(exact)
        values = broad.get("Statement")
        if not isinstance(values, list):
            raise TypeError("bucket policy statements must be a list")
        statement = next(
            value
            for value in values
            if isinstance(value, dict)
            and value.get("Principal") == {"AWS": CONTROL_PLANE_CALLER_ARN}
            and value.get("Resource")
            == (
                "arn:aws:s3:::industrial-shadow-test/"
                f"{ProductionControlPlaneS3.backup_sentinel}"
            )
        )
        statement["Resource"] = (
            "arn:aws:s3:::industrial-shadow-test/snapshot/signatures/*"
        )
        self.assertFalse(self._bucket_policy_is_exact(broad))

    def test_bucket_policy_rejects_missing_header_guard_or_extra_allow(self) -> None:
        exact = ProductionControlPlaneS3().bucket_policy()
        missing_guard = copy.deepcopy(exact)
        values = missing_guard.get("Statement")
        if not isinstance(values, list):
            raise TypeError("test policy statements must be a list")
        removed = False
        kept: list[object] = []
        for value in values:
            is_header_deny = (
                isinstance(value, dict)
                and value.get("Effect") == "Deny"
                and value.get("Action") == "s3:PutObject"
            )
            if is_header_deny and not removed:
                removed = True
                continue
            kept.append(value)
        if not removed:
            raise AssertionError("test bucket policy has no header guard")
        missing_guard["Statement"] = kept

        extra_allow = copy.deepcopy(exact)
        extra_values = extra_allow.get("Statement")
        if not isinstance(extra_values, list):
            raise TypeError("test policy statements must be a list")
        extra_values.append(
            {
                "Effect": "Allow",
                "Principal": {"AWS": STORAGE_ROLE_ARNS["backup"]},
                "Action": "s3:GetObjectTagging",
                "Resource": "arn:aws:s3:::industrial-shadow-test/backup/signatures/*",
            }
        )

        exact_digest = aws_policy_digest(exact)
        for name, policy in (
            ("missing_header_guard", missing_guard),
            ("extra_allow", extra_allow),
        ):
            with self.subTest(name=name):
                self.assertFalse(self._bucket_policy_is_exact(policy))
                self.assertNotEqual(exact_digest, aws_policy_digest(policy))

    def test_bucket_control_digest_is_order_stable_and_signs_mfa_delete(self) -> None:
        exact_client = ProductionControlPlaneS3()
        exact_digest = production_bucket_controls_digest(exact_client)
        self.assertEqual(
            [
                "get_bucket_location",
                "get_bucket_versioning",
                "get_bucket_ownership_controls",
                "get_public_access_block",
                "get_bucket_encryption",
                "get_object_lock_configuration",
                "get_bucket_lifecycle_configuration",
            ],
            exact_client.calls,
        )

        lifecycle = ProductionControlPlaneS3().get_bucket_lifecycle_configuration()
        rules = lifecycle.get("Rules")
        if not isinstance(rules, list):
            raise TypeError("test lifecycle rules must be a list")
        reordered = {"Rules": list(reversed(rules))}
        self.assertEqual(
            exact_digest,
            production_bucket_controls_digest(
                ProductionControlPlaneS3(), lifecycle=reordered
            ),
        )
        self.assertEqual(
            exact_digest,
            production_bucket_controls_digest(
                ProductionControlPlaneS3(),
                versioning={"Status": "Enabled", "MFADelete": "NotConfigured"},
            ),
        )
        self.assertNotEqual(
            exact_digest,
            production_bucket_controls_digest(
                ProductionControlPlaneS3(),
                versioning={"Status": "Enabled", "MFADelete": "Enabled"},
            ),
        )

    def test_bucket_control_digest_rejects_incomplete_or_drifted_controls(self) -> None:
        lifecycle = ProductionControlPlaneS3().get_bucket_lifecycle_configuration()
        values = lifecycle.get("Rules")
        if not isinstance(values, list) or any(
            not isinstance(value, dict) for value in values
        ):
            raise TypeError("test lifecycle rules must be object values")
        missing_rule = {"Rules": values[:-1]}
        extra_rule = {
            "Rules": [
                *values,
                {
                    "ID": "unexpected",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "unexpected/"},
                    "Expiration": {"Days": 30},
                    "NoncurrentVersionExpiration": {"NoncurrentDays": 30},
                    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
                },
            ]
        }
        missing_abort = {
            "Rules": [
                {
                    key: value[key]
                    for key in value
                    if key != "AbortIncompleteMultipartUpload"
                }
                for value in values
            ]
        }
        invalid_abort = {
            "Rules": [
                {
                    **value,
                    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 0},
                }
                for value in values
            ]
        }
        wrong_kms = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": (
                                "arn:aws:kms:us-east-1:123456789012:key/wrong-key"
                            ),
                        },
                        "BucketKeyEnabled": True,
                    }
                ]
            }
        }
        object_lock_disabled = {
            "ObjectLockConfiguration": {
                "ObjectLockEnabled": "Disabled",
                "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 30}},
            }
        }
        wrong_ownership = {
            "OwnershipControls": {
                "Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]
            }
        }
        cases: tuple[tuple[str, Callable[[], str]], ...] = (
            (
                "missing_lifecycle_rule",
                lambda: production_bucket_controls_digest(
                    ProductionControlPlaneS3(), lifecycle=missing_rule
                ),
            ),
            (
                "extra_lifecycle_rule",
                lambda: production_bucket_controls_digest(
                    ProductionControlPlaneS3(), lifecycle=extra_rule
                ),
            ),
            (
                "missing_multipart_abort",
                lambda: production_bucket_controls_digest(
                    ProductionControlPlaneS3(), lifecycle=missing_abort
                ),
            ),
            (
                "invalid_multipart_abort",
                lambda: production_bucket_controls_digest(
                    ProductionControlPlaneS3(), lifecycle=invalid_abort
                ),
            ),
            (
                "wrong_kms_key",
                lambda: production_bucket_controls_digest(
                    ProductionControlPlaneS3(), encryption=wrong_kms
                ),
            ),
            (
                "object_lock_disabled",
                lambda: production_bucket_controls_digest(
                    ProductionControlPlaneS3(), object_lock=object_lock_disabled
                ),
            ),
            (
                "wrong_object_ownership",
                lambda: production_bucket_controls_digest(
                    ProductionControlPlaneS3(), ownership_controls=wrong_ownership
                ),
            ),
            (
                "invalid_mfa_delete",
                lambda: production_bucket_controls_digest(
                    ProductionControlPlaneS3(),
                    versioning={"Status": "Enabled", "MFADelete": "Pending"},
                ),
            ),
        )
        for name, invoke in cases:
            with self.subTest(name=name), self.assertRaises(DomainError) as rejected:
                invoke()
            self.assertEqual("S3_BUCKET_CONTROLS_INVALID", rejected.exception.code)


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
            sessions: ClassVar[list[dict[str, object]]] = []

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

    def test_multipart_upload_scopes_sse_headers_and_verifies_readback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "multipart-source.bin"
            destination = root / "multipart-download.bin"
            source.write_bytes(b"multipart-payload")
            client = MultipartS3()
            storage = S3ObjectStorage(
                "industrial-shadow-test",
                region="us-east-1",
                prefix="backup/signatures",
                kms_key_id=client.kms_key,
                client=client,
            )
            with (
                patch(
                    "shadow_sandbox.common.object_storage.SINGLE_PUT_MAX_BYTES",
                    8,
                ),
                patch(
                    "shadow_sandbox.common.object_storage.MULTIPART_PART_BYTES",
                    5,
                ),
            ):
                reference = storage.put_file(
                    "archive.dump",
                    source,
                    content_type="application/octet-stream",
                )
            operations = [name for name, _request in client.calls]
            self.assertEqual(
                [
                    "create_multipart_upload",
                    "upload_part",
                    "upload_part",
                    "upload_part",
                    "upload_part",
                    "complete_multipart_upload",
                ],
                operations,
            )
            initiation = client.calls[0][1]
            self.assertEqual("aws:kms", initiation["ServerSideEncryption"])
            self.assertEqual(client.kms_key, initiation["SSEKMSKeyId"])
            self.assertIs(True, initiation["BucketKeyEnabled"])
            encryption_keys = {
                "ServerSideEncryption",
                "SSEKMSKeyId",
                "SSEKMSEncryptionContext",
                "BucketKeyEnabled",
            }
            for operation, request in client.calls[1:]:
                with self.subTest(operation=operation):
                    self.assertTrue(encryption_keys.isdisjoint(request))

            downloaded = storage.get_file(
                "archive.dump",
                destination,
                maximum_bytes=1024,
                expected_sha256=reference.sha256,
                version_id=reference.version_id,
            )
            self.assertEqual(source.read_bytes(), destination.read_bytes())
            self.assertEqual(reference.sha256, downloaded.sha256)
            self.assertEqual("aws:kms", downloaded.encryption)

    def test_failed_multipart_upload_uses_unconditioned_abort_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "multipart-source.bin"
            source.write_bytes(b"multipart-payload")
            client = MultipartS3(fail_part_number=2)
            storage = S3ObjectStorage(
                "industrial-shadow-test",
                region="us-east-1",
                prefix="backup/signatures",
                kms_key_id=client.kms_key,
                client=client,
            )
            with (
                patch(
                    "shadow_sandbox.common.object_storage.SINGLE_PUT_MAX_BYTES",
                    8,
                ),
                patch(
                    "shadow_sandbox.common.object_storage.MULTIPART_PART_BYTES",
                    5,
                ),
                self.assertRaises(DomainError) as rejected,
            ):
                storage.put_file(
                    "archive.dump",
                    source,
                    content_type="application/octet-stream",
                )
            self.assertEqual("OBJECT_STORAGE_UNAVAILABLE", rejected.exception.code)
            aborts = [
                request
                for operation, request in client.calls
                if operation == "abort_multipart_upload"
            ]
            self.assertEqual(1, len(aborts))
            self.assertTrue(
                {
                    "ServerSideEncryption",
                    "SSEKMSKeyId",
                    "SSEKMSEncryptionContext",
                    "BucketKeyEnabled",
                }.isdisjoint(aborts[0])
            )

    def test_backup_job_uses_streaming_file_upload(self) -> None:
        storage = RecordingStorage()
        commands: list[list[str]] = []

        def run(
            command: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            commands.append(command)
            if command[0] == "pg_dump":
                output = Path(command[command.index("--file") + 1])
                output.write_bytes(b"postgres-custom-dump" * 1024)
            return subprocess.CompletedProcess(command, 0)

        environment = {
            "SHADOW_ENVIRONMENT": "test",
            "SHADOW_DATABASE_URL": "postgresql://backup@127.0.0.1/shadow?sslmode=disable",
            "SHADOW_OBJECT_STORAGE_BACKEND": "local",
            "SHADOW_DATABASE_BACKUP_ROLE": "shadow_backup",
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
            patch(
                "shadow_sandbox.operations.backup_job.PostgreSqlBackupSnapshot",
                FakeBackupSnapshot,
            ),
            patch(
                "shadow_sandbox.operations.backup_job._capture_snapshot_fingerprint",
                return_value=({}, ()),
            ),
            patch(
                "shadow_sandbox.operations.backup_job._finalize_snapshot_fingerprint",
                return_value=backup_snapshot_fixture(),
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
        self.assertTrue(storage.bytes[1].endswith(".receipt.json"))
        pg_dump = next(command for command in commands if command[0] == "pg_dump")
        self.assertEqual(
            "00000003-0000001B-1", pg_dump[pg_dump.index("--snapshot") + 1]
        )

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
        backup_snapshot = backup_snapshot_fixture()
        manifest: dict[str, object] = {
            "schema_version": 3,
            "created_at": created_at,
            "source_database_digest": source_digest,
            "archive": archive_descriptor,
            "kms_key_id_digest": canonical_digest({"kms_key_id": kms_key}),
            "kms_key_partition": "aws",
            "format": "postgresql-custom",
            "verified_by": "pg_restore --list + exported snapshot fingerprints",
            "backup_snapshot": backup_snapshot,
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
        sealed_receipt: dict[str, object] = {
            "schema_version": 1,
            "created_at": created_at,
            "source_database_digest": source_digest,
            "archive": archive_descriptor,
            "manifest": manifest_descriptor,
            "manifest_digest": manifest["manifest_digest"],
            "backup_snapshot_digest": backup_snapshot["snapshot_digest"],
            "kms_key_partition": "aws",
        }
        sealed_receipt["sealed_receipt_digest"] = canonical_digest(sealed_receipt)
        sealed_receipt_bytes = canonical_json(sealed_receipt).encode()
        sealed_receipt_descriptor = {
            "key": archive_descriptor["key"] + ".receipt.json",
            "size": len(sealed_receipt_bytes),
            "sha256": hashlib.sha256(sealed_receipt_bytes).hexdigest(),
            "version_id": "receipt-v4",
            "encryption": "aws:kms",
        }
        receipt: dict[str, object] = {
            "schema_version": 2,
            "created_at": created_at,
            "source_database_digest": source_digest,
            "archive": archive_descriptor,
            "manifest": manifest_descriptor,
            "manifest_digest": manifest["manifest_digest"],
            "backup_snapshot_digest": backup_snapshot["snapshot_digest"],
            "kms_key_partition": "aws",
            "sealed_receipt": sealed_receipt_descriptor,
            "sealed_receipt_digest": sealed_receipt["sealed_receipt_digest"],
        }
        receipt["receipt_digest"] = canonical_digest(receipt)
        storage = ImmutableRestoreStorage(
            {
                (str(archive_descriptor["key"]), "archive-v7"): (archive, "aws:kms"),
                (str(sealed_receipt_descriptor["key"]), "receipt-v4"): (
                    sealed_receipt_bytes,
                    "aws:kms",
                ),
                (str(manifest_descriptor["key"]), "manifest-v9"): (
                    manifest_bytes,
                    "aws:kms",
                ),
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "receipt.json"
            receipt_path.write_text(canonical_json(receipt), encoding="utf-8")
            receipt_path.chmod(0o600)
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
            (
                restored,
                manifest_ref,
                archive_ref,
                receipt_ref,
                snapshot,
                retentions,
                _seconds,
            ) = (
                drill._fetch_immutable_backup(
                    Path(directory),
                    receipt=parsed,
                    kms_key_digest=canonical_digest({"kms_key_id": kms_key}),
                    kms_key_partition="aws",
                )
            )
            self.assertEqual(archive, restored.read_bytes())
            self.assertEqual("manifest-v9", manifest_ref.version_id)
            self.assertEqual("archive-v7", archive_ref.version_id)
            self.assertEqual("receipt-v4", receipt_ref.version_id)
            self.assertEqual(
                backup_snapshot["snapshot_digest"], snapshot.snapshot_digest
            )
            self.assertTrue(retentions.sealed_receipt.active())
            self.assertTrue(retentions.manifest.active())
            self.assertTrue(retentions.archive.active())
            self.assertEqual(
                [
                    (str(sealed_receipt_descriptor["key"]), "receipt-v4"),
                    (str(manifest_descriptor["key"]), "manifest-v9"),
                    (str(archive_descriptor["key"]), "archive-v7"),
                ],
                storage.requests,
            )
            self.assertEqual(storage.requests, storage.retention_requests)

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
            "SHADOW_OBJECT_STORAGE_REGION": "us-east-1",
            "SHADOW_AWS_ACCOUNT_ID": "123456789012",
            "SHADOW_DATABASE_BACKUP_ROLE": "shadow_backup",
            "SHADOW_BACKUP_OBJECT_STORAGE_PREFIX": "industrial-shadow/backups",
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
            patch(
                "shadow_sandbox.operations.backup_job.PostgreSqlBackupSnapshot",
                FakeBackupSnapshot,
            ),
            patch(
                "shadow_sandbox.operations.backup_job._capture_snapshot_fingerprint",
                return_value=({}, ()),
            ),
            patch(
                "shadow_sandbox.operations.backup_job._finalize_snapshot_fingerprint",
                return_value=backup_snapshot_fixture(),
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

    def test_github_caller_trust_uses_partition_exact_audience(self) -> None:
        contract = github_actions_caller_trust_contract(
            account_id=AWS_ACCOUNT_ID,
            region="cn-north-1",
            repository="industrial-shadow/industry-shadow",
            repository_owner_id="214596190",
            repository_id="24681012",
            ref="refs/heads/main",
            environment="production-acceptance",
            workflow="production-acceptance",
        )
        provider = "token.actions.githubusercontent.com"
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": contract["provider_arn"]},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            f"{provider}:{name}": contract[name]
                            for name in (
                                "audience",
                                "subject",
                                "repository",
                                "repository_owner_id",
                                "repository_id",
                                "ref",
                                "environment",
                                "workflow",
                            )
                        }
                    },
                }
            ],
        }
        condition = policy["Statement"][0]["Condition"]["StringEquals"]
        condition[f"{provider}:aud"] = condition.pop(f"{provider}:audience")
        condition[f"{provider}:sub"] = condition.pop(f"{provider}:subject")
        self.assertEqual("sts.amazonaws.com.cn", contract["audience"])
        self.assertTrue(
            github_actions_caller_trust_is_exact(
                policy,
                role_arn="arn:aws-cn:iam::123456789012:role/acceptance",
                contract=contract,
            )
        )
        condition[f"{provider}:aud"] = "sts.amazonaws.com"
        self.assertFalse(
            github_actions_caller_trust_is_exact(
                policy,
                role_arn="arn:aws-cn:iam::123456789012:role/acceptance",
                contract=contract,
            )
        )

    @classmethod
    def _confirmation(cls) -> str:
        return s3_control_plane_mutation_confirmation(
            bucket="industrial-shadow-test",
            prefix="acceptance",
            acceptance_run_id=cls.run_id,
            signed_target_profile_digest=cls.target_profile_digest,
        )

    @classmethod
    def _policy_digests(cls) -> dict[str, str]:
        kms = ProductionKms()
        iam = ProductionIam()
        _policy, kms_policy_digest, kms_grants_digest, _grants_absent = (
            inspect_kms_policy_and_grants(kms, kms_key_arn=FakeS3.kms_key)
        )
        oidc_configuration_digest, oidc_exact = inspect_iam_oidc_provider(
            iam,
            provider_arn=IRSA_PROVIDER_ARN,
        )
        if not oidc_exact:
            raise AssertionError("test IAM OIDC provider fixture is not exact")
        (
            caller_trust_digest,
            caller_permissions_digest,
            caller_trust_exact,
            caller_permissions_exact,
        ) = (
            inspect_iam_control_plane_caller_role(
                iam,
                role_arn=CONTROL_PLANE_CALLER_ARN,
                kms_admin_role_arn=KMS_ADMIN_ROLE_ARN,
                storage_role_arns=STORAGE_ROLE_ARNS,
                oidc_provider_arn=IRSA_PROVIDER_ARN,
                bucket="industrial-shadow-test",
                prefixes=STORAGE_PREFIXES,
                sentinel_keys={
                    "backup": ProductionControlPlaneS3.backup_sentinel,
                    "snapshot": ProductionControlPlaneS3.snapshot_sentinel,
                },
                kms_key_arn=FakeS3.kms_key,
                region="us-east-1",
                account_id=AWS_ACCOUNT_ID,
                trust_contract=CALLER_TRUST_CONTRACT,
            )
        )
        if not caller_trust_exact or not caller_permissions_exact:
            raise AssertionError("test caller IAM permissions fixture is not exact")
        digests = {
            "aws_irsa_oidc_provider_arn_digest": canonical_digest(
                {"provider_arn": IRSA_PROVIDER_ARN}
            ),
            "aws_irsa_oidc_provider_configuration_digest": (
                oidc_configuration_digest
            ),
            "s3_control_plane_caller_arn_digest": canonical_digest(
                {"caller_arn": CONTROL_PLANE_CALLER_ARN}
            ),
            "s3_control_plane_caller_trust_contract_digest": canonical_digest(
                CALLER_TRUST_CONTRACT
            ),
            "s3_control_plane_caller_iam_role_trust_policy_digest": (
                caller_trust_digest
            ),
            "s3_control_plane_caller_iam_role_permissions_digest": (
                caller_permissions_digest
            ),
            "kms_admin_role_arn_digest": canonical_digest(
                {"role_arn": KMS_ADMIN_ROLE_ARN}
            ),
            "kms_admin_iam_role_trust_policy_digest": (
                inspect_iam_role_trust_policy(
                    iam,
                    role_arn=KMS_ADMIN_ROLE_ARN,
                    account_id=AWS_ACCOUNT_ID,
                )
            ),
            "s3_bucket_controls_digest": production_bucket_controls_digest(
                ProductionControlPlaneS3()
            ),
            "s3_bucket_policy_digest": aws_policy_digest(
                ProductionControlPlaneS3().bucket_policy()
            ),
            "kms_key_policy_digest": kms_policy_digest,
            "kms_grants_digest": kms_grants_digest,
        }
        for identity in ("backup", "snapshot"):
            trust_digest, permissions_digest, _provider, _trust, _permissions = (
                inspect_iam_storage_role(
                    iam,
                    role_arn=STORAGE_ROLE_ARNS[identity],
                    expected_provider_arn=IRSA_PROVIDER_ARN,
                    expected_subject=TRUST_SUBJECTS[identity],
                    bucket="industrial-shadow-test",
                    prefix=STORAGE_PREFIXES[identity],
                    kms_key_arn=FakeS3.kms_key,
                    purpose=identity,
                    region="us-east-1",
                    account_id=AWS_ACCOUNT_ID,
                )
            )
            digests[f"{identity}_iam_role_trust_policy_digest"] = trust_digest
            digests[f"{identity}_iam_role_permissions_digest"] = permissions_digest
        if set(digests) != AWS_STORAGE_POLICY_DIGEST_FIELDS:
            raise AssertionError("test AWS policy digest fixture is incomplete")
        return digests

    @classmethod
    def _probe(
        cls,
        client: ProductionControlPlaneS3,
        *,
        confirmation: str,
        kms_client: ProductionKms | None = None,
        iam_client: ProductionIam | None = None,
        sts_client: ProductionSts | None = None,
        expected_policy_digests: dict[str, str] | None = None,
        kms_admin_role_arn: str = KMS_ADMIN_ROLE_ARN,
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
        policy_digests = expected_policy_digests or cls._policy_digests()
        return S3KmsProbe(
            storage,
            require_object_lock=True,
            kms_client=kms_client or ProductionKms(),
            sts_client=sts_client or ProductionSts(),
            iam_client=iam_client or ProductionIam(),
            expected_account_id="123456789012",
            expected_caller_arn=CONTROL_PLANE_CALLER_ARN,
            expected_caller_trust_contract=CALLER_TRUST_CONTRACT,
            expected_kms_admin_role_arn=kms_admin_role_arn,
            expected_irsa_oidc_provider_arn=IRSA_PROVIDER_ARN,
            expected_role_arns=STORAGE_ROLE_ARNS,
            expected_trust_subjects=TRUST_SUBJECTS,
            expected_policy_digests=policy_digests,
            expected_policy_bundle_digest=aws_storage_policy_bundle_digest(
                policy_digests
            ),
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

    def test_read_only_collector_reproduces_signed_policy_bundle(self) -> None:
        s3 = ProductionControlPlaneS3()
        fragment = collect_aws_storage_policy_digests(
            s3_client=s3,
            kms_client=ProductionKms(),
            iam_client=ProductionIam(),
            sts_client=ProductionSts(),
            bucket="industrial-shadow-test",
            region="us-east-1",
            account_id=AWS_ACCOUNT_ID,
            kms_key_arn=FakeS3.kms_key,
            control_plane_caller_arn=CONTROL_PLANE_CALLER_ARN,
            kms_admin_role_arn=KMS_ADMIN_ROLE_ARN,
            oidc_provider_arn=IRSA_PROVIDER_ARN,
            role_arns=STORAGE_ROLE_ARNS,
            trust_subjects=TRUST_SUBJECTS,
            prefixes=STORAGE_PREFIXES,
            sentinel_keys={
                "backup": ProductionControlPlaneS3.backup_sentinel,
                "snapshot": ProductionControlPlaneS3.snapshot_sentinel,
            },
            caller_trust_repository="industrial-shadow/industry-shadow",
            caller_trust_repository_owner_id="214596190",
            caller_trust_repository_id="24681012",
            caller_trust_ref="refs/heads/main",
            caller_trust_environment="production-acceptance",
            caller_trust_workflow="production-acceptance",
        )
        self.assertEqual(
            [
                "get_bucket_location",
                "get_bucket_versioning",
                "get_bucket_ownership_controls",
                "get_public_access_block",
                "get_bucket_encryption",
                "get_object_lock_configuration",
                "get_bucket_lifecycle_configuration",
                "get_bucket_policy",
            ],
            s3.calls,
        )
        expected = self._policy_digests()
        self.assertEqual("aws", fragment["aws_partition"])
        self.assertEqual(
            CALLER_TRUST_CONTRACT,
            fragment["s3_control_plane_caller_trust_contract"],
        )
        self.assertEqual(
            {name: fragment[name] for name in AWS_STORAGE_POLICY_DIGEST_FIELDS},
            expected,
        )
        self.assertEqual(
            aws_storage_policy_bundle_digest(expected),
            fragment["aws_storage_policy_bundle_digest"],
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

    def test_kms_admin_role_must_be_same_account_and_distinct_before_reads(self) -> None:
        for role_arn in (
            CONTROL_PLANE_CALLER_ARN,
            "arn:aws:iam::210987654321:role/shadow-kms-admin",
        ):
            client = ProductionControlPlaneS3()
            with self.assertRaises(DomainError) as rejected:
                self._probe(
                    client,
                    confirmation=self._confirmation(),
                    kms_admin_role_arn=role_arn,
                )
            self.assertEqual("CLOUD_CONTROL_PLANE_REQUIRED", rejected.exception.code)
            self.assertEqual([], client.calls)

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

    def test_wrong_signed_control_plane_caller_never_mutates(self) -> None:
        client = ProductionControlPlaneS3()
        with self.assertRaises(DomainError) as rejected:
            self._probe(
                client,
                confirmation=self._confirmation(),
                sts_client=ProductionSts(
                    "arn:aws:sts::123456789012:assumed-role/other/control"
                ),
            ).run()
        self.assertEqual("S3_CONTROL_PLANE_INVALID", rejected.exception.code)
        self.assertNotIn("put_object", client.calls)
        self.assertNotIn("delete_object", client.calls)

    def test_public_bucket_allow_and_broad_role_policy_never_mutate(self) -> None:
        for client, iam in (
            (ProductionControlPlaneS3(extra_bucket_allow=True), ProductionIam()),
            (
                ProductionControlPlaneS3(missing_mutation_guard=True),
                ProductionIam(),
            ),
            (ProductionControlPlaneS3(), ProductionIam(broad_role="backup")),
            (ProductionControlPlaneS3(), ProductionIam(broad_caller=True)),
            *(
                (
                    ProductionControlPlaneS3(),
                    ProductionIam(caller_trust_drift=drift),
                )
                for drift in (
                    "extra_statement",
                    "wildcard_principal",
                    "string_like",
                    "missing_audience",
                    "extra_condition",
                )
            ),
            (
                ProductionControlPlaneS3(),
                ProductionIam(
                    oidc_client_ids=["sts.amazonaws.com", "unapproved-client"]
                ),
            ),
            (ProductionControlPlaneS3(), ProductionIam(admin_trust_drift=True)),
        ):
            with self.assertRaises(DomainError) as rejected:
                self._probe(
                    client,
                    confirmation=self._confirmation(),
                    iam_client=iam,
                ).run()
            self.assertEqual("S3_CONTROL_PLANE_INVALID", rejected.exception.code)
            self.assertNotIn("put_object", client.calls)
            self.assertNotIn("delete_object", client.calls)

    def test_kms_grant_or_signed_policy_digest_drift_never_mutates(self) -> None:
        cases: tuple[tuple[ProductionKms, dict[str, str] | None], ...] = (
            (
                ProductionKms(
                    grants=[
                        {
                            "GrantId": "grant-1",
                            "Name": "unexpected",
                            "GranteePrincipal": STORAGE_ROLE_ARNS["backup"],
                            "Operations": ["Decrypt"],
                        }
                    ]
                ),
                None,
            ),
            (
                ProductionKms(),
                {**self._policy_digests(), "s3_bucket_policy_digest": "f" * 64},
            ),
            (ProductionKms(extra_policy_allow=True), None),
            (ProductionKms(admin_forbidden_action="kms:Decrypt"), None),
            (ProductionKms(admin_forbidden_action="kms:CreateGrant"), None),
            (ProductionKms(admin_forbidden_action="kms:RevokeGrant"), None),
            (ProductionKms(admin_forbidden_action="kms:*"), None),
        )
        for kms, policy_digests in cases:
            client = ProductionControlPlaneS3()
            with self.assertRaises(DomainError) as rejected:
                self._probe(
                    client,
                    confirmation=self._confirmation(),
                    kms_client=kms,
                    expected_policy_digests=policy_digests,
                ).run()
            self.assertEqual("S3_CONTROL_PLANE_INVALID", rejected.exception.code)
            self.assertNotIn("put_object", client.calls)
            self.assertNotIn("delete_object", client.calls)

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
        self.assertEqual(1, evidence.metrics["aws_policy_digests_verified"])
        self.assertEqual(
            aws_storage_policy_bundle_digest(self._policy_digests()),
            evidence.metrics["aws_storage_policy_bundle_digest"],
        )
        self.assertTrue(
            next(
                check.passed
                for check in evidence.checks
                if check.name == "mutation_authorization_bound"
            )
        )


if __name__ == "__main__":
    unittest.main()
