from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from typing import Any

from shadow_sandbox.common.models import DomainError, utc_now
from shadow_sandbox.common.object_storage import S3ObjectStorage

from .evidence import GateCheck, GateEvidence, complete


class S3KmsProbe:
    """Live S3/KMS acceptance probe with version-aware cleanup and no secret output."""

    def __init__(
        self,
        storage: S3ObjectStorage,
        *,
        require_object_lock: bool = False,
        kms_client: Any | None = None,
        sts_client: Any | None = None,
        expected_account_id: str | None = None,
        require_cloud_control_plane: bool = False,
    ) -> None:
        if not storage.kms_key_id or not storage.kms_key_id.startswith("arn:"):
            raise DomainError(
                "KMS_KEY_REQUIRED", "S3 production probe requires an exact KMS key ARN"
            )
        self.storage = storage
        self.require_object_lock = require_object_lock
        self.kms_client = kms_client
        self.sts_client = sts_client
        self.expected_account_id = expected_account_id
        self.require_cloud_control_plane = require_cloud_control_plane
        if require_cloud_control_plane and (
            kms_client is None
            or sts_client is None
            or not expected_account_id
            or not expected_account_id.isdigit()
            or len(expected_account_id) != 12
        ):
            raise DomainError(
                "CLOUD_CONTROL_PLANE_REQUIRED",
                "KMS, STS, and the expected AWS account are required",
            )

    @staticmethod
    def _tls_only_policy(document: Mapping[str, Any]) -> bool:
        statements = document.get("Statement", ())
        if isinstance(statements, Mapping):
            statements = (statements,)
        for item in statements:
            if not isinstance(item, Mapping) or item.get("Effect") != "Deny":
                continue
            condition = item.get("Condition", {})
            boolean = condition.get("Bool", {}) if isinstance(condition, Mapping) else {}
            action = item.get("Action", ())
            actions = {action} if isinstance(action, str) else set(action)
            if boolean.get("aws:SecureTransport") == "false" and (
                "s3:*" in actions or {"s3:GetObject", "s3:PutObject"}.issubset(actions)
            ):
                return True
        return False

    def _cleanup_versions(self, full_key: str) -> bool:
        response = self.storage.client.list_object_versions(
            Bucket=self.storage.bucket, Prefix=full_key
        )
        for collection in ("Versions", "DeleteMarkers"):
            for item in response.get(collection, ()):
                if item.get("Key") == full_key and item.get("VersionId"):
                    self.storage.client.delete_object(
                        Bucket=self.storage.bucket,
                        Key=full_key,
                        VersionId=item["VersionId"],
                    )
        remaining = self.storage.client.list_object_versions(
            Bucket=self.storage.bucket, Prefix=full_key
        )
        return not any(
            item.get("Key") == full_key
            for collection in ("Versions", "DeleteMarkers")
            for item in remaining.get(collection, ())
        )

    def _has_retained_version(self, full_key: str) -> bool:
        response = self.storage.client.list_object_versions(
            Bucket=self.storage.bucket, Prefix=full_key
        )
        return any(
            item.get("Key") == full_key and bool(item.get("VersionId"))
            for item in response.get("Versions", ())
        )

    def run(self) -> GateEvidence:
        started = utc_now()
        client = self.storage.client
        versioning = client.get_bucket_versioning(Bucket=self.storage.bucket)
        public = client.get_public_access_block(Bucket=self.storage.bucket).get(
            "PublicAccessBlockConfiguration", {}
        )
        encryption = client.get_bucket_encryption(Bucket=self.storage.bucket)
        rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", ())
        lifecycle = client.get_bucket_lifecycle_configuration(Bucket=self.storage.bucket)
        public_policy = False
        tls_only_policy = False
        kms_enabled = False
        kms_rotation = False
        kms_identity = False
        account_identity = False
        if self.require_cloud_control_plane:
            kms_client = self.kms_client
            sts_client = self.sts_client
            if kms_client is None or sts_client is None:
                raise DomainError(
                    "CLOUD_CONTROL_PLANE_REQUIRED", "KMS and STS clients are required"
                )
            public_policy = not bool(
                client.get_bucket_policy_status(Bucket=self.storage.bucket)
                .get("PolicyStatus", {})
                .get("IsPublic", True)
            )
            policy = json.loads(
                client.get_bucket_policy(Bucket=self.storage.bucket).get("Policy", "{}")
            )
            tls_only_policy = self._tls_only_policy(policy)
            metadata = kms_client.describe_key(KeyId=self.storage.kms_key_id).get(
                "KeyMetadata", {}
            )
            kms_identity = metadata.get("Arn") == self.storage.kms_key_id
            kms_enabled = (
                metadata.get("KeyState") == "Enabled"
                and metadata.get("Enabled") is True
                and metadata.get("KeyUsage") == "ENCRYPT_DECRYPT"
                and metadata.get("KeySpec") == "SYMMETRIC_DEFAULT"
            )
            kms_rotation = bool(
                kms_client.get_key_rotation_status(KeyId=self.storage.kms_key_id).get(
                    "KeyRotationEnabled"
                )
            )
            caller = sts_client.get_caller_identity()
            account_identity = caller.get("Account") == self.expected_account_id
        lock_enabled = False
        lock_retention = False
        try:
            lock_config = client.get_object_lock_configuration(Bucket=self.storage.bucket).get(
                "ObjectLockConfiguration", {}
            )
            lock_enabled = lock_config.get("ObjectLockEnabled") == "Enabled"
            retention = lock_config.get("Rule", {}).get("DefaultRetention", {})
            lock_retention = (
                retention.get("Mode")
                in {
                    "GOVERNANCE",
                    "COMPLIANCE",
                }
                and int(retention.get("Days", 0) or retention.get("Years", 0)) > 0
            )
        except Exception as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code")
            if code not in {
                "ObjectLockConfigurationNotFoundError",
                "NoSuchObjectLockConfiguration",
            }:
                raise

        key = f"production-probes/{os.urandom(16).hex()}.bin"
        full_key = self.storage._key(key)
        payload = os.urandom(4096)
        reference = None
        read_back = b""
        head: dict[str, Any] = {}
        disposition_verified = False
        retained_probe = False
        try:
            reference = self.storage.put_bytes(
                key, payload, content_type="application/octet-stream"
            )
            head = client.head_object(Bucket=self.storage.bucket, Key=full_key)
            read_back = self.storage.get_bytes(key, maximum_bytes=8192)
        finally:
            if self.require_object_lock and lock_enabled and lock_retention:
                retained_probe = True
                disposition_verified = self._has_retained_version(full_key)
            else:
                disposition_verified = self._cleanup_versions(full_key)

        default_kms = any(
            item.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") == "aws:kms"
            for item in rules
        )
        default_kms_key = any(
            item.get("ApplyServerSideEncryptionByDefault", {}).get("KMSMasterKeyID")
            == self.storage.kms_key_id
            for item in rules
        )
        bucket_key_enabled = any(item.get("BucketKeyEnabled") is True for item in rules)
        block_keys = (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
        checks = (
            GateCheck("bucket_versioning", versioning.get("Status") == "Enabled"),
            GateCheck("public_access_block", all(public.get(key) is True for key in block_keys)),
            GateCheck(
                "default_kms_encryption",
                default_kms
                and default_kms_key
                and (bucket_key_enabled or not self.require_cloud_control_plane),
            ),
            GateCheck(
                "bucket_policy_not_public",
                public_policy or not self.require_cloud_control_plane,
            ),
            GateCheck(
                "bucket_policy_tls_only",
                tls_only_policy or not self.require_cloud_control_plane,
            ),
            GateCheck(
                "kms_key_enabled_and_pinned",
                (kms_identity and kms_enabled) or not self.require_cloud_control_plane,
            ),
            GateCheck(
                "kms_automatic_rotation",
                kms_rotation or not self.require_cloud_control_plane,
            ),
            GateCheck(
                "aws_account_identity",
                account_identity or not self.require_cloud_control_plane,
            ),
            GateCheck(
                "lifecycle_policy",
                any(
                    item.get("Status") == "Enabled"
                    and bool(item.get("Expiration"))
                    and bool(item.get("NoncurrentVersionExpiration"))
                    for item in lifecycle.get("Rules", ())
                ),
            ),
            GateCheck(
                "object_lock",
                (lock_enabled and lock_retention) or not self.require_object_lock,
            ),
            GateCheck(
                "probe_object_kms",
                bool(reference)
                and reference.encryption == "aws:kms"
                and bool(reference.version_id)
                and head.get("ServerSideEncryption") == "aws:kms"
                and head.get("SSEKMSKeyId") == self.storage.kms_key_id,
            ),
            GateCheck(
                "probe_object_integrity",
                read_back == payload
                and head.get("Metadata", {}).get("sha256") == hashlib.sha256(payload).hexdigest(),
            ),
            GateCheck("probe_object_disposition", disposition_verified),
        )
        return complete(
            "s3",
            started_at=started,
            coordinates={
                "service": "s3",
                "bucket_digest": hashlib.sha256(self.storage.bucket.encode()).hexdigest(),
                "prefix": self.storage.prefix,
            },
            checks=checks,
            metrics={
                "probe_bytes": len(payload),
                "lifecycle_rules": len(lifecycle.get("Rules", ())),
                "retained_probe_version": int(retained_probe),
                "cloud_control_plane_verified": int(self.require_cloud_control_plane),
            },
            limitations=(() if self.require_object_lock else ("object_lock_optional",)),
        )
