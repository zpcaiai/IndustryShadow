from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError, utc_now
from shadow_sandbox.common.object_storage import S3ObjectStorage

from .evidence import GateCheck, GateEvidence, complete

WORKLOAD_SESSION_KEYS = frozenset(
    {"method", "profile", "role_arn", "web_identity_token_file", "role_session_name"}
)


def workload_session(config: Mapping[str, Any], *, boto3_module: Any) -> Any:
    """Create a non-default AWS session from one explicit, private identity contract."""
    if set(config) != WORKLOAD_SESSION_KEYS:
        raise DomainError(
            "WORKLOAD_IDENTITY_CONFIG_INVALID", "workload session fields are invalid"
        )
    method = config.get("method")
    profile = str(config.get("profile", ""))
    role_arn = str(config.get("role_arn", ""))
    token_file = str(config.get("web_identity_token_file", ""))
    session_name = str(config.get("role_session_name", ""))
    if method == "profile":
        if not profile or role_arn or token_file or session_name:
            raise DomainError(
                "WORKLOAD_IDENTITY_CONFIG_INVALID",
                "profile sessions require only one explicit AWS profile",
            )
        return boto3_module.Session(profile_name=profile)
    if method != "web_identity" or profile or not role_arn or not token_file or not session_name:
        raise DomainError(
            "WORKLOAD_IDENTITY_CONFIG_INVALID", "web identity session fields are invalid"
        )
    token_path = Path(token_file)
    try:
        token_status = token_path.lstat()
    except OSError:
        token_status = None
    if (
        token_status is None
        or not stat.S_ISREG(token_status.st_mode)
        or token_status.st_nlink != 1
        or not 1 <= token_status.st_size <= 1024 * 1024
        or stat.S_IMODE(token_status.st_mode) & 0o077
        or not re.fullmatch(
            r"arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]+",
            role_arn,
        )
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+=,.@_-]{1,63}", session_name)
    ):
        raise DomainError(
            "WORKLOAD_IDENTITY_CONFIG_INVALID", "web identity token input is unsafe"
        )
    token = token_path.read_text(encoding="utf-8").strip()
    if not token:
        raise DomainError("WORKLOAD_IDENTITY_CONFIG_INVALID", "web identity token is empty")
    base = boto3_module.Session()
    assumed = base.client("sts").assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        WebIdentityToken=token,
        DurationSeconds=900,
    )
    credentials = assumed.get("Credentials", {})
    if not all(credentials.get(name) for name in ("AccessKeyId", "SecretAccessKey", "SessionToken")):
        raise DomainError(
            "WORKLOAD_IDENTITY_CONFIG_INVALID", "web identity did not return credentials"
        )
    return boto3_module.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def normalized_iam_role_arn(caller_arn: str) -> str:
    """Normalize direct IAM roles and STS assumed-role sessions to one role ARN."""
    direct = re.fullmatch(
        r"arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/(.+)", caller_arn
    )
    if direct:
        return caller_arn
    assumed = re.fullmatch(
        r"arn:(aws|aws-us-gov|aws-cn):sts::(\d{12}):assumed-role/(.+)/[^/]+",
        caller_arn,
    )
    if not assumed:
        raise DomainError(
            "WORKLOAD_IDENTITY_INVALID", "STS caller is not an IAM role session"
        )
    return f"arn:{assumed.group(1)}:iam::{assumed.group(2)}:role/{assumed.group(3)}"


class S3WorkloadIdentityProbe:
    """Verify one pod identity can access only its KMS-bound S3 prefix."""

    def __init__(
        self,
        storage: S3ObjectStorage,
        *,
        identity: str,
        sts_client: Any,
        expected_role_arn: str,
        forbidden_key: str,
        require_object_lock: bool = False,
    ) -> None:
        if identity not in {"backup", "snapshot"} or not forbidden_key:
            raise DomainError(
                "WORKLOAD_IDENTITY_CONFIG_INVALID", "workload identity probe config is invalid"
            )
        self.storage = storage
        self.identity = identity
        self.sts_client = sts_client
        self.expected_role_arn = expected_role_arn
        self.forbidden_key = forbidden_key
        self.require_object_lock = require_object_lock

    def run(self) -> GateEvidence:
        started = utc_now()
        caller = self.sts_client.get_caller_identity()
        caller_arn = str(caller.get("Arn", ""))
        caller_role = normalized_iam_role_arn(caller_arn)
        account = str(caller.get("Account", ""))
        expected_match = re.fullmatch(
            r"arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/.+",
            self.expected_role_arn,
        )
        if expected_match is None:
            raise DomainError(
                "WORKLOAD_IDENTITY_CONFIG_INVALID", "expected workload role ARN is invalid"
            )
        payload = os.urandom(4096)
        key = f"production-workload-probes/{os.urandom(16).hex()}.bin"
        reference = None
        disposition_verified = False
        try:
            reference = self.storage.put_bytes(
                key, payload, content_type="application/octet-stream"
            )
            readback = self.storage.get_version_bytes(
                key,
                version_id=str(reference.version_id or ""),
                maximum_bytes=8192,
                expected_sha256=reference.sha256,
            )
            full_key = self.storage._key(key)
            forbidden_denied = False
            try:
                response = self.storage.client.get_object(
                    Bucket=self.storage.bucket, Key=self.forbidden_key
                )
                body = response.get("Body")
                if body is not None:
                    body.close()
            except Exception as error:
                code = str(
                    getattr(error, "response", {}).get("Error", {}).get("Code", "")
                )
                forbidden_denied = code in {"AccessDenied", "403", "Forbidden"}
            if self.require_object_lock:
                disposition_verified = self._retained(
                    full_key, str(reference.version_id or "")
                )
        finally:
            if reference is not None and not self.require_object_lock:
                disposition = self.storage.client.delete_object(
                    Bucket=self.storage.bucket,
                    Key=self.storage._key(key),
                    VersionId=reference.version_id,
                )
                disposition_verified = isinstance(disposition, Mapping)
        checks = (
            GateCheck(
                "exact_workload_role",
                caller_role == self.expected_role_arn
                and account == expected_match.group(2)
                and bool(
                    re.fullmatch(
                        r"arn:(?:aws|aws-us-gov|aws-cn):sts::\d{12}:assumed-role/.+/[^/]+",
                        caller_arn,
                    )
                ),
            ),
            GateCheck(
                "versioned_kms_roundtrip",
                readback == payload
                and bool(reference.version_id)
                and reference.encryption == "aws:kms",
            ),
            GateCheck("cross_prefix_denied", forbidden_denied),
            GateCheck("probe_object_disposition", disposition_verified),
        )
        return complete(
            f"s3_{self.identity}_identity",
            started_at=started,
            coordinates={
                "bucket_digest": hashlib.sha256(self.storage.bucket.encode()).hexdigest(),
                "prefix": self.storage.prefix,
                "role_arn_digest": hashlib.sha256(self.expected_role_arn.encode()).hexdigest(),
                "kms_key_digest": hashlib.sha256(
                    str(self.storage.kms_key_id).encode()
                ).hexdigest(),
            },
            checks=checks,
            metrics={"probe_bytes": len(payload)},
        )

    def _retained(self, full_key: str, version_id: str) -> bool:
        if not version_id:
            return False
        response = self.storage.client.get_object_retention(
            Bucket=self.storage.bucket, Key=full_key, VersionId=version_id
        )
        retention = response.get("Retention", {})
        until = retention.get("RetainUntilDate")
        if isinstance(until, str):
            try:
                until = dt.datetime.fromisoformat(until)
            except ValueError:
                return False
        if not isinstance(until, dt.datetime):
            return False
        if until.tzinfo is None:
            until = until.replace(tzinfo=dt.UTC)
        return retention.get("Mode") in {"GOVERNANCE", "COMPLIANCE"} and until > dt.datetime.now(dt.UTC)


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
        expected_caller_arn: str | None = None,
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
        self.expected_caller_arn = expected_caller_arn
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
    def _tls_only_policy(document: Mapping[str, Any], bucket: str, partition: str = "aws") -> bool:
        def string_set(value: Any) -> set[str]:
            if isinstance(value, str):
                return {value}
            if isinstance(value, (list, tuple, set)) and all(
                isinstance(item, str) for item in value
            ):
                return set(value)
            return set()

        statements = document.get("Statement", ())
        if isinstance(statements, Mapping):
            statements = (statements,)
        required_resources = {
            f"arn:{partition}:s3:::{bucket}",
            f"arn:{partition}:s3:::{bucket}/*",
        }
        for item in statements:
            if not isinstance(item, Mapping) or item.get("Effect") != "Deny":
                continue
            if any(name in item for name in ("NotAction", "NotPrincipal", "NotResource")):
                continue
            condition = item.get("Condition", {})
            boolean = condition.get("Bool", {}) if isinstance(condition, Mapping) else {}
            if (
                not isinstance(condition, Mapping)
                or set(condition) != {"Bool"}
                or not isinstance(boolean, Mapping)
                or set(boolean) != {"aws:SecureTransport"}
            ):
                continue
            actions = string_set(item.get("Action", ()))
            resources = string_set(item.get("Resource", ()))
            principal = item.get("Principal")
            everyone = principal == "*" or (
                isinstance(principal, Mapping)
                and (principal.get("AWS") == "*" or principal.get("AWS") == ["*"])
            )
            if (
                boolean.get("aws:SecureTransport") in {"false", False}
                and "s3:*" in actions
                and required_resources.issubset(resources)
                and everyone
            ):
                return True
        return False

    @staticmethod
    def _lifecycle_rule_covers(rule: Mapping[str, Any], full_key: str) -> bool:
        if rule.get("Status") != "Enabled":
            return False
        expiration = rule.get("Expiration", {})
        noncurrent = rule.get("NoncurrentVersionExpiration", {})
        if not isinstance(expiration, Mapping) or not isinstance(noncurrent, Mapping):
            return False
        expiration_days = expiration.get("Days")
        current_expiry = (type(expiration_days) is int and expiration_days > 0) or bool(
            expiration.get("Date")
        )
        noncurrent_days = noncurrent.get("NoncurrentDays")
        noncurrent_expiry = type(noncurrent_days) is int and noncurrent_days > 0
        if not current_expiry or not noncurrent_expiry:
            return False
        if "Prefix" in rule:
            prefix = rule.get("Prefix")
            return isinstance(prefix, str) and full_key.startswith(prefix)
        filter_value = rule.get("Filter")
        if filter_value is None or filter_value == {}:
            return True
        if not isinstance(filter_value, Mapping):
            return False
        if set(filter_value) == {"Prefix"}:
            prefix = filter_value.get("Prefix")
            return isinstance(prefix, str) and full_key.startswith(prefix)
        if set(filter_value) == {"And"} and isinstance(filter_value.get("And"), Mapping):
            conjunction = filter_value["And"]
            if set(conjunction) != {"Prefix"}:
                return False
            prefix = conjunction.get("Prefix")
            return isinstance(prefix, str) and full_key.startswith(prefix)
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

    def _has_retained_version(self, full_key: str, version_id: str | None) -> bool:
        if not version_id:
            return False
        response = self.storage.client.list_object_versions(
            Bucket=self.storage.bucket, Prefix=full_key
        )
        present = any(
            item.get("Key") == full_key and item.get("VersionId") == version_id
            for item in response.get("Versions", ())
        )
        if not present:
            return False
        response = self.storage.client.get_object_retention(
            Bucket=self.storage.bucket,
            Key=full_key,
            VersionId=version_id,
        )
        retention = response.get("Retention", {})
        mode = retention.get("Mode")
        until = retention.get("RetainUntilDate")
        if isinstance(until, str):
            try:
                until = dt.datetime.fromisoformat(until)
            except ValueError:
                return False
        if not isinstance(until, dt.datetime):
            return False
        if until.tzinfo is None:
            until = until.replace(tzinfo=dt.UTC)
        return mode in {"GOVERNANCE", "COMPLIANCE"} and until > dt.datetime.now(dt.UTC)

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
        workload_identity = False
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
            kms_arn = str(self.storage.kms_key_id).split(":")
            partition = kms_arn[1] if len(kms_arn) == 6 else "aws"
            tls_only_policy = self._tls_only_policy(policy, self.storage.bucket, partition)
            metadata = kms_client.describe_key(KeyId=self.storage.kms_key_id).get("KeyMetadata", {})
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
            workload_identity = bool(
                self.expected_caller_arn
                and normalized_iam_role_arn(str(caller.get("Arn", "")))
                == self.expected_caller_arn
            )
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
                disposition_verified = self._has_retained_version(
                    full_key, reference.version_id if reference else None
                )
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
        lifecycle_scope = any(
            isinstance(item, Mapping) and self._lifecycle_rule_covers(item, full_key)
            for item in lifecycle.get("Rules", ())
        )
        kms_arn = str(self.storage.kms_key_id).split(":")
        kms_coordinate_match = not self.require_cloud_control_plane or (
            len(kms_arn) == 6
            and kms_arn[0] == "arn"
            and kms_arn[2] == "kms"
            and kms_arn[3] == self.storage.region
            and kms_arn[4] == self.expected_account_id
            and kms_arn[5].startswith("key/")
        )
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
                (kms_identity and kms_enabled and kms_coordinate_match)
                or not self.require_cloud_control_plane,
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
                "aws_workload_identity",
                workload_identity
                or not self.require_cloud_control_plane
                or self.expected_caller_arn is None,
            ),
            GateCheck(
                "lifecycle_policy",
                lifecycle_scope,
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
                "region": self.storage.region or "provider-default",
                "kms_key_digest": hashlib.sha256(str(self.storage.kms_key_id).encode()).hexdigest(),
                "workload_identity_arn_digest": hashlib.sha256(
                    str(self.expected_caller_arn or "not-required").encode()
                ).hexdigest(),
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
