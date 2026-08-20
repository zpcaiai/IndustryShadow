from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import unquote

from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now
from shadow_sandbox.common.object_storage import S3ObjectStorage, validate_object_key
from shadow_sandbox.common.secure_files import read_private_file

from .evidence import GateCheck, GateEvidence, complete

WORKLOAD_SESSION_KEYS = frozenset(
    {"method", "profile", "role_arn", "web_identity_token_file", "role_session_name"}
)
DENIED_ERROR_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "AllAccessDisabled",
        "Forbidden",
        "403",
    }
)
NOT_FOUND_ERROR_CODES = frozenset({"NoSuchKey", "NoSuchVersion", "NotFound", "404"})
SENTINEL_MAX_BYTES = 64 * 1024
ACCEPTANCE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
IAM_ROLE_ARN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/([A-Za-z0-9+=,.@_/-]+)$"
)
IAM_OIDC_PROVIDER_ARN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):"
    r"oidc-provider/([A-Za-z0-9][A-Za-z0-9._/-]{0,254})$"
)
AWS_STORAGE_POLICY_DIGEST_FIELDS = frozenset(
    {
        "aws_irsa_oidc_provider_arn_digest",
        "aws_irsa_oidc_provider_configuration_digest",
        "s3_control_plane_caller_arn_digest",
        "s3_control_plane_caller_trust_contract_digest",
        "s3_control_plane_caller_iam_role_trust_policy_digest",
        "s3_control_plane_caller_iam_role_permissions_digest",
        "kms_admin_role_arn_digest",
        "kms_admin_iam_role_trust_policy_digest",
        "s3_bucket_controls_digest",
        "s3_bucket_policy_digest",
        "kms_key_policy_digest",
        "kms_grants_digest",
        "backup_iam_role_trust_policy_digest",
        "backup_iam_role_permissions_digest",
        "snapshot_iam_role_trust_policy_digest",
        "snapshot_iam_role_permissions_digest",
    }
)
WORKLOAD_S3_READ_ACTIONS = frozenset(
    {"s3:GetObject", "s3:GetObjectRetention", "s3:GetObjectVersion"}
)
WORKLOAD_S3_WRITE_ACTIONS = frozenset({"s3:PutObject"})
WORKLOAD_S3_MULTIPART_ABORT_ACTIONS = frozenset({"s3:AbortMultipartUpload"})
WORKLOAD_KMS_ACTIONS = frozenset({"kms:Decrypt", "kms:GenerateDataKey"})
RESTORE_KMS_ACTIONS = frozenset({"kms:Decrypt"})
CONTROL_S3_LIST_ACTIONS = frozenset({"s3:ListBucketVersions"})
CONTROL_PLANE_S3_BUCKET_READ_ACTIONS = frozenset(
    {
        "s3:GetBucketLocation",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetBucketOwnershipControls",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "s3:GetLifecycleConfiguration",
    }
)
CONTROL_PLANE_S3_ACCEPTANCE_OBJECT_ACTIONS = frozenset(
    {
        "s3:GetObjectRetention",
        "s3:GetObjectVersion",
        "s3:PutObject",
    }
)
CONTROL_PLANE_S3_ACCEPTANCE_READ_ACTIONS = frozenset(
    {"s3:GetObjectRetention", "s3:GetObjectVersion"}
)
CONTROL_PLANE_IAM_ROLE_READ_ACTIONS = frozenset({"iam:GetRole"})
CONTROL_PLANE_IAM_ROLE_POLICY_READ_ACTIONS = frozenset(
    {
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
    }
)
CONTROL_PLANE_IAM_MANAGED_POLICY_READ_ACTIONS = frozenset(
    {"iam:GetPolicy", "iam:GetPolicyVersion"}
)
CONTROL_PLANE_IAM_OIDC_READ_ACTIONS = frozenset(
    {"iam:GetOpenIDConnectProvider"}
)
PROTECTED_S3_MUTATION_ACTIONS = frozenset(
    {
        "s3:AbortMultipartUpload",
        "s3:BypassGovernanceRetention",
        "s3:DeleteObject",
        "s3:DeleteObjectTagging",
        "s3:DeleteObjectVersion",
        "s3:DeleteObjectVersionTagging",
        "s3:ObjectOwnerOverrideToBucketOwner",
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:PutObjectLegalHold",
        "s3:PutObjectRetention",
        "s3:PutObjectTagging",
        "s3:PutObjectVersionAcl",
        "s3:PutObjectVersionTagging",
        "s3:ReplicateDelete",
        "s3:ReplicateObject",
        "s3:ReplicateTags",
        "s3:RestoreObject",
    }
)
CONTROL_KMS_READ_ACTIONS = frozenset(
    {
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListGrants",
        "kms:ListKeyPolicies",
    }
)
KMS_ADMIN_ACTIONS = frozenset(
    {
        *CONTROL_KMS_READ_ACTIONS,
        "kms:CancelKeyDeletion",
        "kms:DisableKey",
        "kms:DisableKeyRotation",
        "kms:EnableKey",
        "kms:EnableKeyRotation",
        "kms:ListResourceTags",
        "kms:PutKeyPolicy",
        "kms:RotateKeyOnDemand",
        "kms:ScheduleKeyDeletion",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:UpdateKeyDescription",
    }
)
IRSA_TOKEN_AUDIENCE = "sts.amazonaws.com"
OIDC_THUMBPRINT = re.compile(r"^[A-Fa-f0-9]{40}$")
S3_PUBLIC_ACCESS_BLOCK_KEYS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)
GITHUB_ACTIONS_OIDC_PROVIDER = "token.actions.githubusercontent.com"
GITHUB_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GITHUB_BRANCH_REF = re.compile(r"^refs/heads/[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,253})$")


def aws_partition_for_region(region: str) -> str:
    if not re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*", region):
        raise DomainError("AWS_REGION_INVALID", "AWS region is invalid")
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


def _normalized_policy_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) or not key for key in value):
            raise DomainError("AWS_POLICY_INVALID", "AWS policy keys must be non-empty strings")
        return {key: _normalized_policy_value(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        normalized = [_normalized_policy_value(item) for item in value]
        digests = [canonical_digest(item) for item in normalized]
        if len(digests) != len(set(digests)):
            raise DomainError("AWS_POLICY_INVALID", "AWS policy arrays must not repeat values")
        return [item for _digest, item in sorted(zip(digests, normalized, strict=True))]
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    raise DomainError("AWS_POLICY_INVALID", "AWS policy contains a non-JSON value")


def normalize_aws_policy(document: Mapping[str, Any] | str) -> Mapping[str, Any]:
    """Normalize ordering without discarding any policy-semantic field."""
    value: Any = document
    if isinstance(document, str):
        try:
            value = json.loads(document)
        except json.JSONDecodeError as error:
            try:
                value = json.loads(unquote(document))
            except json.JSONDecodeError:
                raise DomainError("AWS_POLICY_INVALID", "AWS policy JSON is invalid") from error
    if (
        not isinstance(value, Mapping)
        or set(value).difference({"Version", "Id", "Statement"})
        or value.get("Version") != "2012-10-17"
        or "Statement" not in value
    ):
        raise DomainError("AWS_POLICY_INVALID", "AWS policy document contract is invalid")
    normalized = _normalized_policy_value(value)
    if not isinstance(normalized, Mapping):
        raise DomainError("AWS_POLICY_INVALID", "AWS policy must be an object")
    statements = normalized.get("Statement")
    if isinstance(statements, Mapping):
        normalized = {**normalized, "Statement": [statements]}
    elif not isinstance(statements, list) or not statements:
        raise DomainError("AWS_POLICY_INVALID", "AWS policy statements are required")
    return normalized


def aws_policy_digest(document: Mapping[str, Any] | str) -> str:
    return canonical_digest(normalize_aws_policy(document))


def aws_storage_policy_bundle_digest(digests: Mapping[str, str]) -> str:
    if set(digests) != AWS_STORAGE_POLICY_DIGEST_FIELDS or any(
        not re.fullmatch(r"[a-f0-9]{64}", value) for value in digests.values()
    ):
        raise DomainError(
            "AWS_POLICY_BINDING_INVALID",
            "AWS storage policy digest bundle is incomplete",
        )
    return canonical_digest({"schema_version": 1, "policy_digests": dict(sorted(digests.items()))})


def s3_bucket_controls_digest(
    *,
    bucket: str,
    expected_bucket_owner: str,
    region: str,
    kms_key_arn: str,
    lifecycle_prefixes: Mapping[str, str],
    location_constraint: Any,
    versioning: Mapping[str, Any],
    ownership_controls: Mapping[str, Any],
    public_access_block: Mapping[str, Any],
    encryption: Mapping[str, Any],
    object_lock: Mapping[str, Any],
    lifecycle: Mapping[str, Any],
) -> str:
    """Validate and digest the stable, exact S3 bucket-control semantics."""
    try:
        partition = aws_partition_for_region(region)
    except DomainError as error:
        raise DomainError(
            "S3_BUCKET_CONTROLS_INVALID", "S3 bucket control coordinates are invalid"
        ) from error
    kms_match = re.fullmatch(
        rf"arn:{re.escape(partition)}:kms:{re.escape(region)}:"
        rf"{re.escape(expected_bucket_owner)}:key/[A-Za-z0-9-]+",
        kms_key_arn,
    )
    if (
        not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket)
        or not re.fullmatch(r"\d{12}", expected_bucket_owner)
        or kms_match is None
        or set(lifecycle_prefixes) != {"acceptance", "backup", "snapshot"}
        or any(not isinstance(prefix, str) for prefix in lifecycle_prefixes.values())
    ):
        raise DomainError(
            "S3_BUCKET_CONTROLS_INVALID", "S3 bucket control coordinates are invalid"
        )
    try:
        normalized_prefixes = {
            name: validate_object_key(prefix.rstrip("/")) + "/"
            for name, prefix in lifecycle_prefixes.items()
        }
    except DomainError as error:
        raise DomainError(
            "S3_BUCKET_CONTROLS_INVALID", "S3 lifecycle prefixes are invalid"
        ) from error
    prefix_values = tuple(normalized_prefixes.values())
    if normalized_prefixes != dict(lifecycle_prefixes) or any(
        left.startswith(right) or right.startswith(left)
        for index, left in enumerate(prefix_values)
        for right in prefix_values[index + 1 :]
    ):
        raise DomainError(
            "S3_BUCKET_CONTROLS_INVALID",
            "S3 lifecycle prefixes must be canonical and pairwise non-nested",
        )

    if location_constraint is None or location_constraint == "":
        observed_region = "us-east-1"
    elif location_constraint == "EU":
        observed_region = "eu-west-1"
    elif isinstance(location_constraint, str):
        observed_region = location_constraint
    else:
        observed_region = ""
    mfa_delete = versioning.get("MFADelete", "NotConfigured")
    ownership_configuration = ownership_controls.get("OwnershipControls")
    ownership_rules = (
        ownership_configuration.get("Rules", ())
        if isinstance(ownership_configuration, Mapping)
        else ()
    )
    public_configuration = public_access_block.get("PublicAccessBlockConfiguration")
    if (
        observed_region != region
        or versioning.get("Status") != "Enabled"
        or mfa_delete not in {"NotConfigured", "Enabled", "Disabled"}
        or not isinstance(ownership_configuration, Mapping)
        or set(ownership_configuration) != {"Rules"}
        or not isinstance(ownership_rules, list)
        or len(ownership_rules) != 1
        or not isinstance(ownership_rules[0], Mapping)
        or set(ownership_rules[0]) != {"ObjectOwnership"}
        or ownership_rules[0].get("ObjectOwnership") != "BucketOwnerEnforced"
        or not isinstance(public_configuration, Mapping)
        or set(public_configuration) != set(S3_PUBLIC_ACCESS_BLOCK_KEYS)
        or any(public_configuration.get(name) is not True for name in S3_PUBLIC_ACCESS_BLOCK_KEYS)
    ):
        raise DomainError(
            "S3_BUCKET_CONTROLS_INVALID",
            "S3 location, versioning, ownership, or public-access controls are invalid",
        )

    encryption_configuration = encryption.get("ServerSideEncryptionConfiguration")
    encryption_rules = (
        encryption_configuration.get("Rules", ())
        if isinstance(encryption_configuration, Mapping)
        else ()
    )
    encryption_rule = encryption_rules[0] if isinstance(encryption_rules, list) and encryption_rules else None
    encryption_default = (
        encryption_rule.get("ApplyServerSideEncryptionByDefault")
        if isinstance(encryption_rule, Mapping)
        else None
    )
    if (
        not isinstance(encryption_configuration, Mapping)
        or set(encryption_configuration) != {"Rules"}
        or not isinstance(encryption_rules, list)
        or len(encryption_rules) != 1
        or not isinstance(encryption_rule, Mapping)
        or set(encryption_rule) != {"ApplyServerSideEncryptionByDefault", "BucketKeyEnabled"}
        or encryption_rule.get("BucketKeyEnabled") is not True
        or not isinstance(encryption_default, Mapping)
        or set(encryption_default) != {"SSEAlgorithm", "KMSMasterKeyID"}
        or encryption_default.get("SSEAlgorithm") != "aws:kms"
        or encryption_default.get("KMSMasterKeyID") != kms_key_arn
    ):
        raise DomainError(
            "S3_BUCKET_CONTROLS_INVALID", "S3 default KMS encryption controls are invalid"
        )

    lock_configuration = object_lock.get("ObjectLockConfiguration")
    lock_rule = (
        lock_configuration.get("Rule") if isinstance(lock_configuration, Mapping) else None
    )
    default_retention = lock_rule.get("DefaultRetention") if isinstance(lock_rule, Mapping) else None
    retention_mode = (
        default_retention.get("Mode") if isinstance(default_retention, Mapping) else None
    )
    retention_days = (
        default_retention.get("Days") if isinstance(default_retention, Mapping) else None
    )
    retention_years = (
        default_retention.get("Years") if isinstance(default_retention, Mapping) else None
    )
    retention_measurements = int(retention_days is not None) + int(retention_years is not None)
    if (
        not isinstance(lock_configuration, Mapping)
        or set(lock_configuration) != {"ObjectLockEnabled", "Rule"}
        or lock_configuration.get("ObjectLockEnabled") != "Enabled"
        or not isinstance(lock_rule, Mapping)
        or set(lock_rule) != {"DefaultRetention"}
        or not isinstance(default_retention, Mapping)
        or set(default_retention)
        not in ({"Mode", "Days"}, {"Mode", "Years"})
        or retention_mode not in {"GOVERNANCE", "COMPLIANCE"}
        or retention_measurements != 1
        or (
            retention_days is not None
            and (type(retention_days) is not int or retention_days <= 0)
        )
        or (
            retention_years is not None
            and (type(retention_years) is not int or retention_years <= 0)
        )
    ):
        raise DomainError(
            "S3_BUCKET_CONTROLS_INVALID", "S3 Object Lock controls are invalid"
        )

    lifecycle_rules = lifecycle.get("Rules", ())
    normalized_rules: dict[str, Mapping[str, Any]] = {}
    rule_ids: set[str] = set()
    if not isinstance(lifecycle_rules, list) or len(lifecycle_rules) != 3:
        raise DomainError(
            "S3_BUCKET_CONTROLS_INVALID", "S3 lifecycle rules are incomplete"
        )
    for rule in lifecycle_rules:
        if not isinstance(rule, Mapping) or set(rule) != {
            "ID",
            "Status",
            "Filter",
            "Expiration",
            "NoncurrentVersionExpiration",
            "AbortIncompleteMultipartUpload",
        }:
            raise DomainError(
                "S3_BUCKET_CONTROLS_INVALID", "S3 lifecycle rule shape is invalid"
            )
        rule_id = rule.get("ID")
        filter_value = rule.get("Filter")
        expiration = rule.get("Expiration")
        noncurrent = rule.get("NoncurrentVersionExpiration")
        multipart_abort = rule.get("AbortIncompleteMultipartUpload")
        if (
            not isinstance(rule_id, str)
            or not 1 <= len(rule_id) <= 255
            or rule_id in rule_ids
            or rule.get("Status") != "Enabled"
            or not isinstance(filter_value, Mapping)
            or set(filter_value) != {"Prefix"}
            or not isinstance(expiration, Mapping)
            or set(expiration) != {"Days"}
            or type(expiration.get("Days")) is not int
            or expiration["Days"] <= 0
            or not isinstance(noncurrent, Mapping)
            or set(noncurrent) != {"NoncurrentDays"}
            or type(noncurrent.get("NoncurrentDays")) is not int
            or noncurrent["NoncurrentDays"] <= 0
            or not isinstance(multipart_abort, Mapping)
            or set(multipart_abort) != {"DaysAfterInitiation"}
            or type(multipart_abort.get("DaysAfterInitiation")) is not int
            or multipart_abort["DaysAfterInitiation"] <= 0
        ):
            raise DomainError(
                "S3_BUCKET_CONTROLS_INVALID", "S3 lifecycle rule values are invalid"
            )
        matches = [
            name
            for name, prefix in normalized_prefixes.items()
            if filter_value.get("Prefix") == prefix
        ]
        if len(matches) != 1 or matches[0] in normalized_rules:
            raise DomainError(
                "S3_BUCKET_CONTROLS_INVALID", "S3 lifecycle rule scope is invalid"
            )
        rule_ids.add(rule_id)
        normalized_rules[matches[0]] = {
            "id": rule_id,
            "prefix": normalized_prefixes[matches[0]],
            "expiration_days": expiration["Days"],
            "noncurrent_expiration_days": noncurrent["NoncurrentDays"],
            "abort_incomplete_multipart_days": multipart_abort["DaysAfterInitiation"],
        }
    if set(normalized_rules) != {"acceptance", "backup", "snapshot"}:
        raise DomainError(
            "S3_BUCKET_CONTROLS_INVALID", "S3 lifecycle rule scopes are incomplete"
        )

    return canonical_digest(
        {
            "schema_version": 1,
            "bucket": {
                "name": bucket,
                "expected_owner": expected_bucket_owner,
                "region": region,
            },
            "versioning": {"status": "Enabled", "mfa_delete": mfa_delete},
            "object_ownership": "BucketOwnerEnforced",
            "public_access_block": {
                name: True for name in S3_PUBLIC_ACCESS_BLOCK_KEYS
            },
            "default_encryption": {
                "algorithm": "aws:kms",
                "kms_key_arn": kms_key_arn,
                "bucket_key_enabled": True,
            },
            "object_lock": {
                "enabled": True,
                "default_retention": {
                    "mode": retention_mode,
                    "days": retention_days or 0,
                    "years": retention_years or 0,
                },
            },
            "lifecycle_rules": {
                name: normalized_rules[name] for name in sorted(normalized_rules)
            },
        }
    )


def _statements(document: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    values = document.get("Statement", ())
    if not isinstance(values, list) or any(not isinstance(item, Mapping) for item in values):
        raise DomainError("AWS_POLICY_INVALID", "AWS policy statements are invalid")
    return tuple(values)


def _string_set(value: Any) -> frozenset[str]:
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return frozenset(value)
    return frozenset()


def s3_control_plane_mutation_confirmation(
    *,
    bucket: str,
    prefix: str,
    acceptance_run_id: str,
    signed_target_profile_digest: str,
) -> str:
    """Derive the one-run authorization for the bounded control-plane probe write."""
    if (
        not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket)
        or validate_object_key(prefix) != prefix
        or not ACCEPTANCE_RUN_ID.fullmatch(acceptance_run_id)
        or not re.fullmatch(r"[a-f0-9]{64}", signed_target_profile_digest)
    ):
        raise DomainError(
            "S3_MUTATION_CONFIRMATION_INVALID",
            "S3 mutation confirmation coordinates are invalid",
        )
    return canonical_digest(
        {
            "schema_version": 1,
            "operation": "s3-control-plane-production-probe-write",
            "bucket": bucket,
            "prefix": prefix,
            "probe_prefix": f"{prefix}/production-probes/",
            "acceptance_run_id": acceptance_run_id,
            "signed_target_profile_digest": signed_target_profile_digest,
        }
    )


def _error_class(error: Exception) -> tuple[str, bool, bool]:
    response = getattr(error, "response", {})
    detail = response.get("Error", {}) if isinstance(response, Mapping) else {}
    code = str(detail.get("Code", "")) if isinstance(detail, Mapping) else ""
    message = str(detail.get("Message", "")) if isinstance(detail, Mapping) else ""
    kms_denial = "kms" in code.lower() or "kms" in message.lower()
    return code, code in DENIED_ERROR_CODES, kms_denial


def _retention_coordinates(value: Mapping[str, Any]) -> tuple[str, str] | None:
    mode = value.get("Mode")
    until = value.get("RetainUntilDate")
    if isinstance(until, str):
        try:
            until = dt.datetime.fromisoformat(until)
        except ValueError:
            return None
    if not isinstance(until, dt.datetime):
        return None
    if until.tzinfo is None:
        until = until.replace(tzinfo=dt.UTC)
    until = until.astimezone(dt.UTC)
    if mode not in {"GOVERNANCE", "COMPLIANCE"} or until <= dt.datetime.now(dt.UTC):
        return None
    return str(mode), until.isoformat()


@dataclass(frozen=True, slots=True)
class S3SentinelBinding:
    """Control-plane proof for one exact retained cross-prefix object version."""

    schema_version: int
    bucket: str
    key: str
    version_id: str
    sha256: str
    content_length: int
    kms_key_id: str
    etag: str
    retention_mode: str
    retain_until: str

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str)
            for value in (
                self.bucket,
                self.key,
                self.version_id,
                self.sha256,
                self.kms_key_id,
                self.etag,
                self.retention_mode,
                self.retain_until,
            )
        ):
            raise DomainError("S3_SENTINEL_BINDING_INVALID", "sentinel binding types are invalid")
        try:
            retained = dt.datetime.fromisoformat(self.retain_until)
        except (TypeError, ValueError) as error:
            raise DomainError(
                "S3_SENTINEL_BINDING_INVALID", "sentinel retention timestamp is invalid"
            ) from error
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", self.bucket)
            or validate_object_key(self.key) != self.key
            or not 1 <= len(self.version_id) <= 1024
            or any(ord(character) < 0x20 for character in self.version_id)
            or not re.fullmatch(r"[a-f0-9]{64}", self.sha256)
            or type(self.content_length) is not int
            or not 1 <= self.content_length <= SENTINEL_MAX_BYTES
            or not re.fullmatch(
                r"arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:\d{12}:key/[A-Za-z0-9-]+",
                self.kms_key_id,
            )
            or not 1 <= len(self.etag) <= 256
            or self.retention_mode not in {"GOVERNANCE", "COMPLIANCE"}
            or retained.tzinfo is None
            or retained <= dt.datetime.now(dt.UTC)
        ):
            raise DomainError(
                "S3_SENTINEL_BINDING_INVALID", "immutable sentinel binding is invalid"
            )

    @property
    def binding_digest(self) -> str:
        return canonical_digest(asdict(self))

    def to_mapping(self) -> Mapping[str, Any]:
        return {**asdict(self), "binding_digest": self.binding_digest}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> S3SentinelBinding:
        expected = {
            "schema_version",
            "bucket",
            "key",
            "version_id",
            "sha256",
            "content_length",
            "kms_key_id",
            "etag",
            "retention_mode",
            "retain_until",
            "binding_digest",
        }
        if set(value) != expected:
            raise DomainError("S3_SENTINEL_BINDING_INVALID", "sentinel binding fields are invalid")
        schema_version = value["schema_version"]
        bucket = value["bucket"]
        key = value["key"]
        version_id = value["version_id"]
        sha256 = value["sha256"]
        content_length = value["content_length"]
        kms_key_id = value["kms_key_id"]
        etag = value["etag"]
        retention_mode = value["retention_mode"]
        retain_until = value["retain_until"]
        binding_digest = value["binding_digest"]
        if type(schema_version) is not int or type(content_length) is not int:
            raise DomainError("S3_SENTINEL_BINDING_INVALID", "sentinel binding types are invalid")
        if (
            not isinstance(bucket, str)
            or not isinstance(key, str)
            or not isinstance(version_id, str)
            or not isinstance(sha256, str)
            or not isinstance(kms_key_id, str)
            or not isinstance(etag, str)
            or not isinstance(retention_mode, str)
            or not isinstance(retain_until, str)
            or not isinstance(binding_digest, str)
        ):
            raise DomainError("S3_SENTINEL_BINDING_INVALID", "sentinel binding types are invalid")
        binding = cls(
            schema_version=schema_version,
            bucket=bucket,
            key=key,
            version_id=version_id,
            sha256=sha256,
            content_length=content_length,
            kms_key_id=kms_key_id,
            etag=etag,
            retention_mode=retention_mode,
            retain_until=retain_until,
        )
        if binding_digest != binding.binding_digest:
            raise DomainError("S3_SENTINEL_BINDING_INVALID", "sentinel binding digest is invalid")
        return binding


def workload_session(config: Mapping[str, Any], *, boto3_module: Any) -> Any:
    """Create a non-default AWS session from one explicit, private identity contract."""
    if set(config) != WORKLOAD_SESSION_KEYS:
        raise DomainError("WORKLOAD_IDENTITY_CONFIG_INVALID", "workload session fields are invalid")
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
    if not re.fullmatch(
        r"arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]+",
        role_arn,
    ) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+=,.@_-]{1,63}", session_name):
        raise DomainError("WORKLOAD_IDENTITY_CONFIG_INVALID", "web identity token input is unsafe")
    try:
        token = (
            read_private_file(
                token_file,
                maximum_bytes=1024 * 1024,
                code="WORKLOAD_IDENTITY_CONFIG_INVALID",
            )
            .decode("utf-8")
            .strip()
        )
    except UnicodeDecodeError as error:
        raise DomainError(
            "WORKLOAD_IDENTITY_CONFIG_INVALID", "web identity token must be UTF-8"
        ) from error
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
    if not all(
        credentials.get(name) for name in ("AccessKeyId", "SecretAccessKey", "SessionToken")
    ):
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
    direct = re.fullmatch(r"arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/(.+)", caller_arn)
    if direct:
        return caller_arn
    assumed = re.fullmatch(
        r"arn:(aws|aws-us-gov|aws-cn):sts::(\d{12}):assumed-role/(.+)/[^/]+",
        caller_arn,
    )
    if not assumed:
        raise DomainError("WORKLOAD_IDENTITY_INVALID", "STS caller is not an IAM role session")
    return f"arn:{assumed.group(1)}:iam::{assumed.group(2)}:role/{assumed.group(3)}"


def github_actions_caller_trust_contract(
    *,
    account_id: str,
    region: str,
    repository: str,
    repository_owner_id: str,
    repository_id: str,
    ref: str,
    environment: str,
    workflow: str,
) -> Mapping[str, Any]:
    """Build the one accepted GitHub Actions OIDC trust contract."""
    partition = aws_partition_for_region(region)
    audience = "sts.amazonaws.com.cn" if partition == "aws-cn" else IRSA_TOKEN_AUDIENCE
    owner, name = repository.split("/", 1) if "/" in repository else ("", "")
    expected_subject = (
        f"repo:{owner}@{repository_owner_id}/{name}@{repository_id}:"
        "environment:production-acceptance"
    )
    if (
        not re.fullmatch(r"\d{12}", account_id)
        or not GITHUB_REPOSITORY.fullmatch(repository)
        or not re.fullmatch(r"[1-9][0-9]*", repository_owner_id)
        or not re.fullmatch(r"[1-9][0-9]*", repository_id)
        or not GITHUB_BRANCH_REF.fullmatch(ref)
        or ref != "refs/heads/main"
        or environment != "production-acceptance"
        or workflow != "production-acceptance"
    ):
        raise DomainError(
            "AWS_CALLER_TRUST_CONTRACT_INVALID",
            "GitHub Actions caller trust coordinates are invalid",
        )
    return {
        "schema_version": 1,
        "provider_arn": (
            f"arn:{partition}:iam::{account_id}:oidc-provider/"
            f"{GITHUB_ACTIONS_OIDC_PROVIDER}"
        ),
        "audience": audience,
        "subject": expected_subject,
        "repository": repository,
        "repository_owner_id": repository_owner_id,
        "repository_id": repository_id,
        "ref": ref,
        "environment": environment,
        "workflow": workflow,
    }


def github_actions_caller_trust_is_exact(
    document: Mapping[str, Any],
    *,
    role_arn: str,
    contract: Mapping[str, Any],
) -> bool:
    """Accept one exact GitHub OIDC statement and no trust-policy widening."""
    role_match = IAM_ROLE_ARN.fullmatch(role_arn)
    provider_arn = contract.get("provider_arn")
    provider_match = (
        IAM_OIDC_PROVIDER_ARN.fullmatch(provider_arn)
        if isinstance(provider_arn, str)
        else None
    )
    if (
        set(contract)
        != {
            "schema_version",
            "provider_arn",
            "audience",
            "subject",
            "repository",
            "repository_owner_id",
            "repository_id",
            "ref",
            "environment",
            "workflow",
        }
        or contract.get("schema_version") != 1
        or role_match is None
        or provider_match is None
        or provider_match.group(1) != role_match.group(1)
        or provider_match.group(2) != role_match.group(2)
        or provider_match.group(3) != GITHUB_ACTIONS_OIDC_PROVIDER
        or contract.get("audience")
        != (
            "sts.amazonaws.com.cn"
            if role_match.group(1) == "aws-cn"
            else IRSA_TOKEN_AUDIENCE
        )
    ):
        return False
    provider = GITHUB_ACTIONS_OIDC_PROVIDER
    statements = _statements(document)
    if len(statements) != 1:
        return False
    statement = statements[0]
    principal = statement.get("Principal")
    return (
        set(statement).difference({"Sid"})
        == {"Effect", "Principal", "Action", "Condition"}
        and statement.get("Effect") == "Allow"
        and isinstance(principal, Mapping)
        and set(principal) == {"Federated"}
        and principal.get("Federated") == provider_arn
        and _string_set(statement.get("Action"))
        == {"sts:AssumeRoleWithWebIdentity"}
        and statement.get("Condition")
        == {
            "StringEquals": {
                f"{provider}:aud": contract.get("audience"),
                f"{provider}:sub": contract.get("subject"),
                f"{provider}:repository": contract.get("repository"),
                f"{provider}:repository_owner_id": contract.get(
                    "repository_owner_id"
                ),
                f"{provider}:repository_id": contract.get("repository_id"),
                f"{provider}:ref": contract.get("ref"),
                f"{provider}:environment": contract.get("environment"),
                f"{provider}:workflow": contract.get("workflow"),
            }
        }
    )


def iam_role_trust_is_exact(
    document: Mapping[str, Any],
    *,
    role_arn: str,
    expected_provider_arn: str,
    expected_subject: str,
) -> bool:
    match = IAM_ROLE_ARN.fullmatch(role_arn)
    provider_match = IAM_OIDC_PROVIDER_ARN.fullmatch(expected_provider_arn)
    if (
        match is None
        or provider_match is None
        or provider_match.group(1) != match.group(1)
        or provider_match.group(2) != match.group(2)
        or not re.fullmatch(
            r"system:serviceaccount:[a-z0-9](?:[-a-z0-9]*[a-z0-9])?:"
            r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?",
            expected_subject,
        )
    ):
        return False
    statements = _statements(document)
    if len(statements) != 1:
        return False
    statement = statements[0]
    if set(statement).difference({"Sid"}) != {
        "Effect",
        "Principal",
        "Action",
        "Condition",
    }:
        return False
    principal = statement.get("Principal")
    if not isinstance(principal, Mapping) or set(principal) != {"Federated"}:
        return False
    if principal.get("Federated") != expected_provider_arn:
        return False
    provider = provider_match.group(3)
    return (
        statement.get("Effect") == "Allow"
        and _string_set(statement.get("Action")) == {"sts:AssumeRoleWithWebIdentity"}
        and statement.get("Condition")
        == {
            "StringEquals": {
                f"{provider}:aud": IRSA_TOKEN_AUDIENCE,
                f"{provider}:sub": expected_subject,
            }
        }
    )


def inspect_iam_oidc_provider(
    iam_client: Any,
    *,
    provider_arn: str,
) -> tuple[str, bool]:
    """Read and bind the exact IAM OIDC provider used by the two IRSA roles."""
    match = IAM_OIDC_PROVIDER_ARN.fullmatch(provider_arn)
    if match is None:
        raise DomainError("AWS_IAM_OIDC_PROVIDER_INVALID", "IAM OIDC provider ARN is invalid")
    try:
        response = iam_client.get_open_id_connect_provider(
            OpenIDConnectProviderArn=provider_arn
        )
    except Exception as error:
        raise DomainError(
            "AWS_IAM_OIDC_PROVIDER_INVALID",
            "IAM OIDC provider could not be read",
        ) from error
    if not isinstance(response, Mapping):
        raise DomainError(
            "AWS_IAM_OIDC_PROVIDER_INVALID",
            "IAM OIDC provider response is invalid",
        )
    url = response.get("Url")
    client_ids = response.get("ClientIDList")
    thumbprints = response.get("ThumbprintList")
    if (
        not isinstance(url, str)
        or not isinstance(client_ids, list)
        or any(not isinstance(value, str) for value in client_ids)
        or len(client_ids) != len(set(client_ids))
        or not isinstance(thumbprints, list)
        or any(not isinstance(value, str) for value in thumbprints)
        or len(thumbprints) != len({value.lower() for value in thumbprints})
    ):
        raise DomainError(
            "AWS_IAM_OIDC_PROVIDER_INVALID",
            "IAM OIDC provider configuration is invalid",
        )
    normalized = {
        "schema_version": 1,
        "provider_arn": provider_arn,
        "issuer": f"https://{url}",
        "client_ids": sorted(client_ids),
        "thumbprints": sorted(value.lower() for value in thumbprints),
    }
    exact = (
        url == match.group(3)
        and client_ids == [IRSA_TOKEN_AUDIENCE]
        and 1 <= len(thumbprints) <= 5
        and all(OIDC_THUMBPRINT.fullmatch(value) for value in thumbprints)
    )
    return canonical_digest(normalized), exact


def iam_role_permissions_are_least_privilege(
    documents: tuple[Mapping[str, Any], ...],
    *,
    bucket: str,
    prefix: str,
    kms_key_arn: str,
    purpose: str,
    region: str,
    account_id: str,
) -> bool:
    if purpose not in {"backup", "snapshot"}:
        return False
    kms_match = re.fullmatch(
        rf"arn:(aws|aws-us-gov|aws-cn):kms:{re.escape(region)}:"
        rf"{re.escape(account_id)}:key/[A-Za-z0-9-]+",
        kms_key_arn,
    )
    if kms_match is None:
        return False
    statements = tuple(statement for document in documents for statement in _statements(document))
    if len(statements) != 4:
        return False
    bucket_arn = f"arn:{kms_match.group(1)}:s3:::{bucket}"
    object_arn = f"{bucket_arn}/{prefix.rstrip('/')}/*"
    dns_suffix = "amazonaws.com.cn" if kms_match.group(1) == "aws-cn" else "amazonaws.com"
    expected_kms_condition = {
        "StringEquals": {
            "kms:CallerAccount": account_id,
            "kms:EncryptionContext:application": "industrial-shadow",
            "kms:EncryptionContext:purpose": purpose,
            "kms:EncryptionContext:aws:s3:arn": bucket_arn,
            "kms:ViaService": f"s3.{region}.{dns_suffix}",
        }
    }
    matched = {"read": False, "write": False, "multipart_abort": False, "kms": False}
    for statement in statements:
        if statement.get("Effect") != "Allow" or any(
            name in statement for name in ("NotAction", "NotResource", "Principal")
        ):
            return False
        actions = _string_set(statement.get("Action"))
        resources = _string_set(statement.get("Resource"))
        condition = statement.get("Condition")
        keys = set(statement).difference({"Sid"})
        if (
            actions == WORKLOAD_S3_READ_ACTIONS
            and resources == {object_arn}
            and condition is None
            and keys == {"Effect", "Action", "Resource"}
        ):
            if matched["read"]:
                return False
            matched["read"] = True
        elif (
            actions == WORKLOAD_S3_WRITE_ACTIONS
            and resources == {object_arn}
            and condition is None
            and keys == {"Effect", "Action", "Resource"}
        ):
            if matched["write"]:
                return False
            matched["write"] = True
        elif (
            actions == WORKLOAD_S3_MULTIPART_ABORT_ACTIONS
            and resources == {object_arn}
            and condition is None
            and keys == {"Effect", "Action", "Resource"}
        ):
            if matched["multipart_abort"]:
                return False
            matched["multipart_abort"] = True
        elif (
            actions == WORKLOAD_KMS_ACTIONS
            and resources == {kms_key_arn}
            and condition == expected_kms_condition
            and keys == {"Effect", "Action", "Resource", "Condition"}
        ):
            if matched["kms"]:
                return False
            matched["kms"] = True
        else:
            return False
    return all(matched.values())


def iam_control_plane_caller_permissions_are_least_privilege(
    documents: tuple[Mapping[str, Any], ...],
    *,
    bucket: str,
    prefixes: Mapping[str, str],
    sentinel_keys: Mapping[str, str],
    kms_key_arn: str,
    caller_role_arn: str,
    kms_admin_role_arn: str,
    storage_role_arns: Mapping[str, str],
    oidc_provider_arn: str,
    attached_policy_arns: frozenset[str],
    region: str,
    account_id: str,
) -> bool:
    """Reject every caller permission outside the live acceptance read/probe path."""
    if (
        set(prefixes) != {"acceptance", "backup", "snapshot"}
        or set(sentinel_keys) != {"backup", "snapshot"}
        or set(storage_role_arns) != {"backup", "snapshot"}
    ):
        return False
    kms_match = re.fullmatch(
        rf"arn:(aws|aws-us-gov|aws-cn):kms:{re.escape(region)}:"
        rf"{re.escape(account_id)}:key/[A-Za-z0-9-]+",
        kms_key_arn,
    )
    provider_match = IAM_OIDC_PROVIDER_ARN.fullmatch(oidc_provider_arn)
    role_arns = {
        "caller": caller_role_arn,
        "kms_admin": kms_admin_role_arn,
        **storage_role_arns,
    }
    role_matches = {name: IAM_ROLE_ARN.fullmatch(arn) for name, arn in role_arns.items()}
    if (
        kms_match is None
        or provider_match is None
        or provider_match.group(1) != kms_match.group(1)
        or provider_match.group(2) != account_id
        or len(set(role_arns.values())) != 4
        or any(
            match is None
            or match.group(1) != kms_match.group(1)
            or match.group(2) != account_id
            for match in role_matches.values()
        )
        or any(
            not re.fullmatch(
                rf"arn:{re.escape(kms_match.group(1))}:iam::(?:aws|{re.escape(account_id)}):"
                r"policy/[A-Za-z0-9+=,.@_/-]+",
                arn,
            )
            for arn in attached_policy_arns
        )
    ):
        return False
    try:
        normalized_prefixes = {
            name: validate_object_key(value.rstrip("/")) + "/"
            for name, value in prefixes.items()
        }
        normalized_sentinels = {
            name: validate_object_key(value) for name, value in sentinel_keys.items()
        }
    except DomainError:
        return False
    if normalized_prefixes != dict(prefixes) or normalized_sentinels != dict(sentinel_keys):
        return False
    if (
        not normalized_sentinels["backup"].startswith(normalized_prefixes["snapshot"])
        or not normalized_sentinels["snapshot"].startswith(normalized_prefixes["backup"])
    ):
        return False

    partition = kms_match.group(1)
    bucket_arn = f"arn:{partition}:s3:::{bucket}"
    acceptance_object_arn = (
        f"{bucket_arn}/{normalized_prefixes['acceptance'].rstrip('/')}/*"
    )
    sentinel_arns = {
        f"{bucket_arn}/{normalized_sentinels[name]}"
        for name in ("backup", "snapshot")
    }
    dns_suffix = "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com"

    def kms_condition(identity: str) -> Mapping[str, Any]:
        purpose = "probe" if identity == "acceptance" else identity
        return {
            "StringEquals": {
                "kms:CallerAccount": account_id,
                "kms:EncryptionContext:application": "industrial-shadow",
                "kms:EncryptionContext:purpose": purpose,
                "kms:EncryptionContext:aws:s3:arn": bucket_arn,
                "kms:ViaService": f"s3.{region}.{dns_suffix}",
            }
        }

    matched = {
        "s3_bucket_read": False,
        "s3_acceptance_list": False,
        "s3_acceptance_objects": False,
        "s3_sentinel_read": False,
        "kms_control_read": False,
        "kms_acceptance_data": False,
        "kms_backup_audit": False,
        "kms_snapshot_audit": False,
        "iam_role_read": False,
        "iam_role_policy_read": False,
        "iam_oidc_read": False,
        "iam_managed_policy_read": not attached_policy_arns,
    }
    statements = tuple(statement for document in documents for statement in _statements(document))
    expected_count = 11 + int(bool(attached_policy_arns))
    if len(statements) != expected_count:
        return False
    for statement in statements:
        if statement.get("Effect") != "Allow" or any(
            name in statement for name in ("NotAction", "NotResource", "Principal")
        ):
            return False
        actions = _string_set(statement.get("Action"))
        resources = _string_set(statement.get("Resource"))
        condition = statement.get("Condition")
        keys = set(statement).difference({"Sid"})
        name = ""
        if (
            actions == CONTROL_PLANE_S3_BUCKET_READ_ACTIONS
            and resources == {bucket_arn}
            and condition is None
            and keys == {"Effect", "Action", "Resource"}
        ):
            name = "s3_bucket_read"
        elif (
            actions == CONTROL_S3_LIST_ACTIONS
            and resources == {bucket_arn}
            and condition
            == {
                "StringLike": {
                    "s3:prefix": f"{normalized_prefixes['acceptance'].rstrip('/')}/*"
                }
            }
            and keys == {"Effect", "Action", "Resource", "Condition"}
        ):
            name = "s3_acceptance_list"
        elif (
            actions == CONTROL_PLANE_S3_ACCEPTANCE_OBJECT_ACTIONS
            and resources == {acceptance_object_arn}
            and condition is None
            and keys == {"Effect", "Action", "Resource"}
        ):
            name = "s3_acceptance_objects"
        elif (
            actions == WORKLOAD_S3_READ_ACTIONS
            and resources == sentinel_arns
            and condition is None
            and keys == {"Effect", "Action", "Resource"}
        ):
            name = "s3_sentinel_read"
        elif (
            actions == CONTROL_KMS_READ_ACTIONS
            and resources == {kms_key_arn}
            and condition is None
            and keys == {"Effect", "Action", "Resource"}
        ):
            name = "kms_control_read"
        elif (
            actions == WORKLOAD_KMS_ACTIONS
            and resources == {kms_key_arn}
            and condition == kms_condition("acceptance")
            and keys == {"Effect", "Action", "Resource", "Condition"}
        ):
            name = "kms_acceptance_data"
        elif (
            actions == RESTORE_KMS_ACTIONS
            and resources == {kms_key_arn}
            and condition == kms_condition("backup")
            and keys == {"Effect", "Action", "Resource", "Condition"}
        ):
            name = "kms_backup_audit"
        elif (
            actions == RESTORE_KMS_ACTIONS
            and resources == {kms_key_arn}
            and condition == kms_condition("snapshot")
            and keys == {"Effect", "Action", "Resource", "Condition"}
        ):
            name = "kms_snapshot_audit"
        elif (
            actions == CONTROL_PLANE_IAM_ROLE_READ_ACTIONS
            and resources == set(role_arns.values())
            and condition is None
            and keys == {"Effect", "Action", "Resource"}
        ):
            name = "iam_role_read"
        elif (
            actions == CONTROL_PLANE_IAM_ROLE_POLICY_READ_ACTIONS
            and resources
            == {caller_role_arn, storage_role_arns["backup"], storage_role_arns["snapshot"]}
            and condition is None
            and keys == {"Effect", "Action", "Resource"}
        ):
            name = "iam_role_policy_read"
        elif (
            actions == CONTROL_PLANE_IAM_OIDC_READ_ACTIONS
            and resources == {oidc_provider_arn}
            and condition is None
            and keys == {"Effect", "Action", "Resource"}
        ):
            name = "iam_oidc_read"
        elif (
            attached_policy_arns
            and actions == CONTROL_PLANE_IAM_MANAGED_POLICY_READ_ACTIONS
            and resources == attached_policy_arns
            and condition is None
            and keys == {"Effect", "Action", "Resource"}
        ):
            name = "iam_managed_policy_read"
        if not name or matched[name]:
            return False
        matched[name] = True
    return all(matched.values())


def kms_key_policy_is_least_privilege(
    document: Mapping[str, Any],
    *,
    control_plane_caller_arn: str,
    kms_admin_role_arn: str,
    role_arns: Mapping[str, str],
    bucket: str,
    prefixes: Mapping[str, str],
    kms_key_arn: str,
    region: str,
    account_id: str,
) -> bool:
    if (
        set(role_arns) != {"backup", "snapshot"}
        or set(prefixes) != {"acceptance", "backup", "snapshot"}
        or len({control_plane_caller_arn, kms_admin_role_arn, *role_arns.values()}) != 4
    ):
        return False
    kms_match = re.fullmatch(
        rf"arn:(aws|aws-us-gov|aws-cn):kms:{re.escape(region)}:"
        rf"{re.escape(account_id)}:key/[A-Za-z0-9-]+",
        kms_key_arn,
    )
    caller_match = IAM_ROLE_ARN.fullmatch(control_plane_caller_arn)
    admin_match = IAM_ROLE_ARN.fullmatch(kms_admin_role_arn)
    if (
        kms_match is None
        or caller_match is None
        or admin_match is None
        or caller_match.group(1) != kms_match.group(1)
        or caller_match.group(2) != account_id
        or admin_match.group(1) != kms_match.group(1)
        or admin_match.group(2) != account_id
    ):
        return False
    dns_suffix = "amazonaws.com.cn" if kms_match.group(1) == "aws-cn" else "amazonaws.com"
    identity_arns = {"acceptance": control_plane_caller_arn, **role_arns}
    def expected_condition(_prefix: str, purpose: str) -> Mapping[str, Any]:
        return {
            "StringEquals": {
                "kms:CallerAccount": account_id,
                "kms:EncryptionContext:application": "industrial-shadow",
                "kms:EncryptionContext:purpose": purpose,
                "kms:EncryptionContext:aws:s3:arn": (
                    f"arn:{kms_match.group(1)}:s3:::{bucket}"
                ),
                "kms:ViaService": f"s3.{region}.{dns_suffix}",
            }
        }

    statements = _statements(document)
    if len(statements) != 7 or any(statement.get("Effect") != "Allow" for statement in statements):
        return False
    matched = {"acceptance": False, "backup": False, "snapshot": False}
    control_read_seen = False
    admin_seen = False
    audit_reads = {"backup": False, "snapshot": False}
    for statement in statements:
        if any(name in statement for name in ("NotAction", "NotPrincipal", "NotResource")):
            return False
        principal = statement.get("Principal")
        if principal == "*" or (
            isinstance(principal, Mapping) and "*" in _string_set(principal.get("AWS"))
        ):
            return False
        principals = (
            _string_set(principal.get("AWS"))
            if isinstance(principal, Mapping) and set(principal) == {"AWS"}
            else frozenset()
        )
        if principals == {kms_admin_role_arn}:
            if (
                _string_set(statement.get("Action")) != KMS_ADMIN_ACTIONS
                or _string_set(statement.get("Resource")) != {"*"}
                or statement.get("Condition") is not None
                or set(statement).difference({"Sid"})
                != {"Effect", "Principal", "Action", "Resource"}
                or admin_seen
            ):
                return False
            admin_seen = True
            continue
        identity_statement = False
        for identity, role_arn in identity_arns.items():
            if role_arn not in principals:
                continue
            identity_statement = True
            actions = _string_set(statement.get("Action"))
            if identity == "acceptance" and actions == CONTROL_KMS_READ_ACTIONS:
                if (
                    principals != {role_arn}
                    or _string_set(statement.get("Resource")) != {"*"}
                    or statement.get("Condition") is not None
                    or set(statement).difference({"Sid"})
                    != {"Effect", "Principal", "Action", "Resource"}
                    or control_read_seen
                ):
                    return False
                control_read_seen = True
                continue
            if identity == "acceptance" and actions == RESTORE_KMS_ACTIONS:
                audit_matches = [
                    name
                    for name in ("backup", "snapshot")
                    if statement.get("Condition")
                    == expected_condition(prefixes[name], name)
                ]
                if (
                    len(audit_matches) != 1
                    or principals != {role_arn}
                    or _string_set(statement.get("Resource")) != {"*"}
                    or set(statement).difference({"Sid"})
                    != {"Effect", "Principal", "Action", "Resource", "Condition"}
                    or audit_reads[audit_matches[0]]
                ):
                    return False
                audit_reads[audit_matches[0]] = True
                continue
            purpose = "probe" if identity == "acceptance" else identity
            if (
                principals != {role_arn}
                or actions != WORKLOAD_KMS_ACTIONS
                or _string_set(statement.get("Resource")) != {"*"}
                or statement.get("Condition")
                != expected_condition(prefixes[identity], purpose)
                or set(statement).difference({"Sid"})
                != {"Effect", "Principal", "Action", "Resource", "Condition"}
                or matched[identity]
            ):
                return False
            matched[identity] = True
        if not identity_statement:
            return False
    return (
        admin_seen
        and control_read_seen
        and all(audit_reads.values())
        and all(matched.values())
    )


def bucket_policy_is_workload_bound(
    document: Mapping[str, Any],
    *,
    bucket: str,
    control_plane_caller_arn: str,
    role_arns: Mapping[str, str],
    prefixes: Mapping[str, str],
    sentinel_keys: Mapping[str, str],
    kms_key_arn: str,
) -> bool:
    if (
        set(role_arns) != {"backup", "snapshot"}
        or set(prefixes) != {"acceptance", "backup", "snapshot"}
        or set(sentinel_keys) != {"backup", "snapshot"}
        or len({control_plane_caller_arn, *role_arns.values()}) != 3
    ):
        return False
    try:
        normalized_sentinels = {
            name: validate_object_key(value) for name, value in sentinel_keys.items()
        }
    except DomainError:
        return False
    if normalized_sentinels != dict(sentinel_keys) or (
        not normalized_sentinels["backup"].startswith(prefixes["snapshot"])
        or not normalized_sentinels["snapshot"].startswith(prefixes["backup"])
    ):
        return False
    identity_arns = {"acceptance": control_plane_caller_arn, **role_arns}
    role_matches = {
        identity: IAM_ROLE_ARN.fullmatch(role_arn) for identity, role_arn in identity_arns.items()
    }
    kms_match = re.fullmatch(
        r"arn:(aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:(\d{12}):key/[A-Za-z0-9-]+",
        kms_key_arn,
    )
    if kms_match is None or any(match is None for match in role_matches.values()):
        return False
    if any(
        match is None
        or match.group(1) != kms_match.group(1)
        or match.group(2) != kms_match.group(2)
        for match in role_matches.values()
    ):
        return False
    partition = kms_match.group(1)
    bucket_arn = f"arn:{partition}:s3:::{bucket}"
    tls_deny_seen = False
    protected_mutation_denies = {"backup": False, "snapshot": False}
    encryption_header_denies = {
        f"{identity}_{guard}": False
        for identity in ("acceptance", "backup", "snapshot")
        for guard in ("algorithm_mismatch", "key_mismatch", "kms_key_missing")
    }
    encryption_header_conditions = {
        "algorithm_mismatch": {
            "StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"},
            "Null": {"s3:x-amz-server-side-encryption": "false"},
        },
        "key_mismatch": {
            "StringNotEquals": {
                "s3:x-amz-server-side-encryption-aws-kms-key-id": kms_key_arn
            },
            "Null": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "false"},
        },
        "kms_key_missing": {
            "StringEquals": {"s3:x-amz-server-side-encryption": "aws:kms"},
            "Null": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "true"},
        },
    }
    matched = {
        f"{identity}_{operation}": False
        for identity in ("acceptance", "backup", "snapshot")
        for operation in (
            ("read", "write")
            if identity == "acceptance"
            else ("read", "write", "multipart_abort")
        )
    }
    matched.update(
        {
            "acceptance_backup_read": False,
            "acceptance_snapshot_read": False,
            "acceptance_version_list": False,
        }
    )
    statements = _statements(document)
    if len(statements) != 23:
        return False
    for statement in statements:
        effect = statement.get("Effect")
        keys = set(statement).difference({"Sid"})
        if effect == "Deny":
            actions = _string_set(statement.get("Action"))
            resources = _string_set(statement.get("Resource"))
            condition = statement.get("Condition")
            if (
                not tls_deny_seen
                and keys == {"Effect", "Principal", "Action", "Resource", "Condition"}
                and statement.get("Principal") == "*"
                and actions == {"s3:*"}
                and resources == {bucket_arn, f"{bucket_arn}/*"}
                and condition == {"Bool": {"aws:SecureTransport": "false"}}
            ):
                tls_deny_seen = True
                continue
            encryption_matches = [
                (identity, guard)
                for identity in ("acceptance", "backup", "snapshot")
                for guard, expected_condition in encryption_header_conditions.items()
                if resources
                == {f"{bucket_arn}/{prefixes[identity].rstrip('/')}/*"}
                and condition == expected_condition
            ]
            if encryption_matches:
                identity, guard = encryption_matches[0]
                name = f"{identity}_{guard}"
                if (
                    len(encryption_matches) != 1
                    or keys != {"Effect", "Principal", "Action", "Resource", "Condition"}
                    or statement.get("Principal") != "*"
                    or actions != WORKLOAD_S3_WRITE_ACTIONS
                    or encryption_header_denies[name]
                ):
                    return False
                encryption_header_denies[name] = True
                continue
            protected_matches = [
                name
                for name in ("backup", "snapshot")
                if resources
                == {f"{bucket_arn}/{prefixes[name].rstrip('/')}/*"}
                and condition
                == {"ArnNotEquals": {"aws:PrincipalArn": role_arns[name]}}
            ]
            if (
                len(protected_matches) != 1
                or keys != {"Effect", "Principal", "Action", "Resource", "Condition"}
                or statement.get("Principal") != "*"
                or actions != PROTECTED_S3_MUTATION_ACTIONS
                or protected_mutation_denies[protected_matches[0]]
            ):
                return False
            protected_mutation_denies[protected_matches[0]] = True
            continue
        if (
            effect != "Allow"
            or keys
            not in (
                {"Effect", "Principal", "Action", "Resource"},
                {"Effect", "Principal", "Action", "Resource", "Condition"},
            )
            or any(name in statement for name in ("NotAction", "NotPrincipal", "NotResource"))
        ):
            return False
        principal = statement.get("Principal")
        principals = (
            _string_set(principal.get("AWS"))
            if isinstance(principal, Mapping) and set(principal) == {"AWS"}
            else frozenset()
        )
        identities = [
            identity for identity, role_arn in identity_arns.items() if principals == {role_arn}
        ]
        if len(identities) != 1:
            return False
        identity = identities[0]
        object_arn = f"{bucket_arn}/{prefixes[identity].rstrip('/')}/*"
        actions = _string_set(statement.get("Action"))
        resources = _string_set(statement.get("Resource"))
        if (
            identity == "acceptance"
            and actions == CONTROL_S3_LIST_ACTIONS
            and resources == {bucket_arn}
            and statement.get("Condition")
            == {
                "StringLike": {
                    "s3:prefix": f"{prefixes['acceptance'].rstrip('/')}/*"
                }
            }
            and keys == {"Effect", "Principal", "Action", "Resource", "Condition"}
        ):
            name = "acceptance_version_list"
        elif (
            identity == "acceptance"
            and actions == WORKLOAD_S3_READ_ACTIONS
            and resources != {object_arn}
        ):
            audit_resources = {
                "backup": f"{bucket_arn}/{prefixes['backup'].rstrip('/')}/*",
                "snapshot": f"{bucket_arn}/{normalized_sentinels['backup']}",
            }
            audit_names = [name for name, resource in audit_resources.items() if resources == {resource}]
            if (
                len(audit_names) != 1
                or statement.get("Condition") is not None
                or keys != {"Effect", "Principal", "Action", "Resource"}
            ):
                return False
            name = f"acceptance_{audit_names[0]}_read"
        elif (
            actions
            == (
                CONTROL_PLANE_S3_ACCEPTANCE_READ_ACTIONS
                if identity == "acceptance"
                else WORKLOAD_S3_READ_ACTIONS
            )
            and resources == {object_arn}
            and statement.get("Condition") is None
            and keys == {"Effect", "Principal", "Action", "Resource"}
        ):
            name = f"{identity}_read"
        elif (
            actions == WORKLOAD_S3_WRITE_ACTIONS
            and resources == {object_arn}
            and statement.get("Condition") is None
            and keys == {"Effect", "Principal", "Action", "Resource"}
        ):
            name = f"{identity}_write"
        elif (
            identity != "acceptance"
            and actions == WORKLOAD_S3_MULTIPART_ABORT_ACTIONS
            and resources == {object_arn}
            and statement.get("Condition") is None
            and keys == {"Effect", "Principal", "Action", "Resource"}
        ):
            name = f"{identity}_multipart_abort"
        else:
            return False
        if matched[name]:
            return False
        matched[name] = True
    return (
        tls_deny_seen
        and all(protected_mutation_denies.values())
        and all(encryption_header_denies.values())
        and all(matched.values())
    )


def _inspect_iam_role_trust(
    iam_client: Any,
    *,
    role_arn: str,
    account_id: str,
) -> tuple[Mapping[str, Any], Mapping[str, Any], str]:
    match = IAM_ROLE_ARN.fullmatch(role_arn)
    if match is None or match.group(2) != account_id:
        raise DomainError("AWS_IAM_ROLE_INVALID", "IAM role ARN is invalid")
    role_name = match.group(3).rsplit("/", 1)[-1]
    try:
        role = iam_client.get_role(RoleName=role_name).get("Role", {})
    except Exception as error:
        raise DomainError("AWS_IAM_ROLE_INVALID", "IAM role could not be read") from error
    if not isinstance(role, Mapping) or role.get("Arn") != role_arn:
        raise DomainError("AWS_IAM_ROLE_INVALID", "IAM role identity drifted")
    trust = normalize_aws_policy(role.get("AssumeRolePolicyDocument", {}))
    return role, trust, canonical_digest(trust)


def inspect_iam_role_trust_policy(
    iam_client: Any,
    *,
    role_arn: str,
    account_id: str,
) -> str:
    """Read the exact trust policy for a separately approved IAM role."""
    _role, _trust, digest = _inspect_iam_role_trust(
        iam_client,
        role_arn=role_arn,
        account_id=account_id,
    )
    return digest


def inspect_iam_storage_role(
    iam_client: Any,
    *,
    role_arn: str,
    expected_provider_arn: str,
    expected_subject: str,
    bucket: str,
    prefix: str,
    kms_key_arn: str,
    purpose: str,
    region: str,
    account_id: str,
) -> tuple[str, str, str, bool, bool]:
    match = IAM_ROLE_ARN.fullmatch(role_arn)
    if match is None or match.group(2) != account_id:
        raise DomainError("AWS_IAM_ROLE_INVALID", "storage IAM role ARN is invalid")
    role_name = match.group(3).rsplit("/", 1)[-1]
    role, trust, trust_digest = _inspect_iam_role_trust(
        iam_client,
        role_arn=role_arn,
        account_id=account_id,
    )
    trust_statements = _statements(trust)
    trust_principal = trust_statements[0].get("Principal", {}) if len(trust_statements) == 1 else {}
    observed_provider_arn = (
        str(trust_principal.get("Federated", "")) if isinstance(trust_principal, Mapping) else ""
    )

    inline_response = iam_client.list_role_policies(RoleName=role_name, MaxItems=100)
    attached_response = iam_client.list_attached_role_policies(
        RoleName=role_name,
        MaxItems=100,
    )
    if (
        inline_response.get("IsTruncated") is True
        or attached_response.get("IsTruncated") is True
        or inline_response.get("Marker")
        or attached_response.get("Marker")
    ):
        raise DomainError(
            "AWS_IAM_POLICY_INVALID",
            "storage IAM role policy inventory exceeds the bounded probe",
        )
    inline_names = inline_response.get("PolicyNames", ())
    attached_values = attached_response.get("AttachedPolicies", ())
    if (
        not isinstance(inline_names, list)
        or any(not isinstance(name, str) or not name for name in inline_names)
        or len(inline_names) != len(set(inline_names))
        or not isinstance(attached_values, list)
        or any(not isinstance(item, Mapping) for item in attached_values)
    ):
        raise DomainError("AWS_IAM_POLICY_INVALID", "storage IAM policy inventory is invalid")

    documents: list[Mapping[str, Any]] = []
    inline_records: list[Mapping[str, Any]] = []
    for name in sorted(inline_names):
        response = iam_client.get_role_policy(RoleName=role_name, PolicyName=name)
        document = normalize_aws_policy(response.get("PolicyDocument", {}))
        documents.append(document)
        inline_records.append({"name": name, "document": document})

    attached_records: list[Mapping[str, Any]] = []
    attached_arns: set[str] = set()
    for item in attached_values:
        policy_arn = str(item.get("PolicyArn", ""))
        policy_match = re.fullmatch(
            r"arn:(aws|aws-us-gov|aws-cn):iam::(?:aws|\d{12}):policy/"
            r"[A-Za-z0-9+=,.@_/-]+",
            policy_arn,
        )
        if (
            policy_match is None
            or policy_match.group(1) != match.group(1)
            or policy_arn in attached_arns
        ):
            raise DomainError("AWS_IAM_POLICY_INVALID", "attached IAM policy ARN is invalid")
        attached_arns.add(policy_arn)
        policy = iam_client.get_policy(PolicyArn=policy_arn).get("Policy", {})
        version_id = str(policy.get("DefaultVersionId", ""))
        if policy.get("Arn") != policy_arn or not re.fullmatch(r"v[1-9][0-9]*", version_id):
            raise DomainError("AWS_IAM_POLICY_INVALID", "managed IAM policy version is invalid")
        version = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id,
        ).get("PolicyVersion", {})
        if (
            version.get("VersionId") != version_id
            or version.get("IsDefaultVersion") is not True
        ):
            raise DomainError("AWS_IAM_POLICY_INVALID", "managed IAM policy version drifted")
        document = normalize_aws_policy(version.get("Document", {}))
        documents.append(document)
        attached_records.append({"arn": policy_arn, "version_id": version_id, "document": document})

    permissions_bundle = {
        "schema_version": 1,
        "role_arn": role_arn,
        "permissions_boundary": role.get("PermissionsBoundary") or None,
        "inline_policies": inline_records,
        "attached_policies": sorted(
            attached_records,
            key=lambda value: str(value["arn"]),
        ),
    }
    permissions_digest = canonical_digest(permissions_bundle)
    trust_exact = iam_role_trust_is_exact(
        trust,
        role_arn=role_arn,
        expected_provider_arn=expected_provider_arn,
        expected_subject=expected_subject,
    )
    permissions_exact = role.get("PermissionsBoundary") is None and (
        iam_role_permissions_are_least_privilege(
            tuple(documents),
            bucket=bucket,
            prefix=prefix,
            kms_key_arn=kms_key_arn,
            purpose=purpose,
            region=region,
            account_id=account_id,
        )
    )
    return (
        trust_digest,
        permissions_digest,
        observed_provider_arn,
        trust_exact,
        permissions_exact,
    )


def inspect_iam_control_plane_caller_role(
    iam_client: Any,
    *,
    role_arn: str,
    kms_admin_role_arn: str,
    storage_role_arns: Mapping[str, str],
    oidc_provider_arn: str,
    bucket: str,
    prefixes: Mapping[str, str],
    sentinel_keys: Mapping[str, str],
    kms_key_arn: str,
    region: str,
    account_id: str,
    trust_contract: Mapping[str, Any],
) -> tuple[str, str, bool, bool]:
    """Bind the caller trust verbatim and enforce an exact read/probe IAM policy."""
    match = IAM_ROLE_ARN.fullmatch(role_arn)
    if match is None or match.group(2) != account_id:
        raise DomainError("AWS_IAM_ROLE_INVALID", "control-plane caller role ARN is invalid")
    role_name = match.group(3).rsplit("/", 1)[-1]
    role, _trust, trust_digest = _inspect_iam_role_trust(
        iam_client,
        role_arn=role_arn,
        account_id=account_id,
    )
    inline_response = iam_client.list_role_policies(RoleName=role_name, MaxItems=100)
    attached_response = iam_client.list_attached_role_policies(
        RoleName=role_name,
        MaxItems=100,
    )
    if (
        not isinstance(inline_response, Mapping)
        or not isinstance(attached_response, Mapping)
        or inline_response.get("IsTruncated") is True
        or attached_response.get("IsTruncated") is True
        or inline_response.get("Marker")
        or attached_response.get("Marker")
    ):
        raise DomainError(
            "AWS_IAM_POLICY_INVALID",
            "control-plane caller policy inventory exceeds the bounded probe",
        )
    inline_names = inline_response.get("PolicyNames", ())
    attached_values = attached_response.get("AttachedPolicies", ())
    if (
        not isinstance(inline_names, list)
        or any(not isinstance(name, str) or not name for name in inline_names)
        or len(inline_names) != len(set(inline_names))
        or not isinstance(attached_values, list)
        or any(not isinstance(item, Mapping) for item in attached_values)
    ):
        raise DomainError(
            "AWS_IAM_POLICY_INVALID", "control-plane caller policy inventory is invalid"
        )

    documents: list[Mapping[str, Any]] = []
    inline_records: list[Mapping[str, Any]] = []
    for name in sorted(inline_names):
        response = iam_client.get_role_policy(RoleName=role_name, PolicyName=name)
        document = normalize_aws_policy(response.get("PolicyDocument", {}))
        documents.append(document)
        inline_records.append({"name": name, "document": document})

    attached_records: list[Mapping[str, Any]] = []
    attached_arns: set[str] = set()
    for item in attached_values:
        policy_name = item.get("PolicyName")
        policy_arn = item.get("PolicyArn")
        if (
            not isinstance(policy_name, str)
            or not policy_name
            or not isinstance(policy_arn, str)
            or not re.fullmatch(
                rf"arn:{re.escape(match.group(1))}:iam::(?:aws|{re.escape(account_id)}):"
                r"policy/[A-Za-z0-9+=,.@_/-]+",
                policy_arn,
            )
            or policy_arn in attached_arns
        ):
            raise DomainError(
                "AWS_IAM_POLICY_INVALID", "attached caller IAM policy is invalid"
            )
        attached_arns.add(policy_arn)
        policy = iam_client.get_policy(PolicyArn=policy_arn).get("Policy", {})
        version_id = str(policy.get("DefaultVersionId", ""))
        if (
            policy.get("Arn") != policy_arn
            or policy.get("PolicyName") != policy_name
            or not re.fullmatch(r"v[1-9][0-9]*", version_id)
        ):
            raise DomainError(
                "AWS_IAM_POLICY_INVALID", "managed caller IAM policy identity drifted"
            )
        version = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id,
        ).get("PolicyVersion", {})
        if version.get("VersionId") != version_id or version.get("IsDefaultVersion") is not True:
            raise DomainError(
                "AWS_IAM_POLICY_INVALID", "managed caller IAM policy version drifted"
            )
        document = normalize_aws_policy(version.get("Document", {}))
        documents.append(document)
        attached_records.append(
            {
                "arn": policy_arn,
                "name": policy_name,
                "version_id": version_id,
                "document": document,
            }
        )
    storage_attached_arns: set[str] = set()
    for storage_role_arn in storage_role_arns.values():
        storage_match = IAM_ROLE_ARN.fullmatch(storage_role_arn)
        if (
            storage_match is None
            or storage_match.group(1) != match.group(1)
            or storage_match.group(2) != account_id
        ):
            raise DomainError(
                "AWS_IAM_ROLE_INVALID", "storage IAM role ARN is invalid"
            )
        storage_role_name = storage_match.group(3).rsplit("/", 1)[-1]
        storage_attached_response = iam_client.list_attached_role_policies(
            RoleName=storage_role_name,
            MaxItems=100,
        )
        if (
            not isinstance(storage_attached_response, Mapping)
            or storage_attached_response.get("IsTruncated") is True
            or storage_attached_response.get("Marker")
        ):
            raise DomainError(
                "AWS_IAM_POLICY_INVALID",
                "storage IAM attached policy inventory exceeds the bounded probe",
            )
        storage_attached_values = storage_attached_response.get(
            "AttachedPolicies", ()
        )
        if not isinstance(storage_attached_values, list) or any(
            not isinstance(item, Mapping) for item in storage_attached_values
        ):
            raise DomainError(
                "AWS_IAM_POLICY_INVALID",
                "storage IAM attached policy inventory is invalid",
            )
        per_role_arns: set[str] = set()
        for item in storage_attached_values:
            policy_name = item.get("PolicyName")
            policy_arn = item.get("PolicyArn")
            if (
                not isinstance(policy_name, str)
                or not policy_name
                or not isinstance(policy_arn, str)
                or not re.fullmatch(
                    rf"arn:{re.escape(match.group(1))}:iam::"
                    rf"(?:aws|{re.escape(account_id)}):"
                    r"policy/[A-Za-z0-9+=,.@_/-]+",
                    policy_arn,
                )
                or policy_arn in per_role_arns
            ):
                raise DomainError(
                    "AWS_IAM_POLICY_INVALID",
                    "attached storage IAM policy is invalid",
                )
            per_role_arns.add(policy_arn)
        storage_attached_arns.update(per_role_arns)
    permissions_bundle = {
        "schema_version": 1,
        "role_arn": role_arn,
        "permissions_boundary": role.get("PermissionsBoundary") or None,
        "inline_policies": inline_records,
        "attached_policies": sorted(
            attached_records,
            key=lambda value: str(value["arn"]),
        ),
    }
    permissions_digest = canonical_digest(permissions_bundle)
    trust_exact = github_actions_caller_trust_is_exact(
        _trust,
        role_arn=role_arn,
        contract=trust_contract,
    )
    permissions_exact = role.get("PermissionsBoundary") is None and (
        iam_control_plane_caller_permissions_are_least_privilege(
            tuple(documents),
            bucket=bucket,
            prefixes=prefixes,
            sentinel_keys=sentinel_keys,
            kms_key_arn=kms_key_arn,
            caller_role_arn=role_arn,
            kms_admin_role_arn=kms_admin_role_arn,
            storage_role_arns=storage_role_arns,
            oidc_provider_arn=oidc_provider_arn,
            attached_policy_arns=frozenset(
                attached_arns | storage_attached_arns
            ),
            region=region,
            account_id=account_id,
        )
    )
    return trust_digest, permissions_digest, trust_exact, permissions_exact


def inspect_kms_policy_and_grants(
    kms_client: Any,
    *,
    kms_key_arn: str,
) -> tuple[Mapping[str, Any], str, str, bool]:
    names = kms_client.list_key_policies(KeyId=kms_key_arn, Limit=100)
    if names.get("Truncated") is True or names.get("NextMarker"):
        raise DomainError("AWS_KMS_POLICY_INVALID", "KMS key policy inventory is truncated")
    policy_names = names.get("PolicyNames", ())
    if policy_names != ["default"]:
        raise DomainError("AWS_KMS_POLICY_INVALID", "KMS key must use one default policy")
    policy = normalize_aws_policy(
        kms_client.get_key_policy(KeyId=kms_key_arn, PolicyName="default").get("Policy", {})
    )
    grants_response = kms_client.list_grants(KeyId=kms_key_arn, Limit=100)
    if grants_response.get("Truncated") is True or grants_response.get("NextMarker"):
        raise DomainError("AWS_KMS_GRANTS_INVALID", "KMS grants exceed the bounded probe")
    grants = grants_response.get("Grants", ())
    if not isinstance(grants, list):
        raise DomainError("AWS_KMS_GRANTS_INVALID", "KMS grants response is invalid")
    normalized_grants: list[Mapping[str, Any]] = []
    for grant in grants:
        if not isinstance(grant, Mapping):
            raise DomainError("AWS_KMS_GRANTS_INVALID", "KMS grant is invalid")
        operations = grant.get("Operations", ())
        if not isinstance(operations, list) or any(
            not isinstance(operation, str) for operation in operations
        ):
            raise DomainError("AWS_KMS_GRANTS_INVALID", "KMS grant operations are invalid")
        normalized_grants.append(
            {
                "grant_id": str(grant.get("GrantId", "")),
                "name": str(grant.get("Name", "")),
                "grantee_principal": str(grant.get("GranteePrincipal", "")),
                "retiring_principal": str(grant.get("RetiringPrincipal", "")),
                "issuing_account": str(grant.get("IssuingAccount", "")),
                "operations": sorted(operations),
                "constraints": _normalized_policy_value(grant.get("Constraints", {})),
            }
        )
    normalized_grants.sort(key=canonical_digest)
    return (
        policy,
        canonical_digest(policy),
        canonical_digest({"schema_version": 1, "grants": normalized_grants}),
        not normalized_grants,
    )


class S3WorkloadIdentityProbe:
    """Verify one pod identity can access only its KMS-bound S3 prefix."""

    def __init__(
        self,
        storage: S3ObjectStorage,
        *,
        identity: str,
        sts_client: Any,
        expected_role_arn: str,
        forbidden_sentinel: S3SentinelBinding | Mapping[str, Any] | None = None,
        forbidden_key: str | None = None,
        require_object_lock: bool = False,
    ) -> None:
        binding = (
            S3SentinelBinding.from_mapping(forbidden_sentinel)
            if isinstance(forbidden_sentinel, Mapping)
            else forbidden_sentinel
        )
        if (
            identity not in {"backup", "snapshot"}
            or binding is None
            or type(require_object_lock) is not bool
            or (forbidden_key is not None and forbidden_key != binding.key)
            or binding.bucket != storage.bucket
            or binding.kms_key_id != storage.kms_key_id
            or binding.key == storage.prefix
            or binding.key.startswith(storage.prefix.rstrip("/") + "/")
        ):
            raise DomainError(
                "WORKLOAD_IDENTITY_CONFIG_INVALID",
                "an exact control-plane cross-prefix sentinel is required",
            )
        self.storage = storage
        self.identity = identity
        self.sts_client = sts_client
        self.expected_role_arn = expected_role_arn
        self.forbidden_sentinel = binding
        self.require_object_lock = require_object_lock

    def _denied(self, operation: str, **arguments: Any) -> tuple[bool, bool]:
        try:
            response = getattr(self.storage.client, operation)(**arguments)
            if isinstance(response, Mapping):
                body = response.get("Body")
                if body is not None and hasattr(body, "close"):
                    body.close()
            return False, False
        except Exception as error:  # noqa: BLE001 - classify provider authorization errors
            _code, denied, kms_denial = _error_class(error)
            return denied, kms_denial

    def _deleted_version_absent(self, full_key: str, version_id: str) -> bool:
        try:
            response = self.storage.client.get_object(
                **self.storage.bucket_request(Key=full_key, VersionId=version_id)
            )
            body = response.get("Body") if isinstance(response, Mapping) else None
            if body is not None and hasattr(body, "close"):
                body.close()
            return False
        except Exception as error:  # noqa: BLE001 - exact absence is provider-defined
            code, _denied, _kms_denial = _error_class(error)
            return code in NOT_FOUND_ERROR_CODES

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
        readback = b""
        disposition_verified = False
        exact_get_denied = False
        exact_head_denied = False
        list_denied = False
        version_list_denied = False
        kms_denial_observed = False
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
            sentinel = self.forbidden_sentinel
            exact_get_denied, get_kms_denial = self._denied(
                "get_object",
                **self.storage.bucket_request(
                    Key=sentinel.key,
                    VersionId=sentinel.version_id,
                ),
            )
            exact_head_denied, head_kms_denial = self._denied(
                "head_object",
                **self.storage.bucket_request(
                    Key=sentinel.key,
                    VersionId=sentinel.version_id,
                ),
            )
            list_denied, list_kms_denial = self._denied(
                "list_objects_v2",
                **self.storage.bucket_request(Prefix=sentinel.key, MaxKeys=1),
            )
            version_list_denied, version_list_kms_denial = self._denied(
                "list_object_versions",
                **self.storage.bucket_request(Prefix=sentinel.key, MaxKeys=1),
            )
            kms_denial_observed = any(
                (
                    get_kms_denial,
                    head_kms_denial,
                    list_kms_denial,
                    version_list_kms_denial,
                )
            )
        finally:
            if reference is not None and reference.version_id:
                full_key = self.storage._key(key)
                try:
                    disposition = self.storage.client.delete_object(
                        **self.storage.bucket_request(
                            Key=full_key,
                            VersionId=reference.version_id,
                        )
                    )
                except Exception as error:  # noqa: BLE001 - retained versions deny deletion
                    _code, deletion_denied, _kms_denial = _error_class(error)
                    disposition_verified = self.require_object_lock and deletion_denied
                else:
                    disposition_verified = (
                        not self.require_object_lock
                        and isinstance(disposition, Mapping)
                        and self._deleted_version_absent(full_key, reference.version_id)
                    )
        cross_prefix_denied = (
            exact_get_denied
            and exact_head_denied
            and list_denied
            and version_list_denied
            and not kms_denial_observed
        )
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
                reference is not None
                and readback == payload
                and bool(reference.version_id)
                and reference.encryption == "aws:kms",
            ),
            GateCheck("cross_prefix_exact_version_get_denied", exact_get_denied),
            GateCheck("cross_prefix_exact_version_head_denied", exact_head_denied),
            GateCheck("cross_prefix_list_denied", list_denied),
            GateCheck("cross_prefix_version_list_denied", version_list_denied),
            GateCheck("cross_prefix_denial_not_kms_only", not kms_denial_observed),
            GateCheck("cross_prefix_denied", cross_prefix_denied),
            GateCheck("probe_object_disposition", disposition_verified),
        )
        return complete(
            f"s3_{self.identity}_identity",
            started_at=started,
            coordinates={
                "bucket_digest": hashlib.sha256(self.storage.bucket.encode()).hexdigest(),
                "prefix": self.storage.prefix,
                "role_arn_digest": hashlib.sha256(self.expected_role_arn.encode()).hexdigest(),
                "kms_key_digest": hashlib.sha256(str(self.storage.kms_key_id).encode()).hexdigest(),
                "forbidden_sentinel_binding_digest": self.forbidden_sentinel.binding_digest,
            },
            checks=checks,
            metrics={
                "probe_bytes": len(payload),
                "kms_denial_observed": int(kms_denial_observed),
                "workload_retention_api_calls": 0,
                "sentinel_binding_digest": self.forbidden_sentinel.binding_digest,
            },
        )


class S3KmsProbe:
    """Live S3/KMS acceptance probe with version-aware cleanup and no secret output."""

    def __init__(
        self,
        storage: S3ObjectStorage,
        *,
        require_object_lock: bool = False,
        kms_client: Any | None = None,
        sts_client: Any | None = None,
        iam_client: Any | None = None,
        expected_account_id: str | None = None,
        expected_caller_arn: str | None = None,
        expected_caller_trust_contract: Mapping[str, Any] | None = None,
        expected_kms_admin_role_arn: str | None = None,
        expected_irsa_oidc_provider_arn: str | None = None,
        expected_role_arns: Mapping[str, str] | None = None,
        expected_trust_subjects: Mapping[str, str] | None = None,
        expected_policy_digests: Mapping[str, str] | None = None,
        expected_policy_bundle_digest: str | None = None,
        require_cloud_control_plane: bool = False,
        lifecycle_prefixes: Mapping[str, str] | None = None,
        immutable_sentinel_keys: Mapping[str, str] | None = None,
        acceptance_run_id: str | None = None,
        signed_target_profile_digest: str | None = None,
        mutation_confirmation: str | None = None,
    ) -> None:
        if not storage.kms_key_id or not storage.kms_key_id.startswith("arn:"):
            raise DomainError(
                "KMS_KEY_REQUIRED", "S3 production probe requires an exact KMS key ARN"
            )
        self.storage = storage
        self.require_object_lock = require_object_lock
        self.kms_client = kms_client
        self.sts_client = sts_client
        self.iam_client = iam_client
        self.expected_account_id = expected_account_id
        self.expected_caller_arn = expected_caller_arn
        self.expected_caller_trust_contract = dict(expected_caller_trust_contract or {})
        self.expected_kms_admin_role_arn = expected_kms_admin_role_arn
        self.expected_irsa_oidc_provider_arn = expected_irsa_oidc_provider_arn
        self.expected_role_arns = dict(expected_role_arns or {})
        self.expected_trust_subjects = dict(expected_trust_subjects or {})
        self.expected_policy_digests = dict(expected_policy_digests or {})
        self.expected_policy_bundle_digest = expected_policy_bundle_digest
        self.require_cloud_control_plane = require_cloud_control_plane
        self.acceptance_run_id = acceptance_run_id
        self.signed_target_profile_digest = signed_target_profile_digest
        self.mutation_confirmation = mutation_confirmation
        if lifecycle_prefixes is None:
            normalized_lifecycle = {
                "acceptance": storage._key("production-probes").rstrip("/") + "/"
            }
        else:
            if set(lifecycle_prefixes) != {"acceptance", "snapshot", "backup"}:
                raise DomainError(
                    "S3_LIFECYCLE_PREFIX_INVALID",
                    "exact acceptance, snapshot, and backup prefixes are required",
                )
            normalized_lifecycle = {}
            for name, value in lifecycle_prefixes.items():
                if not isinstance(value, str) or not value:
                    raise DomainError("S3_LIFECYCLE_PREFIX_INVALID", "lifecycle prefix is invalid")
                normalized = validate_object_key(value.rstrip("/")) + "/"
                normalized_lifecycle[name] = normalized
            expected_acceptance = storage._key("production-probes").rstrip("/") + "/"
            if normalized_lifecycle["acceptance"] != expected_acceptance:
                raise DomainError(
                    "S3_LIFECYCLE_PREFIX_INVALID",
                    "acceptance lifecycle prefix must cover the live probe namespace",
                )
            prefixes = tuple(normalized_lifecycle.values())
            if len(set(prefixes)) != len(prefixes) or any(
                left.startswith(right) or right.startswith(left)
                for index, left in enumerate(prefixes)
                for right in prefixes[index + 1 :]
            ):
                raise DomainError(
                    "S3_LIFECYCLE_PREFIX_INVALID",
                    "lifecycle prefixes must be pairwise non-overlapping",
                )
        self.lifecycle_prefixes = normalized_lifecycle
        if immutable_sentinel_keys is None:
            normalized_sentinels: dict[str, str] = {}
        else:
            if set(immutable_sentinel_keys) != {"backup", "snapshot"}:
                raise DomainError(
                    "S3_SENTINEL_CONFIG_INVALID",
                    "exact backup and snapshot sentinel keys are required",
                )
            normalized_sentinels = {
                name: validate_object_key(value)
                for name, value in immutable_sentinel_keys.items()
                if isinstance(value, str)
            }
            if (
                set(normalized_sentinels) != {"backup", "snapshot"}
                or len(set(normalized_sentinels.values())) != 2
            ):
                raise DomainError("S3_SENTINEL_CONFIG_INVALID", "sentinel keys must be distinct")
        self.immutable_sentinel_keys = normalized_sentinels
        self.sentinel_bindings: dict[str, S3SentinelBinding] = {}
        try:
            expected_partition = aws_partition_for_region(str(storage.region or ""))
        except DomainError:
            expected_partition = ""
        try:
            normalized_caller_trust_contract = github_actions_caller_trust_contract(
                account_id=str(expected_account_id or ""),
                region=str(storage.region or ""),
                repository=str(self.expected_caller_trust_contract.get("repository", "")),
                repository_owner_id=str(
                    self.expected_caller_trust_contract.get(
                        "repository_owner_id", ""
                    )
                ),
                repository_id=str(
                    self.expected_caller_trust_contract.get("repository_id", "")
                ),
                ref=str(self.expected_caller_trust_contract.get("ref", "")),
                environment=str(
                    self.expected_caller_trust_contract.get("environment", "")
                ),
                workflow=str(self.expected_caller_trust_contract.get("workflow", "")),
            )
        except DomainError:
            normalized_caller_trust_contract = {}
        if require_cloud_control_plane and (
            kms_client is None
            or sts_client is None
            or iam_client is None
            or not expected_account_id
            or not expected_account_id.isdigit()
            or len(expected_account_id) != 12
            or storage.expected_bucket_owner != expected_account_id
            or not storage.production
            or storage.endpoint_url is not None
            or set(normalized_lifecycle) != {"acceptance", "snapshot", "backup"}
            or set(normalized_sentinels) != {"backup", "snapshot"}
            or (caller_match := IAM_ROLE_ARN.fullmatch(str(expected_caller_arn or ""))) is None
            or caller_match.group(2) != expected_account_id
            or caller_match.group(1) != expected_partition
            or normalized_iam_role_arn(str(expected_caller_arn)) != expected_caller_arn
            or self.expected_caller_trust_contract != normalized_caller_trust_contract
            or (
                admin_match := IAM_ROLE_ARN.fullmatch(
                    str(expected_kms_admin_role_arn or "")
                )
            )
            is None
            or admin_match.group(2) != expected_account_id
            or admin_match.group(1) != expected_partition
            or (
                provider_match := IAM_OIDC_PROVIDER_ARN.fullmatch(
                    str(expected_irsa_oidc_provider_arn or "")
                )
            )
            is None
            or provider_match.group(2) != expected_account_id
            or provider_match.group(1) != expected_partition
            or set(self.expected_role_arns) != {"backup", "snapshot"}
            or len(set(self.expected_role_arns.values())) != 2
            or len(
                {
                    str(expected_caller_arn),
                    str(expected_kms_admin_role_arn),
                    *self.expected_role_arns.values(),
                }
            )
            != 4
            or any(
                (match := IAM_ROLE_ARN.fullmatch(role_arn)) is None
                or match.group(2) != expected_account_id
                or match.group(1) != expected_partition
                for role_arn in self.expected_role_arns.values()
            )
            or set(self.expected_trust_subjects) != {"backup", "snapshot"}
            or set(self.expected_policy_digests) != AWS_STORAGE_POLICY_DIGEST_FIELDS
            or self.expected_policy_digests.get(
                "s3_control_plane_caller_trust_contract_digest"
            )
            != canonical_digest(normalized_caller_trust_contract)
            or any(
                not re.fullmatch(r"[a-f0-9]{64}", value)
                for value in self.expected_policy_digests.values()
            )
            or not isinstance(expected_policy_bundle_digest, str)
            or not re.fullmatch(r"[a-f0-9]{64}", expected_policy_bundle_digest)
            or aws_storage_policy_bundle_digest(self.expected_policy_digests)
            != expected_policy_bundle_digest
            or not isinstance(acceptance_run_id, str)
            or not ACCEPTANCE_RUN_ID.fullmatch(acceptance_run_id)
            or not isinstance(signed_target_profile_digest, str)
            or not re.fullmatch(r"[a-f0-9]{64}", signed_target_profile_digest)
            or not isinstance(mutation_confirmation, str)
            or not re.fullmatch(r"[a-f0-9]{64}", mutation_confirmation)
        ):
            raise DomainError(
                "CLOUD_CONTROL_PLANE_REQUIRED",
                "AWS control-plane clients, signed run coordinates, and authorization are required",
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

    def bind_immutable_sentinel(
        self,
        key: str,
        *,
        forbidden_to: str | None = None,
    ) -> S3SentinelBinding:
        """Bind and checksum one exact retained sentinel using control-plane credentials."""
        full_key = validate_object_key(key)
        if forbidden_to not in {None, "backup", "snapshot"}:
            raise DomainError("S3_SENTINEL_CONFIG_INVALID", "sentinel workload identity is invalid")
        if forbidden_to is not None and set(self.lifecycle_prefixes) == {
            "acceptance",
            "backup",
            "snapshot",
        }:
            source_prefix = self.lifecycle_prefixes[
                "snapshot" if forbidden_to == "backup" else "backup"
            ]
            if not full_key.startswith(source_prefix):
                raise DomainError(
                    "S3_SENTINEL_CONFIG_INVALID",
                    "cross-prefix sentinel is outside the opposite workload prefix",
                )
        client = self.storage.client
        latest = client.head_object(**self.storage.bucket_request(Key=full_key))
        version_id = str(latest.get("VersionId", ""))
        if not version_id:
            raise DomainError("S3_SENTINEL_BINDING_INVALID", "sentinel must have an exact version")
        exact = client.head_object(
            **self.storage.bucket_request(Key=full_key, VersionId=version_id)
        )
        content_length = exact.get("ContentLength")
        metadata = exact.get("Metadata", {})
        expected_sha256 = str(metadata.get("sha256", "")) if isinstance(metadata, Mapping) else ""
        if (
            exact.get("VersionId") != version_id
            or type(content_length) is not int
            or not 1 <= content_length <= SENTINEL_MAX_BYTES
            or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
            or exact.get("ServerSideEncryption") != "aws:kms"
            or exact.get("SSEKMSKeyId") != self.storage.kms_key_id
        ):
            raise DomainError(
                "S3_SENTINEL_BINDING_INVALID",
                "sentinel metadata is not versioned and KMS-bound",
            )
        response = client.get_object(
            **self.storage.bucket_request(Key=full_key, VersionId=version_id)
        )
        body = response.get("Body") if isinstance(response, Mapping) else None
        if body is None or not hasattr(body, "read") or not hasattr(body, "close"):
            raise DomainError("S3_SENTINEL_BINDING_INVALID", "sentinel body is unavailable")
        try:
            payload = body.read(SENTINEL_MAX_BYTES + 1)
        finally:
            body.close()
        if (
            not isinstance(payload, bytes)
            or len(payload) != content_length
            or hashlib.sha256(payload).hexdigest() != expected_sha256
            or response.get("VersionId") != version_id
            or response.get("ServerSideEncryption") != "aws:kms"
            or response.get("SSEKMSKeyId") != self.storage.kms_key_id
        ):
            raise DomainError(
                "S3_SENTINEL_BINDING_INVALID", "sentinel immutable checksum is invalid"
            )
        retained = client.get_object_retention(
            **self.storage.bucket_request(Key=full_key, VersionId=version_id)
        )
        retention = retained.get("Retention", {}) if isinstance(retained, Mapping) else {}
        coordinates = _retention_coordinates(retention) if isinstance(retention, Mapping) else None
        if coordinates is None:
            raise DomainError(
                "S3_SENTINEL_RETENTION_INVALID",
                "control plane did not prove future sentinel retention",
            )
        mode, retain_until = coordinates
        return S3SentinelBinding(
            schema_version=1,
            bucket=self.storage.bucket,
            key=full_key,
            version_id=version_id,
            sha256=expected_sha256,
            content_length=content_length,
            kms_key_id=str(self.storage.kms_key_id),
            etag=str(exact.get("ETag", "")).strip('"'),
            retention_mode=mode,
            retain_until=retain_until,
        )

    def _cleanup_versions(self, full_key: str) -> bool:
        response = self.storage.client.list_object_versions(
            **self.storage.bucket_request(Prefix=full_key)
        )
        for collection in ("Versions", "DeleteMarkers"):
            for item in response.get(collection, ()):
                if item.get("Key") == full_key and item.get("VersionId"):
                    self.storage.client.delete_object(
                        **self.storage.bucket_request(
                            Key=full_key,
                            VersionId=item["VersionId"],
                        )
                    )
        remaining = self.storage.client.list_object_versions(
            **self.storage.bucket_request(Prefix=full_key)
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
            **self.storage.bucket_request(Prefix=full_key)
        )
        present = any(
            item.get("Key") == full_key and item.get("VersionId") == version_id
            for item in response.get("Versions", ())
        )
        if not present:
            return False
        response = self.storage.client.get_object_retention(
            **self.storage.bucket_request(Key=full_key, VersionId=version_id)
        )
        retention = response.get("Retention", {}) if isinstance(response, Mapping) else {}
        return isinstance(retention, Mapping) and _retention_coordinates(retention) is not None

    def run(self) -> GateEvidence:
        started = utc_now()
        client = self.storage.client
        versioning = client.get_bucket_versioning(**self.storage.bucket_request())
        public = client.get_public_access_block(**self.storage.bucket_request()).get(
            "PublicAccessBlockConfiguration", {}
        )
        encryption = client.get_bucket_encryption(**self.storage.bucket_request())
        rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", ())
        lifecycle = client.get_bucket_lifecycle_configuration(**self.storage.bucket_request())
        lock_response: Mapping[str, Any] = {}
        lock_enabled = False
        lock_retention = False
        try:
            observed_lock = client.get_object_lock_configuration(
                **self.storage.bucket_request()
            )
            if isinstance(observed_lock, Mapping):
                lock_response = observed_lock
            lock_config = lock_response.get("ObjectLockConfiguration", {})
            lock_enabled = (
                isinstance(lock_config, Mapping)
                and lock_config.get("ObjectLockEnabled") == "Enabled"
            )
            lock_rule = lock_config.get("Rule", {}) if isinstance(lock_config, Mapping) else {}
            retention = lock_rule.get("DefaultRetention", {}) if isinstance(lock_rule, Mapping) else {}
            lock_retention = (
                isinstance(retention, Mapping)
                and retention.get("Mode") in {"GOVERNANCE", "COMPLIANCE"}
                and type(retention.get("Days", 0) or retention.get("Years", 0)) is int
                and int(retention.get("Days", 0) or retention.get("Years", 0)) > 0
            )
        except Exception as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code")
            if code not in {
                "ObjectLockConfigurationNotFoundError",
                "NoSuchObjectLockConfiguration",
            }:
                raise
        public_policy = False
        tls_only_policy = False
        kms_enabled = False
        kms_rotation = False
        kms_identity = False
        account_identity = False
        workload_identity = False
        bucket_policy_workload_bound = False
        kms_policy_least_privilege = False
        kms_grants_absent = False
        kms_admin_trust_signed = False
        caller_trust_signed = False
        caller_trust_exact = False
        caller_permissions_exact = False
        oidc_provider_exact = False
        role_trust_exact = {"backup": False, "snapshot": False}
        role_permissions_exact = {"backup": False, "snapshot": False}
        observed_policy_digests: dict[str, str] = {}
        observed_policy_bundle_digest = ""
        policy_digests_signed = False
        bucket_controls_exact = False
        observed_bucket_controls_digest = ""
        ownership_controls: Mapping[str, Any] = {}
        bucket_location_match = not self.require_cloud_control_plane
        bucket_owner_bound = not self.require_cloud_control_plane
        if self.require_cloud_control_plane:
            kms_client = self.kms_client
            sts_client = self.sts_client
            iam_client = self.iam_client
            if kms_client is None or sts_client is None or iam_client is None:
                raise DomainError(
                    "CLOUD_CONTROL_PLANE_REQUIRED",
                    "KMS, STS, and IAM clients are required",
                )
            location = client.get_bucket_location(**self.storage.bucket_request()).get(
                "LocationConstraint"
            )
            normalized_location = (
                "us-east-1"
                if location in {None, ""}
                else "eu-west-1"
                if location == "EU"
                else str(location)
            )
            bucket_location_match = normalized_location == self.storage.region
            bucket_owner_bound = self.storage.expected_bucket_owner == self.expected_account_id
            observed_ownership_controls = client.get_bucket_ownership_controls(
                **self.storage.bucket_request()
            )
            if isinstance(observed_ownership_controls, Mapping):
                ownership_controls = observed_ownership_controls
            try:
                observed_bucket_controls_digest = s3_bucket_controls_digest(
                    bucket=self.storage.bucket,
                    expected_bucket_owner=str(self.expected_account_id),
                    region=str(self.storage.region),
                    kms_key_arn=str(self.storage.kms_key_id),
                    lifecycle_prefixes=self.lifecycle_prefixes,
                    location_constraint=location,
                    versioning=versioning,
                    ownership_controls=ownership_controls,
                    public_access_block={"PublicAccessBlockConfiguration": public},
                    encryption=encryption,
                    object_lock=lock_response,
                    lifecycle=lifecycle,
                )
            except DomainError as error:
                if error.code != "S3_BUCKET_CONTROLS_INVALID":
                    raise
            else:
                bucket_controls_exact = True
            public_policy = not bool(
                client.get_bucket_policy_status(**self.storage.bucket_request())
                .get("PolicyStatus", {})
                .get("IsPublic", True)
            )
            bucket_policy = normalize_aws_policy(
                client.get_bucket_policy(**self.storage.bucket_request()).get("Policy", "{}")
            )
            kms_arn = str(self.storage.kms_key_id).split(":")
            partition = kms_arn[1] if len(kms_arn) == 6 else "aws"
            tls_only_policy = self._tls_only_policy(
                bucket_policy,
                self.storage.bucket,
                partition,
            )
            bucket_policy_workload_bound = bucket_policy_is_workload_bound(
                bucket_policy,
                bucket=self.storage.bucket,
                control_plane_caller_arn=str(self.expected_caller_arn),
                role_arns=self.expected_role_arns,
                prefixes=self.lifecycle_prefixes,
                sentinel_keys=self.immutable_sentinel_keys,
                kms_key_arn=str(self.storage.kms_key_id),
            )
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
            observed_caller_arn = normalized_iam_role_arn(str(caller.get("Arn", "")))
            workload_identity = observed_caller_arn == self.expected_caller_arn
            (
                caller_trust_digest,
                caller_permissions_digest,
                caller_trust_exact,
                caller_permissions_exact,
            ) = inspect_iam_control_plane_caller_role(
                iam_client,
                role_arn=str(self.expected_caller_arn),
                kms_admin_role_arn=str(self.expected_kms_admin_role_arn),
                storage_role_arns=self.expected_role_arns,
                oidc_provider_arn=str(self.expected_irsa_oidc_provider_arn),
                bucket=self.storage.bucket,
                prefixes=self.lifecycle_prefixes,
                sentinel_keys=self.immutable_sentinel_keys,
                kms_key_arn=str(self.storage.kms_key_id),
                region=str(self.storage.region),
                account_id=str(self.expected_account_id),
                trust_contract=self.expected_caller_trust_contract,
            )
            kms_policy, kms_policy_digest, kms_grants_digest, kms_grants_absent = (
                inspect_kms_policy_and_grants(
                    kms_client,
                    kms_key_arn=str(self.storage.kms_key_id),
                )
            )
            kms_policy_least_privilege = kms_key_policy_is_least_privilege(
                kms_policy,
                control_plane_caller_arn=str(self.expected_caller_arn),
                kms_admin_role_arn=str(self.expected_kms_admin_role_arn),
                role_arns=self.expected_role_arns,
                bucket=self.storage.bucket,
                prefixes=self.lifecycle_prefixes,
                kms_key_arn=str(self.storage.kms_key_id),
                region=str(self.storage.region),
                account_id=str(self.expected_account_id),
            )
            observed_policy_digests = {
                "s3_control_plane_caller_arn_digest": canonical_digest(
                    {"caller_arn": observed_caller_arn}
                ),
                "s3_control_plane_caller_trust_contract_digest": canonical_digest(
                    self.expected_caller_trust_contract
                ),
                "s3_control_plane_caller_iam_role_trust_policy_digest": (
                    caller_trust_digest
                ),
                "s3_control_plane_caller_iam_role_permissions_digest": (
                    caller_permissions_digest
                ),
                "kms_admin_role_arn_digest": canonical_digest(
                    {"role_arn": str(self.expected_kms_admin_role_arn)}
                ),
                "kms_admin_iam_role_trust_policy_digest": (
                    inspect_iam_role_trust_policy(
                        iam_client,
                        role_arn=str(self.expected_kms_admin_role_arn),
                        account_id=str(self.expected_account_id),
                    )
                ),
                "s3_bucket_policy_digest": canonical_digest(bucket_policy),
                "kms_key_policy_digest": kms_policy_digest,
                "kms_grants_digest": kms_grants_digest,
            }
            if bucket_controls_exact:
                observed_policy_digests["s3_bucket_controls_digest"] = (
                    observed_bucket_controls_digest
                )
            (
                observed_policy_digests[
                    "aws_irsa_oidc_provider_configuration_digest"
                ],
                oidc_provider_exact,
            ) = inspect_iam_oidc_provider(
                iam_client,
                provider_arn=str(self.expected_irsa_oidc_provider_arn),
            )
            observed_irsa_providers: set[str] = set()
            for identity in ("backup", "snapshot"):
                (
                    trust_digest,
                    permissions_digest,
                    observed_provider_arn,
                    trust_exact,
                    permissions_exact,
                ) = inspect_iam_storage_role(
                    iam_client,
                    role_arn=self.expected_role_arns[identity],
                    expected_provider_arn=str(self.expected_irsa_oidc_provider_arn),
                    expected_subject=self.expected_trust_subjects[identity],
                    bucket=self.storage.bucket,
                    prefix=self.lifecycle_prefixes[identity],
                    kms_key_arn=str(self.storage.kms_key_id),
                    purpose=identity,
                    region=str(self.storage.region),
                    account_id=str(self.expected_account_id),
                )
                observed_irsa_providers.add(observed_provider_arn)
                observed_policy_digests[f"{identity}_iam_role_trust_policy_digest"] = trust_digest
                observed_policy_digests[f"{identity}_iam_role_permissions_digest"] = (
                    permissions_digest
                )
                role_trust_exact[identity] = trust_exact
                role_permissions_exact[identity] = permissions_exact
            if len(observed_irsa_providers) == 1:
                observed_policy_digests["aws_irsa_oidc_provider_arn_digest"] = canonical_digest(
                    {"provider_arn": next(iter(observed_irsa_providers))}
                )
            if set(observed_policy_digests) == AWS_STORAGE_POLICY_DIGEST_FIELDS:
                observed_policy_bundle_digest = aws_storage_policy_bundle_digest(
                    observed_policy_digests
                )
            kms_admin_trust_signed = (
                observed_policy_digests["kms_admin_role_arn_digest"]
                == self.expected_policy_digests["kms_admin_role_arn_digest"]
                and observed_policy_digests[
                    "kms_admin_iam_role_trust_policy_digest"
                ]
                == self.expected_policy_digests[
                    "kms_admin_iam_role_trust_policy_digest"
                ]
            )
            caller_trust_signed = (
                caller_trust_digest
                == self.expected_policy_digests[
                    "s3_control_plane_caller_iam_role_trust_policy_digest"
                ]
            )
            policy_digests_signed = (
                observed_policy_digests == self.expected_policy_digests
                and observed_policy_bundle_digest == self.expected_policy_bundle_digest
            )
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
        lifecycle_scopes = {
            name: any(
                isinstance(item, Mapping)
                and self._lifecycle_rule_covers(item, prefix + "signature-object")
                for item in lifecycle.get("Rules", ())
            )
            for name, prefix in self.lifecycle_prefixes.items()
        }
        lifecycle_scope = all(lifecycle_scopes.values())
        sentinel_bindings = {
            identity: self.bind_immutable_sentinel(key, forbidden_to=identity)
            for identity, key in self.immutable_sentinel_keys.items()
        }
        self.sentinel_bindings = sentinel_bindings
        kms_arn = str(self.storage.kms_key_id).split(":")
        kms_coordinate_match = not self.require_cloud_control_plane or (
            len(kms_arn) == 6
            and kms_arn[0] == "arn"
            and kms_arn[1] == aws_partition_for_region(str(self.storage.region))
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
        pre_mutation_checks = (
            GateCheck("bucket_owner_expected", bucket_owner_bound),
            GateCheck("bucket_location", bucket_location_match),
            GateCheck("bucket_versioning", versioning.get("Status") == "Enabled"),
            GateCheck(
                "public_access_block",
                all(public.get(key) is True for key in block_keys),
            ),
            GateCheck(
                "default_kms_encryption",
                (
                    bucket_controls_exact
                    if self.require_cloud_control_plane
                    else default_kms and default_kms_key
                )
                and (bucket_key_enabled or not self.require_cloud_control_plane),
            ),
            GateCheck(
                "s3_bucket_controls_exact_and_signed",
                (
                    bucket_controls_exact
                    and observed_bucket_controls_digest
                    == self.expected_policy_digests.get("s3_bucket_controls_digest")
                )
                or not self.require_cloud_control_plane,
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
                "bucket_policy_workload_bound",
                bucket_policy_workload_bound or not self.require_cloud_control_plane,
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
                "kms_key_policy_least_privilege",
                kms_policy_least_privilege or not self.require_cloud_control_plane,
            ),
            GateCheck(
                "kms_admin_role_management_only",
                kms_policy_least_privilege or not self.require_cloud_control_plane,
            ),
            GateCheck(
                "kms_admin_role_trust_signed",
                kms_admin_trust_signed or not self.require_cloud_control_plane,
            ),
            GateCheck(
                "kms_grants_absent",
                kms_grants_absent or not self.require_cloud_control_plane,
            ),
            GateCheck(
                "aws_account_identity",
                account_identity or not self.require_cloud_control_plane,
            ),
            GateCheck(
                "aws_workload_identity",
                workload_identity or not self.require_cloud_control_plane,
            ),
            GateCheck(
                "s3_control_plane_caller_trust_contract_exact",
                caller_trust_exact or not self.require_cloud_control_plane,
            ),
            GateCheck(
                "s3_control_plane_caller_iam_role_trust_policy_signed",
                (caller_trust_exact and caller_trust_signed)
                or not self.require_cloud_control_plane,
            ),
            GateCheck(
                "s3_control_plane_caller_iam_role_permissions_least_privilege",
                caller_permissions_exact or not self.require_cloud_control_plane,
            ),
            GateCheck(
                "aws_irsa_oidc_provider_exact",
                oidc_provider_exact or not self.require_cloud_control_plane,
            ),
            *(
                GateCheck(
                    f"{identity}_iam_role_trust_exact",
                    role_trust_exact[identity] or not self.require_cloud_control_plane,
                )
                for identity in ("backup", "snapshot")
            ),
            *(
                GateCheck(
                    f"{identity}_iam_role_permissions_least_privilege",
                    role_permissions_exact[identity] or not self.require_cloud_control_plane,
                )
                for identity in ("backup", "snapshot")
            ),
            GateCheck(
                "aws_policy_digests_signed",
                policy_digests_signed or not self.require_cloud_control_plane,
            ),
            GateCheck(
                "lifecycle_policy",
                bucket_controls_exact if self.require_cloud_control_plane else lifecycle_scope,
            ),
            *(
                GateCheck(f"lifecycle_{name}_prefix", covered)
                for name, covered in lifecycle_scopes.items()
            ),
            *(GateCheck(f"{identity}_sentinel_retained", True) for identity in sentinel_bindings),
            GateCheck(
                "object_lock",
                (lock_enabled and lock_retention) or not self.require_object_lock,
            ),
        )
        mutation_authorized = not self.require_cloud_control_plane
        if self.require_cloud_control_plane:
            if not all(check.passed for check in pre_mutation_checks):
                raise DomainError(
                    "S3_CONTROL_PLANE_INVALID",
                    "read-only S3/KMS/IAM controls, signed policies, lifecycle scopes, "
                    "and sentinels must pass before mutation",
                )
            expected_confirmation = s3_control_plane_mutation_confirmation(
                bucket=self.storage.bucket,
                prefix=self.storage.prefix,
                acceptance_run_id=str(self.acceptance_run_id),
                signed_target_profile_digest=str(self.signed_target_profile_digest),
            )
            mutation_authorized = hmac.compare_digest(
                str(self.mutation_confirmation), expected_confirmation
            )
            if not mutation_authorized:
                raise DomainError(
                    "S3_MUTATION_CONFIRMATION_REQUIRED",
                    "exact run-bound S3 control-plane mutation confirmation is required",
                )

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
            head = client.head_object(
                **self.storage.bucket_request(
                    Key=full_key,
                    VersionId=reference.version_id,
                )
            )
            read_back = self.storage.get_version_bytes(
                key,
                version_id=str(reference.version_id or ""),
                maximum_bytes=8192,
                expected_sha256=reference.sha256,
            )
        finally:
            if reference is None:
                disposition_verified = False
            elif self.require_object_lock and lock_enabled and lock_retention:
                retained_probe = True
                disposition_verified = self._has_retained_version(full_key, reference.version_id)
            else:
                disposition_verified = self._cleanup_versions(full_key)

        checks = (
            *pre_mutation_checks,
            GateCheck("mutation_authorization_bound", mutation_authorized),
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
                "bucket_owner_digest": hashlib.sha256(
                    str(self.storage.expected_bucket_owner or "not-required").encode()
                ).hexdigest(),
                "aws_storage_policy_bundle_digest": (
                    observed_policy_bundle_digest
                    if self.require_cloud_control_plane
                    else "not-required"
                ),
                **{
                    f"{identity}_sentinel_binding_digest": binding.binding_digest
                    for identity, binding in sentinel_bindings.items()
                },
            },
            checks=checks,
            metrics={
                "probe_bytes": len(payload),
                "lifecycle_rules": len(lifecycle.get("Rules", ())),
                "retained_probe_version": int(retained_probe),
                "cloud_control_plane_verified": int(self.require_cloud_control_plane),
                "mutation_authorizations_verified": int(
                    self.require_cloud_control_plane and mutation_authorized
                ),
                "lifecycle_prefixes_verified": sum(lifecycle_scopes.values()),
                "aws_policy_digests_verified": int(
                    self.require_cloud_control_plane and policy_digests_signed
                ),
                **(
                    {
                        **observed_policy_digests,
                        "aws_storage_policy_bundle_digest": observed_policy_bundle_digest,
                    }
                    if self.require_cloud_control_plane
                    else {}
                ),
                **{
                    f"{identity}_sentinel_binding_digest": binding.binding_digest
                    for identity, binding in sentinel_bindings.items()
                },
            },
            limitations=(() if self.require_object_lock else ("object_lock_optional",)),
        )
