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
            until = dt.datetime.fromisoformat(until.replace("Z", "+00:00"))
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
        binding = cls(
            schema_version=value.get("schema_version"),
            bucket=value.get("bucket"),
            key=value.get("key"),
            version_id=value.get("version_id"),
            sha256=value.get("sha256"),
            content_length=value.get("content_length"),
            kms_key_id=value.get("kms_key_id"),
            etag=value.get("etag"),
            retention_mode=value.get("retention_mode"),
            retain_until=value.get("retain_until"),
        )
        if value.get("binding_digest") != binding.binding_digest:
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
                readback == payload
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
        expected_account_id: str | None = None,
        expected_caller_arn: str | None = None,
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
        self.expected_account_id = expected_account_id
        self.expected_caller_arn = expected_caller_arn
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
        if require_cloud_control_plane and (
            kms_client is None
            or sts_client is None
            or not expected_account_id
            or not expected_account_id.isdigit()
            or len(expected_account_id) != 12
            or storage.expected_bucket_owner != expected_account_id
            or not storage.production
            or storage.endpoint_url is not None
            or set(normalized_lifecycle) != {"acceptance", "snapshot", "backup"}
            or set(normalized_sentinels) != {"backup", "snapshot"}
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
        public_policy = False
        tls_only_policy = False
        kms_enabled = False
        kms_rotation = False
        kms_identity = False
        account_identity = False
        workload_identity = False
        bucket_location_match = not self.require_cloud_control_plane
        bucket_owner_bound = not self.require_cloud_control_plane
        if self.require_cloud_control_plane:
            kms_client = self.kms_client
            sts_client = self.sts_client
            if kms_client is None or sts_client is None:
                raise DomainError(
                    "CLOUD_CONTROL_PLANE_REQUIRED", "KMS and STS clients are required"
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
            public_policy = not bool(
                client.get_bucket_policy_status(**self.storage.bucket_request())
                .get("PolicyStatus", {})
                .get("IsPublic", True)
            )
            policy = json.loads(
                client.get_bucket_policy(**self.storage.bucket_request()).get("Policy", "{}")
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
                and normalized_iam_role_arn(str(caller.get("Arn", ""))) == self.expected_caller_arn
            )
        lock_enabled = False
        lock_retention = False
        try:
            lock_config = client.get_object_lock_configuration(**self.storage.bucket_request()).get(
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
            GateCheck("lifecycle_policy", lifecycle_scope),
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
                    "read-only S3/KMS controls, lifecycle scopes, and sentinels must pass before mutation",
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
                **{
                    f"{identity}_sentinel_binding_digest": binding.binding_digest
                    for identity, binding in sentinel_bindings.items()
                },
            },
            limitations=(() if self.require_object_lock else ("object_lock_optional",)),
        )
