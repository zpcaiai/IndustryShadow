"""Collect a fail-closed, read-only AWS storage policy target-profile fragment."""

from __future__ import annotations

import argparse
import re
from collections.abc import Mapping
from typing import Any

from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json
from shadow_sandbox.common.object_storage import validate_object_key
from shadow_sandbox.operations.storage_probe import (
    AWS_STORAGE_POLICY_DIGEST_FIELDS,
    IAM_OIDC_PROVIDER_ARN,
    IAM_ROLE_ARN,
    aws_partition_for_region,
    aws_storage_policy_bundle_digest,
    bucket_policy_is_workload_bound,
    github_actions_caller_trust_contract,
    inspect_iam_control_plane_caller_role,
    inspect_iam_oidc_provider,
    inspect_iam_role_trust_policy,
    inspect_iam_storage_role,
    inspect_kms_policy_and_grants,
    kms_key_policy_is_least_privilege,
    normalize_aws_policy,
    normalized_iam_role_arn,
    s3_bucket_controls_digest,
)


def _prefix(value: str) -> str:
    return validate_object_key(value.rstrip("/")) + "/"


def collect_aws_storage_policy_digests(
    *,
    s3_client: Any,
    kms_client: Any,
    iam_client: Any,
    sts_client: Any,
    bucket: str,
    region: str,
    account_id: str,
    kms_key_arn: str,
    control_plane_caller_arn: str,
    kms_admin_role_arn: str,
    oidc_provider_arn: str,
    role_arns: Mapping[str, str],
    trust_subjects: Mapping[str, str],
    prefixes: Mapping[str, str],
    sentinel_keys: Mapping[str, str],
    caller_trust_repository: str,
    caller_trust_repository_owner_id: str,
    caller_trust_repository_id: str,
    caller_trust_ref: str,
    caller_trust_environment: str,
    caller_trust_workflow: str,
) -> Mapping[str, Any]:
    """Read live policy documents and return only their non-secret canonical digests."""
    partition = aws_partition_for_region(region)
    caller_trust_contract = github_actions_caller_trust_contract(
        account_id=account_id,
        region=region,
        repository=caller_trust_repository,
        repository_owner_id=caller_trust_repository_owner_id,
        repository_id=caller_trust_repository_id,
        ref=caller_trust_ref,
        environment=caller_trust_environment,
        workflow=caller_trust_workflow,
    )
    normalized_prefixes = {name: _prefix(value) for name, value in prefixes.items()}
    kms_match = re.fullmatch(
        rf"arn:{re.escape(partition)}:kms:{re.escape(region)}:"
        rf"{re.escape(account_id)}:key/[A-Za-z0-9-]+",
        kms_key_arn,
    )
    caller_match = IAM_ROLE_ARN.fullmatch(control_plane_caller_arn)
    admin_match = IAM_ROLE_ARN.fullmatch(kms_admin_role_arn)
    provider_match = IAM_OIDC_PROVIDER_ARN.fullmatch(oidc_provider_arn)
    role_matches = {
        name: IAM_ROLE_ARN.fullmatch(role_arn) for name, role_arn in role_arns.items()
    }
    if (
        not re.fullmatch(r"\d{12}", account_id)
        or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket)
        or kms_match is None
        or caller_match is None
        or caller_match.group(1) != partition
        or caller_match.group(2) != account_id
        or normalized_iam_role_arn(control_plane_caller_arn)
        != control_plane_caller_arn
        or admin_match is None
        or admin_match.group(1) != partition
        or admin_match.group(2) != account_id
        or provider_match is None
        or provider_match.group(1) != partition
        or provider_match.group(2) != account_id
        or set(role_arns) != {"backup", "snapshot"}
        or len(
            {control_plane_caller_arn, kms_admin_role_arn, *role_arns.values()}
        )
        != 4
        or any(
            match is None
            or match.group(1) != partition
            or match.group(2) != account_id
            for match in role_matches.values()
        )
        or set(trust_subjects) != {"backup", "snapshot"}
        or set(normalized_prefixes) != {"acceptance", "backup", "snapshot"}
        or set(sentinel_keys) != {"backup", "snapshot"}
        or len(set(normalized_prefixes.values())) != 3
    ):
        raise DomainError(
            "AWS_STORAGE_POLICY_COLLECTION_INVALID",
            "AWS storage collection coordinates are invalid",
        )
    prefix_values = tuple(normalized_prefixes.values())
    if any(
        left.startswith(right) or right.startswith(left)
        for index, left in enumerate(prefix_values)
        for right in prefix_values[index + 1 :]
    ):
        raise DomainError(
            "AWS_STORAGE_POLICY_COLLECTION_INVALID",
            "AWS storage prefixes must be pairwise non-nested",
        )

    try:
        normalized_sentinel_keys = {
            name: validate_object_key(value) for name, value in sentinel_keys.items()
        }
    except DomainError as error:
        raise DomainError(
            "AWS_STORAGE_POLICY_COLLECTION_INVALID",
            "AWS storage sentinel keys are invalid",
        ) from error
    if normalized_sentinel_keys != dict(sentinel_keys) or (
        not normalized_sentinel_keys["backup"].startswith(
            normalized_prefixes["snapshot"]
        )
        or not normalized_sentinel_keys["snapshot"].startswith(
            normalized_prefixes["backup"]
        )
    ):
        raise DomainError(
            "AWS_STORAGE_POLICY_COLLECTION_INVALID",
            "AWS cross-prefix sentinel keys are outside the opposite workload prefixes",
        )

    caller = sts_client.get_caller_identity()
    if (
        not isinstance(caller, Mapping)
        or caller.get("Account") != account_id
        or normalized_iam_role_arn(str(caller.get("Arn", "")))
        != control_plane_caller_arn
    ):
        raise DomainError(
            "AWS_STORAGE_POLICY_COLLECTION_INVALID",
            "the live AWS caller does not match the requested direct IAM role",
        )

    bucket_request = {"Bucket": bucket, "ExpectedBucketOwner": account_id}
    location = s3_client.get_bucket_location(**bucket_request)
    versioning = s3_client.get_bucket_versioning(**bucket_request)
    ownership_controls = s3_client.get_bucket_ownership_controls(**bucket_request)
    public_access_block = s3_client.get_public_access_block(**bucket_request)
    encryption = s3_client.get_bucket_encryption(**bucket_request)
    object_lock = s3_client.get_object_lock_configuration(**bucket_request)
    lifecycle = s3_client.get_bucket_lifecycle_configuration(**bucket_request)
    if any(
        not isinstance(response, Mapping)
        for response in (
            location,
            versioning,
            ownership_controls,
            public_access_block,
            encryption,
            object_lock,
            lifecycle,
        )
    ):
        raise DomainError(
            "AWS_STORAGE_POLICY_COLLECTION_INVALID",
            "the live S3 bucket controls returned an invalid response",
        )
    bucket_controls_digest = s3_bucket_controls_digest(
        bucket=bucket,
        expected_bucket_owner=account_id,
        region=region,
        kms_key_arn=kms_key_arn,
        lifecycle_prefixes=normalized_prefixes,
        location_constraint=location.get("LocationConstraint"),
        versioning=versioning,
        ownership_controls=ownership_controls,
        public_access_block=public_access_block,
        encryption=encryption,
        object_lock=object_lock,
        lifecycle=lifecycle,
    )

    bucket_policy = normalize_aws_policy(
        s3_client.get_bucket_policy(
            **bucket_request,
        ).get("Policy", "{}")
    )
    if not bucket_policy_is_workload_bound(
        bucket_policy,
        bucket=bucket,
        control_plane_caller_arn=control_plane_caller_arn,
        role_arns=role_arns,
        prefixes=normalized_prefixes,
        sentinel_keys=normalized_sentinel_keys,
        kms_key_arn=kms_key_arn,
    ):
        raise DomainError(
            "AWS_STORAGE_POLICY_COLLECTION_INVALID",
            "the live S3 bucket policy is not the exact storage contract",
        )

    kms_policy, kms_policy_digest, kms_grants_digest, grants_absent = (
        inspect_kms_policy_and_grants(kms_client, kms_key_arn=kms_key_arn)
    )
    if not grants_absent or not kms_key_policy_is_least_privilege(
        kms_policy,
        control_plane_caller_arn=control_plane_caller_arn,
        kms_admin_role_arn=kms_admin_role_arn,
        role_arns=role_arns,
        bucket=bucket,
        prefixes=normalized_prefixes,
        kms_key_arn=kms_key_arn,
        region=region,
        account_id=account_id,
    ):
        raise DomainError(
            "AWS_STORAGE_POLICY_COLLECTION_INVALID",
            "the live KMS policy or grants are outside the exact storage contract",
        )

    oidc_configuration_digest, oidc_exact = inspect_iam_oidc_provider(
        iam_client,
        provider_arn=oidc_provider_arn,
    )
    if not oidc_exact:
        raise DomainError(
            "AWS_STORAGE_POLICY_COLLECTION_INVALID",
            "the live IAM OIDC provider is not exact",
        )
    (
        caller_trust_digest,
        caller_permissions_digest,
        caller_trust_exact,
        caller_permissions_exact,
    ) = inspect_iam_control_plane_caller_role(
        iam_client,
        role_arn=control_plane_caller_arn,
        kms_admin_role_arn=kms_admin_role_arn,
        storage_role_arns=role_arns,
        oidc_provider_arn=oidc_provider_arn,
        bucket=bucket,
        prefixes=normalized_prefixes,
        sentinel_keys=normalized_sentinel_keys,
        kms_key_arn=kms_key_arn,
        region=region,
        account_id=account_id,
        trust_contract=caller_trust_contract,
    )
    if not caller_trust_exact or not caller_permissions_exact:
        raise DomainError(
            "AWS_STORAGE_POLICY_COLLECTION_INVALID",
            "the live control-plane caller IAM permissions are not least privilege",
        )
    digests = {
        "aws_irsa_oidc_provider_arn_digest": canonical_digest(
            {"provider_arn": oidc_provider_arn}
        ),
        "aws_irsa_oidc_provider_configuration_digest": (
            oidc_configuration_digest
        ),
        "s3_control_plane_caller_arn_digest": canonical_digest(
            {"caller_arn": control_plane_caller_arn}
        ),
        "s3_control_plane_caller_trust_contract_digest": canonical_digest(
            caller_trust_contract
        ),
        "s3_control_plane_caller_iam_role_trust_policy_digest": (
            caller_trust_digest
        ),
        "s3_control_plane_caller_iam_role_permissions_digest": (
            caller_permissions_digest
        ),
        "kms_admin_role_arn_digest": canonical_digest(
            {"role_arn": kms_admin_role_arn}
        ),
        "kms_admin_iam_role_trust_policy_digest": (
            inspect_iam_role_trust_policy(
                iam_client,
                role_arn=kms_admin_role_arn,
                account_id=account_id,
            )
        ),
        "s3_bucket_controls_digest": bucket_controls_digest,
        "s3_bucket_policy_digest": canonical_digest(bucket_policy),
        "kms_key_policy_digest": kms_policy_digest,
        "kms_grants_digest": kms_grants_digest,
    }
    observed_providers: set[str] = set()
    for identity in ("backup", "snapshot"):
        trust_digest, permissions_digest, observed_provider, trust_exact, permissions_exact = (
            inspect_iam_storage_role(
                iam_client,
                role_arn=role_arns[identity],
                expected_provider_arn=oidc_provider_arn,
                expected_subject=trust_subjects[identity],
                bucket=bucket,
                prefix=normalized_prefixes[identity],
                kms_key_arn=kms_key_arn,
                purpose=identity,
                region=region,
                account_id=account_id,
            )
        )
        if not trust_exact or not permissions_exact:
            raise DomainError(
                "AWS_STORAGE_POLICY_COLLECTION_INVALID",
                f"the live {identity} IAM role is not exact",
            )
        observed_providers.add(observed_provider)
        digests[f"{identity}_iam_role_trust_policy_digest"] = trust_digest
        digests[f"{identity}_iam_role_permissions_digest"] = permissions_digest
    if observed_providers != {oidc_provider_arn} or set(digests) != AWS_STORAGE_POLICY_DIGEST_FIELDS:
        raise DomainError(
            "AWS_STORAGE_POLICY_COLLECTION_INVALID",
            "the live IAM provider or policy inventory drifted",
        )
    return {
        "schema_version": 1,
        "aws_account_id": account_id,
        "aws_partition": partition,
        "aws_region": region,
        "s3_control_plane_caller_trust_contract": caller_trust_contract,
        **dict(sorted(digests.items())),
        "aws_storage_policy_bundle_digest": aws_storage_policy_bundle_digest(digests),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect a read-only AWS storage policy target-profile fragment"
    )
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--kms-key-arn", required=True)
    parser.add_argument("--control-plane-caller-arn", required=True)
    parser.add_argument("--kms-admin-role-arn", required=True)
    parser.add_argument("--oidc-provider-arn", required=True)
    parser.add_argument("--acceptance-prefix", required=True)
    parser.add_argument("--backup-prefix", required=True)
    parser.add_argument("--snapshot-prefix", required=True)
    parser.add_argument("--backup-sentinel-key", required=True)
    parser.add_argument("--snapshot-sentinel-key", required=True)
    parser.add_argument("--caller-trust-repository", required=True)
    parser.add_argument("--caller-trust-repository-owner-id", required=True)
    parser.add_argument("--caller-trust-repository-id", required=True)
    parser.add_argument("--caller-trust-ref", required=True)
    parser.add_argument("--caller-trust-environment", required=True)
    parser.add_argument("--caller-trust-workflow", required=True)
    parser.add_argument("--backup-role-arn", required=True)
    parser.add_argument("--snapshot-role-arn", required=True)
    parser.add_argument("--namespace", required=True)
    arguments = parser.parse_args()
    try:
        import boto3
    except ImportError as error:
        raise DomainError(
            "S3_DEPENDENCY_UNAVAILABLE",
            "install the object-storage dependency",
        ) from error
    value = collect_aws_storage_policy_digests(
        s3_client=boto3.client("s3", region_name=arguments.region),
        kms_client=boto3.client("kms", region_name=arguments.region),
        iam_client=boto3.client("iam", region_name=arguments.region),
        sts_client=boto3.client("sts", region_name=arguments.region),
        bucket=arguments.bucket,
        region=arguments.region,
        account_id=arguments.account_id,
        kms_key_arn=arguments.kms_key_arn,
        control_plane_caller_arn=arguments.control_plane_caller_arn,
        kms_admin_role_arn=arguments.kms_admin_role_arn,
        oidc_provider_arn=arguments.oidc_provider_arn,
        role_arns={
            "backup": arguments.backup_role_arn,
            "snapshot": arguments.snapshot_role_arn,
        },
        trust_subjects={
            "backup": (
                f"system:serviceaccount:{arguments.namespace}:shadow-backup-storage"
            ),
            "snapshot": (
                f"system:serviceaccount:{arguments.namespace}:shadow-simulator-storage"
            ),
        },
        prefixes={
            "acceptance": arguments.acceptance_prefix,
            "backup": arguments.backup_prefix,
            "snapshot": arguments.snapshot_prefix,
        },
        sentinel_keys={
            "backup": arguments.backup_sentinel_key,
            "snapshot": arguments.snapshot_sentinel_key,
        },
        caller_trust_repository=arguments.caller_trust_repository,
        caller_trust_repository_owner_id=(
            arguments.caller_trust_repository_owner_id
        ),
        caller_trust_repository_id=arguments.caller_trust_repository_id,
        caller_trust_ref=arguments.caller_trust_ref,
        caller_trust_environment=arguments.caller_trust_environment,
        caller_trust_workflow=arguments.caller_trust_workflow,
    )
    print(canonical_json(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
