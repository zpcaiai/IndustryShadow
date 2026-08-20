from __future__ import annotations

import re
from dataclasses import dataclass

from shadow_sandbox.common.models import DomainError

AWS_PARTITIONS = frozenset({"aws", "aws-us-gov", "aws-cn"})
REGION = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-\d$")
ACCOUNT_ID = re.compile(r"^\d{12}$")
KMS_KEY_RESOURCE = re.compile(r"^key/[A-Za-z0-9-]{1,256}$")
RDS_DATABASE_RESOURCE = re.compile(r"^db:[A-Za-z0-9-]{1,255}$")


@dataclass(frozen=True, slots=True)
class AwsResourceArn:
    value: str
    partition: str
    service: str
    region: str
    account_id: str
    resource: str


def _partition_matches_region(partition: str, region: str) -> bool:
    if partition == "aws-cn":
        return region.startswith("cn-")
    if partition == "aws-us-gov":
        return region.startswith("us-gov-")
    return not region.startswith(
        ("cn-", "us-gov-", "us-iso-", "us-isob-", "us-isof-", "eu-isoe-", "eusc-")
    )


def _parse(value: str, *, service: str, resource: re.Pattern[str], code: str) -> AwsResourceArn:
    fields = value.split(":", 5)
    if len(fields) != 6:
        raise DomainError(code, "AWS resource ARN is malformed")
    marker, partition, observed_service, region, account_id, observed_resource = fields
    if (
        marker != "arn"
        or partition not in AWS_PARTITIONS
        or observed_service != service
        or REGION.fullmatch(region) is None
        or ACCOUNT_ID.fullmatch(account_id) is None
        or resource.fullmatch(observed_resource) is None
        or not _partition_matches_region(partition, region)
    ):
        raise DomainError(code, "AWS resource ARN coordinates are invalid")
    return AwsResourceArn(value, partition, service, region, account_id, observed_resource)


def parse_kms_key_arn(value: str, *, code: str = "KMS_KEY_ARN_INVALID") -> AwsResourceArn:
    """Parse an exact multi-partition KMS key ARN; aliases are intentionally rejected."""

    return _parse(value, service="kms", resource=KMS_KEY_RESOURCE, code=code)


def parse_rds_database_arn(
    value: str, *, code: str = "MANAGED_POSTGRESQL_BINDING_INVALID"
) -> AwsResourceArn:
    return _parse(value, service="rds", resource=RDS_DATABASE_RESOURCE, code=code)


def require_same_aws_coordinates(
    left: AwsResourceArn,
    right: AwsResourceArn,
    *,
    include_region: bool,
    code: str,
) -> None:
    if (
        left.partition != right.partition
        or left.account_id != right.account_id
        or (include_region and left.region != right.region)
    ):
        raise DomainError(code, "AWS resource partition, account, or region does not match")
