from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit

from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now

from .aws_resource_arns import (
    AwsResourceArn,
    parse_kms_key_arn,
    parse_rds_database_arn,
    require_same_aws_coordinates,
)
from .evidence import GateCheck, GateEvidence, complete

DIGEST = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True, slots=True)
class DatabaseEndpoint:
    host: str
    port: int
    database: str

    @classmethod
    def parse(cls, database_url: str) -> DatabaseEndpoint:
        try:
            parsed = urlsplit(database_url.replace("postgresql+psycopg://", "postgresql://", 1))
            port = parsed.port if parsed.port is not None else 5432
        except ValueError as error:
            raise DomainError("DATABASE_URL_INVALID", "PostgreSQL URL is malformed") from error
        database = unquote(parsed.path.removeprefix("/"))
        if (
            parsed.scheme != "postgresql"
            or not parsed.hostname
            or not database
            or "/" in database
            or parsed.fragment
            or not 1 <= port <= 65535
        ):
            raise DomainError("DATABASE_URL_INVALID", "PostgreSQL coordinate is invalid")
        return cls(parsed.hostname.lower().rstrip("."), port, database)

    @property
    def digest(self) -> str:
        return canonical_digest({"host": self.host, "port": self.port, "database": self.database})


@dataclass(frozen=True, slots=True)
class RdsResourceBinding:
    resource_arn_digest: str
    coordinate_digest: str
    kms_key_id_digest: str
    ca_identifier_digest: str
    database_resource_id_digest: str
    aws_partition: str


class AwsRdsControlPlaneProbe:
    """Bind PostgreSQL connection coordinates to two live, encrypted RDS resources."""

    def __init__(
        self,
        source_database_url: str,
        restore_database_url: str,
        *,
        source_resource_arn: str,
        restore_resource_arn: str,
        expected_account_id: str,
        expected_region: str,
        expected_source_resource_digest: str,
        expected_restore_resource_digest: str,
        expected_source_coordinate_digest: str,
        expected_restore_coordinate_digest: str,
        client: Any,
    ) -> None:
        self.source = DatabaseEndpoint.parse(source_database_url)
        self.restore = DatabaseEndpoint.parse(restore_database_url)
        self.source_arn = source_resource_arn
        self.restore_arn = restore_resource_arn
        self.source_arn_coordinates = parse_rds_database_arn(self.source_arn)
        self.restore_arn_coordinates = parse_rds_database_arn(self.restore_arn)
        require_same_aws_coordinates(
            self.source_arn_coordinates,
            self.restore_arn_coordinates,
            include_region=True,
            code="MANAGED_POSTGRESQL_BINDING_INVALID",
        )
        self.account_id = expected_account_id
        self.region = expected_region
        self.source_resource_digest = expected_source_resource_digest
        self.restore_resource_digest = expected_restore_resource_digest
        self.source_coordinate_digest = expected_source_coordinate_digest
        self.restore_coordinate_digest = expected_restore_coordinate_digest
        self.client = client
        if self.source_arn == self.restore_arn or self.source == self.restore:
            raise DomainError(
                "MANAGED_POSTGRESQL_TARGET_INVALID",
                "source and restore RDS resources must be distinct",
            )
        for arn, arn_coordinates, expected_digest, coordinate, expected_coordinate in (
            (
                self.source_arn,
                self.source_arn_coordinates,
                self.source_resource_digest,
                self.source,
                self.source_coordinate_digest,
            ),
            (
                self.restore_arn,
                self.restore_arn_coordinates,
                self.restore_resource_digest,
                self.restore,
                self.restore_coordinate_digest,
            ),
        ):
            if (
                arn_coordinates.region != self.region
                or arn_coordinates.account_id != self.account_id
                or not DIGEST.fullmatch(expected_digest)
                or canonical_digest({"provider": "aws-rds", "resource_arn": arn}) != expected_digest
                or not DIGEST.fullmatch(expected_coordinate)
                or coordinate.digest != expected_coordinate
            ):
                raise DomainError(
                    "MANAGED_POSTGRESQL_BINDING_INVALID",
                    "RDS resource is not bound to the signed target profile",
                )

    def _describe(
        self,
        resource_arn: str,
        resource_coordinates: AwsResourceArn,
        endpoint: DatabaseEndpoint,
    ) -> tuple[Mapping[str, Any], RdsResourceBinding]:
        try:
            response = self.client.describe_db_instances(
                DBInstanceIdentifier=resource_coordinates.resource.removeprefix("db:")
            )
        except Exception as error:
            raise DomainError(
                "MANAGED_POSTGRESQL_CONTROL_PLANE_UNAVAILABLE",
                "RDS resource lookup failed",
                status=503,
            ) from error
        if not isinstance(response, Mapping):
            raise DomainError(
                "MANAGED_POSTGRESQL_CONTROL_PLANE_INVALID",
                "RDS lookup response is malformed",
            )
        instances = response.get("DBInstances", ())
        if not isinstance(instances, list) or len(instances) != 1:
            raise DomainError(
                "MANAGED_POSTGRESQL_CONTROL_PLANE_INVALID",
                "RDS lookup did not return one exact instance",
            )
        value = instances[0]
        if not isinstance(value, Mapping):
            raise DomainError(
                "MANAGED_POSTGRESQL_CONTROL_PLANE_INVALID",
                "RDS lookup instance is malformed",
            )
        observed_endpoint = value.get("Endpoint", {})
        if not isinstance(observed_endpoint, Mapping):
            raise DomainError(
                "MANAGED_POSTGRESQL_CONTROL_PLANE_INVALID",
                "RDS endpoint is malformed",
            )
        kms_key = str(value.get("KmsKeyId", ""))
        ca_identifier = str(value.get("CACertificateIdentifier", ""))
        resource_id = str(value.get("DbiResourceId", ""))
        try:
            kms_coordinates = parse_kms_key_arn(
                kms_key, code="MANAGED_POSTGRESQL_CONTROL_PLANE_INVALID"
            )
            require_same_aws_coordinates(
                resource_coordinates,
                kms_coordinates,
                include_region=True,
                code="MANAGED_POSTGRESQL_CONTROL_PLANE_INVALID",
            )
        except DomainError:
            raise DomainError(
                "MANAGED_POSTGRESQL_CONTROL_PLANE_INVALID",
                "RDS KMS key ARN is not bound to the resource partition, account, and region",
            ) from None
        try:
            observed_port = int(observed_endpoint.get("Port", 0))
        except (TypeError, ValueError):
            observed_port = 0
        backup_retention = value.get("BackupRetentionPeriod")
        valid = (
            value.get("DBInstanceArn") == resource_arn
            and str(observed_endpoint.get("Address", "")).lower().rstrip(".") == endpoint.host
            and observed_port == endpoint.port
            and value.get("DBInstanceStatus") == "available"
            and value.get("StorageEncrypted") is True
            and value.get("PubliclyAccessible") is False
            and bool(kms_key and ca_identifier and resource_id)
            and isinstance(backup_retention, int)
            and not isinstance(backup_retention, bool)
            and backup_retention >= 0
        )
        if not valid:
            raise DomainError(
                "MANAGED_POSTGRESQL_CONTROL_PLANE_INVALID",
                "RDS encryption, network, status, or endpoint binding is invalid",
            )
        return value, RdsResourceBinding(
            canonical_digest({"provider": "aws-rds", "resource_arn": resource_arn}),
            endpoint.digest,
            canonical_digest({"kms_key_id": kms_key}),
            canonical_digest({"ca_identifier": ca_identifier}),
            canonical_digest({"database_resource_id": resource_id}),
            resource_coordinates.partition,
        )

    def run(self) -> GateEvidence:
        started = utc_now()
        source, source_binding = self._describe(
            self.source_arn, self.source_arn_coordinates, self.source
        )
        _restore, restore_binding = self._describe(
            self.restore_arn, self.restore_arn_coordinates, self.restore
        )
        checks = (
            GateCheck(
                "source_signed_resource",
                source_binding.resource_arn_digest == self.source_resource_digest,
            ),
            GateCheck(
                "restore_signed_resource",
                restore_binding.resource_arn_digest == self.restore_resource_digest,
            ),
            GateCheck(
                "source_backup_policy",
                int(source.get("BackupRetentionPeriod", 0)) >= 1
                and source.get("DeletionProtection") is True,
            ),
            GateCheck(
                "distinct_resources",
                source_binding.database_resource_id_digest
                != restore_binding.database_resource_id_digest,
            ),
            GateCheck(
                "aws_partition_binding",
                source_binding.aws_partition == restore_binding.aws_partition,
            ),
        )
        return complete(
            "managed_postgresql",
            started_at=started,
            coordinates={
                "provider": "aws-rds",
                "account_id_digest": canonical_digest({"account_id": self.account_id}),
                "aws_partition_digest": canonical_digest(
                    {"partition": source_binding.aws_partition}
                ),
                "region": self.region,
                "source_resource_digest": source_binding.resource_arn_digest,
                "restore_resource_digest": restore_binding.resource_arn_digest,
                "source_coordinate_digest": source_binding.coordinate_digest,
                "restore_coordinate_digest": restore_binding.coordinate_digest,
                "source_kms_key_id_digest": source_binding.kms_key_id_digest,
                "restore_kms_key_id_digest": restore_binding.kms_key_id_digest,
                "source_ca_identifier_digest": source_binding.ca_identifier_digest,
                "restore_ca_identifier_digest": restore_binding.ca_identifier_digest,
            },
            checks=checks,
            metrics={
                "resources": 2,
                "source_backup_retention_days": source["BackupRetentionPeriod"],
                # GateEvidence intentionally stores only a target digest plus
                # redacted metrics.  These non-secret digests let a parent gate
                # prove that the live control-plane values match the signed
                # target profile without reaching for a non-existent
                # ``GateEvidence.coordinates`` attribute.
                "source_kms_key_id_digest": source_binding.kms_key_id_digest,
                "restore_kms_key_id_digest": restore_binding.kms_key_id_digest,
                "source_ca_identifier_digest": source_binding.ca_identifier_digest,
                "restore_ca_identifier_digest": restore_binding.ca_identifier_digest,
                "aws_partition_digest": canonical_digest(
                    {"partition": source_binding.aws_partition}
                ),
            },
        )
