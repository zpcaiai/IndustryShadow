from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit

from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now

from .evidence import GateCheck, GateEvidence, complete

RDS_ARN = re.compile(r"^arn:(aws|aws-us-gov|aws-cn):rds:([a-z0-9-]+):(\d{12}):db:([A-Za-z0-9-]+)$")
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
            port = parsed.port or 5432
        except ValueError as error:
            raise DomainError("DATABASE_URL_INVALID", "PostgreSQL URL is malformed") from error
        database = unquote(parsed.path.removeprefix("/"))
        if parsed.scheme != "postgresql" or not parsed.hostname or not database or "/" in database:
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
        for arn, expected_digest, coordinate, expected_coordinate in (
            (
                self.source_arn,
                self.source_resource_digest,
                self.source,
                self.source_coordinate_digest,
            ),
            (
                self.restore_arn,
                self.restore_resource_digest,
                self.restore,
                self.restore_coordinate_digest,
            ),
        ):
            match = RDS_ARN.fullmatch(arn)
            if (
                match is None
                or match.group(2) != self.region
                or match.group(3) != self.account_id
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
        self, resource_arn: str, endpoint: DatabaseEndpoint
    ) -> tuple[Mapping[str, Any], RdsResourceBinding]:
        match = RDS_ARN.fullmatch(resource_arn)
        if match is None:
            raise DomainError("MANAGED_POSTGRESQL_BINDING_INVALID", "RDS ARN is invalid")
        try:
            response = self.client.describe_db_instances(DBInstanceIdentifier=match.group(4))
        except Exception as error:
            raise DomainError(
                "MANAGED_POSTGRESQL_CONTROL_PLANE_UNAVAILABLE",
                "RDS resource lookup failed",
                status=503,
            ) from error
        instances = response.get("DBInstances", ())
        if not isinstance(instances, list) or len(instances) != 1:
            raise DomainError(
                "MANAGED_POSTGRESQL_CONTROL_PLANE_INVALID",
                "RDS lookup did not return one exact instance",
            )
        value = instances[0]
        observed_endpoint = value.get("Endpoint", {})
        kms_key = str(value.get("KmsKeyId", ""))
        ca_identifier = str(value.get("CACertificateIdentifier", ""))
        resource_id = str(value.get("DbiResourceId", ""))
        valid = (
            value.get("DBInstanceArn") == resource_arn
            and str(observed_endpoint.get("Address", "")).lower().rstrip(".") == endpoint.host
            and int(observed_endpoint.get("Port", 0)) == endpoint.port
            and value.get("DBInstanceStatus") == "available"
            and value.get("StorageEncrypted") is True
            and value.get("PubliclyAccessible") is False
            and bool(kms_key and ca_identifier and resource_id)
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
        )

    def run(self) -> GateEvidence:
        started = utc_now()
        source, source_binding = self._describe(self.source_arn, self.source)
        _restore, restore_binding = self._describe(self.restore_arn, self.restore)
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
        )
        return complete(
            "managed_postgresql",
            started_at=started,
            coordinates={
                "provider": "aws-rds",
                "account_id_digest": canonical_digest({"account_id": self.account_id}),
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
            },
        )
