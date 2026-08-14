from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from shadow_sandbox.common.models import (
    DomainError,
    canonical_digest,
    canonical_json,
    utc_now,
)
from shadow_sandbox.common.object_storage import ObjectRef, create_object_storage, sha256_file


def postgres_environment(database_url: str) -> dict[str, str]:
    try:
        parsed = urlsplit(database_url.replace("postgresql+psycopg://", "postgresql://", 1))
        host = parsed.hostname
        port = parsed.port or 5432
    except ValueError as error:
        raise DomainError(
            "DATABASE_URL_INVALID", "PostgreSQL backup URL is malformed", status=503
        ) from error
    database = unquote(parsed.path.removeprefix("/"))
    username = unquote(parsed.username or "")
    if (
        parsed.scheme != "postgresql"
        or not host
        or not database
        or "/" in database
        or parsed.fragment
    ):
        raise DomainError("DATABASE_URL_INVALID", "PostgreSQL backup URL is invalid", status=503)
    query = parse_qs(parsed.query, keep_blank_values=True)
    sslmode_values = query.get("sslmode", ["require"])
    if len(sslmode_values) != 1:
        raise DomainError(
            "DATABASE_SSLMODE_INVALID",
            "PostgreSQL sslmode must be specified exactly once",
            status=503,
        )
    sslmode = sslmode_values[0]
    if sslmode not in {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}:
        raise DomainError("DATABASE_SSLMODE_INVALID", "PostgreSQL sslmode is invalid", status=503)
    production = os.environ.get("SHADOW_ENVIRONMENT", "").lower() == "production"
    if production:
        root_certificates = query.get("sslrootcert", ())
        if (
            sslmode != "verify-full"
            or len(root_certificates) != 1
            or not unquote(root_certificates[0]).strip()
        ):
            raise DomainError(
                "PRODUCTION_DATABASE_TLS_REQUIRED",
                "production PostgreSQL operations require verify-full and an explicit CA root",
                status=503,
            )
        if not username:
            raise DomainError(
                "PRODUCTION_DATABASE_ROLE_REQUIRED",
                "production PostgreSQL operations require an explicit database role",
                status=503,
            )
    environment = {
        name: os.environ[name]
        for name in ("PATH", "LANG", "LC_ALL", "TZ", "TMPDIR")
        if os.environ.get(name)
    }
    environment.update(
        {
            "PGHOST": host,
            "PGPORT": str(port),
            "PGDATABASE": database,
            "PGUSER": username,
            "PGPASSWORD": unquote(parsed.password or ""),
            "PGSSLMODE": sslmode,
        }
    )
    for parameter, variable in {
        "sslrootcert": "PGSSLROOTCERT",
        "sslcert": "PGSSLCERT",
        "sslkey": "PGSSLKEY",
        "sslcrl": "PGSSLCRL",
    }.items():
        if parameter in query:
            if len(query[parameter]) != 1:
                raise DomainError(
                    "DATABASE_TLS_PARAMETER_INVALID",
                    f"PostgreSQL {parameter} must be specified at most once",
                    status=503,
                )
            environment[variable] = unquote(query[parameter][0])
    return environment


def database_coordinate_digest(database_url: str) -> str:
    """Return a credential-free canonical identity for a PostgreSQL database."""
    try:
        parsed = urlsplit(database_url.replace("postgresql+psycopg://", "postgresql://", 1))
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port or 5432
    except ValueError as error:
        raise DomainError("DATABASE_URL_INVALID", "PostgreSQL URL is malformed") from error
    database = unquote(parsed.path.removeprefix("/"))
    if parsed.scheme != "postgresql" or not host or not database or "/" in database:
        raise DomainError("DATABASE_URL_INVALID", "PostgreSQL URL coordinate is invalid")
    return canonical_digest({"host": host, "port": port, "database": database})


def _object_descriptor(reference: ObjectRef) -> dict[str, object]:
    key = str(reference.key)
    size = int(reference.size)
    sha256 = str(reference.sha256)
    version_id = reference.version_id
    encryption = reference.encryption
    return {
        "key": key,
        "size": size,
        "sha256": sha256,
        "version_id": version_id,
        "encryption": encryption,
    }


def create_backup() -> dict[str, object]:
    database_url = os.environ.get("SHADOW_DATABASE_URL", "")
    kms_key_id = os.environ.get("SHADOW_OBJECT_STORAGE_KMS_KEY_ID", "")
    production = os.environ.get("SHADOW_ENVIRONMENT", "").lower() == "production"
    if production and not kms_key_id.startswith("arn:"):
        raise DomainError(
            "PRODUCTION_KMS_KEY_REQUIRED",
            "production backups require an exact KMS key ARN",
            status=503,
        )
    if production and not os.environ.get("SHADOW_BACKUP_OBJECT_STORAGE_PREFIX", "").strip():
        raise DomainError(
            "PRODUCTION_BACKUP_PREFIX_REQUIRED",
            "production backups require a dedicated object-storage prefix",
            status=503,
        )
    pg_environment = postgres_environment(database_url)
    storage = create_object_storage(
        os.environ.get("SHADOW_OBJECT_STORAGE_BACKEND", "s3"),
        local_root=os.environ.get("SHADOW_OBJECT_STORAGE_ROOT", ".runtime/backups"),
        bucket=os.environ.get("SHADOW_OBJECT_STORAGE_BUCKET"),
        region=os.environ.get("SHADOW_OBJECT_STORAGE_REGION"),
        endpoint_url=os.environ.get("SHADOW_OBJECT_STORAGE_ENDPOINT"),
        prefix=os.environ.get(
            "SHADOW_BACKUP_OBJECT_STORAGE_PREFIX", "industrial-shadow/backups"
        ),
        kms_key_id=kms_key_id or None,
        kms_encryption_context={"application": "industrial-shadow", "purpose": "backup"},
    )
    with tempfile.TemporaryDirectory(prefix="shadow-backup-") as temporary:
        path = Path(temporary) / "database.dump"
        completed = subprocess.run(
            ["pg_dump", "--format=custom", "--no-owner", "--no-acl", "--file", str(path)],
            env=pg_environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3600,
            check=False,
        )
        if completed.returncode:
            raise DomainError(
                "DATABASE_BACKUP_FAILED",
                "pg_dump failed",
                {"exit_code": completed.returncode},
                status=503,
            )
        verify = subprocess.run(
            ["pg_restore", "--list", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=300,
            check=False,
        )
        if verify.returncode:
            raise DomainError("DATABASE_BACKUP_INVALID", "pg_restore could not read the backup")
        digest, archive_size = sha256_file(path)
        created_at = utc_now()
        date = created_at[:10]
        key = f"postgres/{date}/{digest}.dump"
        reference = storage.put_file(
            key, path, content_type="application/vnd.postgresql.custom-backup"
        )
        if reference.sha256 != digest or reference.size != archive_size:
            raise DomainError(
                "DATABASE_BACKUP_UPLOAD_INVALID",
                "uploaded backup does not match the local archive",
                status=503,
            )
        if production and (not reference.version_id or reference.encryption != "aws:kms"):
            raise DomainError(
                "DATABASE_BACKUP_STORAGE_INVALID",
                "production backups require a versioned KMS-encrypted object",
                status=503,
            )
        archive_descriptor = _object_descriptor(reference)
        manifest = {
            "schema_version": 2,
            "created_at": created_at,
            "source_database_digest": database_coordinate_digest(database_url),
            "archive": archive_descriptor,
            "kms_key_id_digest": (
                canonical_digest({"kms_key_id": kms_key_id}) if kms_key_id else "not-required"
            ),
            "format": "postgresql-custom",
            "verified_by": "pg_restore --list",
        }
        manifest["manifest_digest"] = canonical_digest(manifest)
        manifest_bytes = canonical_json(manifest).encode("utf-8")
        manifest_reference = storage.put_bytes(
            key + ".manifest.json",
            manifest_bytes,
            content_type="application/json",
        )
        if production and (
            not manifest_reference.version_id or manifest_reference.encryption != "aws:kms"
        ):
            raise DomainError(
                "DATABASE_BACKUP_MANIFEST_STORAGE_INVALID",
                "production backup manifests require a versioned KMS-encrypted object",
                status=503,
            )
        if production:
            manifest_readback = storage.get_version_bytes(
                manifest_reference.key,
                version_id=str(manifest_reference.version_id),
                maximum_bytes=1024 * 1024,
                expected_sha256=manifest_reference.sha256,
            )
            if manifest_readback != manifest_bytes:
                raise DomainError(
                    "DATABASE_BACKUP_MANIFEST_READBACK_INVALID",
                    "production backup manifest immutable readback failed",
                    status=503,
                )
        receipt = {
            "schema_version": 1,
            "created_at": created_at,
            "source_database_digest": manifest["source_database_digest"],
            "archive": archive_descriptor,
            "manifest": _object_descriptor(manifest_reference),
            "manifest_digest": manifest["manifest_digest"],
        }
        receipt["receipt_digest"] = canonical_digest(receipt)
        return receipt


def main() -> int:
    print(json.dumps(create_backup(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
