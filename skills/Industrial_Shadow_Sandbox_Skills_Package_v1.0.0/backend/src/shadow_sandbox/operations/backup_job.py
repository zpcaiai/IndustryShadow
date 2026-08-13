from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from shadow_sandbox.common.models import DomainError, canonical_json, utc_now
from shadow_sandbox.common.object_storage import create_object_storage


def postgres_environment(database_url: str) -> dict[str, str]:
    parsed = urlsplit(database_url.replace("postgresql+psycopg://", "postgresql://", 1))
    if parsed.scheme != "postgresql" or not parsed.hostname or not parsed.path.strip("/"):
        raise DomainError("DATABASE_URL_INVALID", "PostgreSQL backup URL is invalid", status=503)
    environment = dict(os.environ)
    query = parse_qs(parsed.query, keep_blank_values=False)
    sslmode = query.get("sslmode", ["require"])[-1]
    if sslmode not in {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}:
        raise DomainError("DATABASE_SSLMODE_INVALID", "PostgreSQL sslmode is invalid", status=503)
    if os.environ.get("SHADOW_ENVIRONMENT") == "production" and sslmode not in {
        "require",
        "verify-ca",
        "verify-full",
    }:
        raise DomainError(
            "PRODUCTION_DATABASE_TLS_REQUIRED",
            "production PostgreSQL operations require TLS",
            status=503,
        )
    environment.update(
        {
            "PGHOST": parsed.hostname,
            "PGPORT": str(parsed.port or 5432),
            "PGDATABASE": parsed.path.strip("/"),
            "PGUSER": unquote(parsed.username or ""),
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
            environment[variable] = unquote(query[parameter][-1])
    return environment


def create_backup() -> dict[str, object]:
    database_url = os.environ.get("SHADOW_DATABASE_URL", "")
    kms_key_id = os.environ.get("SHADOW_OBJECT_STORAGE_KMS_KEY_ID", "")
    if os.environ.get("SHADOW_ENVIRONMENT") == "production" and not kms_key_id.startswith("arn:"):
        raise DomainError(
            "PRODUCTION_KMS_KEY_REQUIRED",
            "production backups require an exact KMS key ARN",
            status=503,
        )
    pg_environment = postgres_environment(database_url)
    storage = create_object_storage(
        os.environ.get("SHADOW_OBJECT_STORAGE_BACKEND", "s3"),
        local_root=os.environ.get("SHADOW_OBJECT_STORAGE_ROOT", ".runtime/backups"),
        bucket=os.environ.get("SHADOW_OBJECT_STORAGE_BUCKET"),
        region=os.environ.get("SHADOW_OBJECT_STORAGE_REGION"),
        endpoint_url=os.environ.get("SHADOW_OBJECT_STORAGE_ENDPOINT"),
        prefix=os.environ.get("SHADOW_OBJECT_STORAGE_PREFIX", "industrial-shadow/backups"),
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
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        created_at = utc_now()
        date = created_at[:10]
        key = f"postgres/{date}/{digest}.dump"
        reference = storage.put_bytes(
            key, data, content_type="application/vnd.postgresql.custom-backup"
        )
        manifest = {
            "created_at": created_at,
            "object_key": reference.key,
            "size": reference.size,
            "sha256": reference.sha256,
            "format": "postgresql-custom",
            "verified_by": "pg_restore --list",
        }
        storage.put_bytes(
            key + ".manifest.json",
            canonical_json(manifest).encode("utf-8"),
            content_type="application/json",
        )
        return manifest


def main() -> int:
    print(json.dumps(create_backup(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
