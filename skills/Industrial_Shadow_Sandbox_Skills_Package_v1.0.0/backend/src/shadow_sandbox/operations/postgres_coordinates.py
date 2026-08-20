from __future__ import annotations

import os
from urllib.parse import parse_qs, unquote, urlsplit

from shadow_sandbox.common.models import DomainError, canonical_digest


def postgres_environment(database_url: str) -> dict[str, str]:
    try:
        parsed = urlsplit(database_url.replace("postgresql+psycopg://", "postgresql://", 1))
        host = parsed.hostname
        port = parsed.port if parsed.port is not None else 5432
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
        or not 1 <= port <= 65535
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
        supported_parameters = {
            "sslmode",
            "sslrootcert",
            "sslcert",
            "sslkey",
            "sslcrl",
        }
        unsupported_parameters = sorted(set(query) - supported_parameters)
        if unsupported_parameters:
            raise DomainError(
                "PRODUCTION_DATABASE_PARAMETER_INVALID",
                "production PostgreSQL URLs contain unsupported connection parameters",
                {"parameters": unsupported_parameters},
                status=503,
            )
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
            "PGCONNECT_TIMEOUT": "30",
            "PGAPPNAME": "industrial-shadow-postgresql-operation",
            "PGTZ": "UTC",
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
        port = parsed.port if parsed.port is not None else 5432
    except ValueError as error:
        raise DomainError("DATABASE_URL_INVALID", "PostgreSQL URL is malformed") from error
    database = unquote(parsed.path.removeprefix("/"))
    if (
        parsed.scheme != "postgresql"
        or not host
        or not database
        or "/" in database
        or parsed.fragment
        or not 1 <= port <= 65535
    ):
        raise DomainError("DATABASE_URL_INVALID", "PostgreSQL URL coordinate is invalid")
    return canonical_digest({"host": host, "port": port, "database": database})
