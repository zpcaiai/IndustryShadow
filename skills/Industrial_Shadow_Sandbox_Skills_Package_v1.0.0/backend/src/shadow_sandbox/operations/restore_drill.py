from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import subprocess
import tempfile
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from shadow_sandbox.common.models import (
    DomainError,
    canonical_digest,
    canonical_json,
    utc_now,
)
from shadow_sandbox.common.object_storage import ObjectRef, ObjectStorage
from shadow_sandbox.common.sqlalchemy_store import SqlAlchemyStore
from shadow_sandbox.common.tenant_scope import workspace_scope

from .backup_job import postgres_environment
from .database_roles import (
    DatabaseRoleConfigurator,
    role_access_matrix,
    role_matrix_is_exact,
)
from .evidence import GateCheck, GateEvidence, complete

DIGEST = re.compile(r"^[a-f0-9]{64}$")
MAXIMUM_MANIFEST_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class BackupObjectVersion:
    key: str
    size: int
    sha256: str
    version_id: str
    encryption: str

    @classmethod
    def parse(cls, value: object, *, field: str) -> BackupObjectVersion:
        if not isinstance(value, Mapping) or set(value) != {
            "key",
            "size",
            "sha256",
            "version_id",
            "encryption",
        }:
            raise DomainError("BACKUP_RECEIPT_INVALID", f"{field} object descriptor is invalid")
        key = value.get("key")
        size = value.get("size")
        sha256 = value.get("sha256")
        version_id = value.get("version_id")
        encryption = value.get("encryption")
        if (
            not isinstance(key, str)
            or not key.startswith("postgres/")
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 1
            or not isinstance(sha256, str)
            or not DIGEST.fullmatch(sha256)
            or not isinstance(version_id, str)
            or not version_id.strip()
            or len(version_id) > 1024
            or encryption != "aws:kms"
        ):
            raise DomainError(
                "BACKUP_RECEIPT_INVALID",
                f"{field} must identify one versioned KMS-encrypted backup object",
            )
        return cls(key, size, sha256, version_id, encryption)

    def matches(self, reference: ObjectRef) -> bool:
        return (
            reference.key == self.key
            and reference.size == self.size
            and reference.sha256 == self.sha256
            and reference.version_id == self.version_id
            and reference.encryption == self.encryption
        )


@dataclass(frozen=True, slots=True)
class BackupRestoreReceipt:
    created_at: str
    source_database_digest: str
    archive: BackupObjectVersion
    manifest: BackupObjectVersion
    manifest_digest: str
    receipt_digest: str

    @classmethod
    def load(
        cls, path_value: str | Path, *, expected_source_database_digest: str
    ) -> BackupRestoreReceipt:
        path = Path(path_value)
        try:
            if (
                path.is_symlink()
                or not path.is_file()
                or path.stat().st_size > MAXIMUM_MANIFEST_BYTES
            ):
                raise DomainError(
                    "BACKUP_RECEIPT_INVALID", "backup receipt must be a bounded regular file"
                )
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise DomainError(
                "BACKUP_RECEIPT_INVALID", "backup receipt could not be read"
            ) from error
        if not isinstance(raw, Mapping) or set(raw) != {
            "schema_version",
            "created_at",
            "source_database_digest",
            "archive",
            "manifest",
            "manifest_digest",
            "receipt_digest",
        }:
            raise DomainError("BACKUP_RECEIPT_INVALID", "backup receipt fields are invalid")
        payload = {key: raw[key] for key in raw if key != "receipt_digest"}
        if raw.get("schema_version") != 1 or raw.get("receipt_digest") != canonical_digest(payload):
            raise DomainError("BACKUP_RECEIPT_INVALID", "backup receipt digest is invalid")
        created_at = raw.get("created_at")
        try:
            created = dt.datetime.fromisoformat(str(created_at))
        except ValueError as error:
            raise DomainError("BACKUP_RECEIPT_INVALID", "backup timestamp is invalid") from error
        if created.tzinfo is None or created.utcoffset() != dt.timedelta(0):
            raise DomainError("BACKUP_RECEIPT_INVALID", "backup timestamp must be UTC")
        source_digest = raw.get("source_database_digest")
        manifest_digest = raw.get("manifest_digest")
        receipt_digest = raw.get("receipt_digest")
        if (
            source_digest != expected_source_database_digest
            or not isinstance(manifest_digest, str)
            or not DIGEST.fullmatch(manifest_digest)
            or not isinstance(receipt_digest, str)
            or not DIGEST.fullmatch(receipt_digest)
        ):
            raise DomainError(
                "BACKUP_RECEIPT_INVALID", "backup receipt is not bound to the source database"
            )
        archive = BackupObjectVersion.parse(raw.get("archive"), field="archive")
        manifest = BackupObjectVersion.parse(raw.get("manifest"), field="manifest")
        if manifest.key != archive.key + ".manifest.json":
            raise DomainError(
                "BACKUP_RECEIPT_INVALID", "backup manifest key is not bound to its archive"
            )
        return cls(
            str(created_at),
            str(source_digest),
            archive,
            manifest,
            manifest_digest,
            receipt_digest,
        )

    def age_seconds(self) -> float:
        created = dt.datetime.fromisoformat(self.created_at)
        return (dt.datetime.now(dt.UTC) - created).total_seconds()


def _load_immutable_manifest(
    path: Path,
    *,
    receipt: BackupRestoreReceipt,
    expected_kms_key_digest: str,
) -> Mapping[str, object]:
    try:
        encoded = path.read_bytes()
        value = json.loads(encoded)
    except (OSError, json.JSONDecodeError, UnicodeError) as error:
        raise DomainError("BACKUP_MANIFEST_INVALID", "backup manifest is unreadable") from error
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "created_at",
        "source_database_digest",
        "archive",
        "kms_key_id_digest",
        "format",
        "verified_by",
        "manifest_digest",
    }:
        raise DomainError("BACKUP_MANIFEST_INVALID", "backup manifest fields are invalid")
    if canonical_json(value).encode("utf-8") != encoded:
        raise DomainError("BACKUP_MANIFEST_INVALID", "backup manifest is not canonical JSON")
    payload = {key: value[key] for key in value if key != "manifest_digest"}
    if (
        value.get("schema_version") != 2
        or value.get("manifest_digest") != canonical_digest(payload)
        or value.get("manifest_digest") != receipt.manifest_digest
        or value.get("created_at") != receipt.created_at
        or value.get("source_database_digest") != receipt.source_database_digest
        or value.get("archive")
        != {
            "key": receipt.archive.key,
            "size": receipt.archive.size,
            "sha256": receipt.archive.sha256,
            "version_id": receipt.archive.version_id,
            "encryption": receipt.archive.encryption,
        }
        or value.get("kms_key_id_digest") != expected_kms_key_digest
        or value.get("format") != "postgresql-custom"
        or value.get("verified_by") != "pg_restore --list"
    ):
        raise DomainError(
            "BACKUP_MANIFEST_INVALID", "backup manifest does not match the restore receipt"
        )
    return value


@dataclass(frozen=True, slots=True)
class _DatabaseCoordinate:
    host: str
    port: int
    database: str

    @property
    def digest(self) -> str:
        return canonical_digest({"host": self.host, "port": self.port, "database": self.database})


def _database_url_parts(url: str) -> tuple[_DatabaseCoordinate, str, Mapping[str, list[str]]]:
    try:
        parsed = urlsplit(url.replace("postgresql+psycopg://", "postgresql://", 1))
        port = parsed.port or 5432
    except ValueError as error:
        raise DomainError("DATABASE_URL_INVALID", "PostgreSQL URL is malformed") from error
    database = unquote(parsed.path.removeprefix("/"))
    if (
        parsed.scheme != "postgresql"
        or not parsed.hostname
        or not database
        or "/" in database
        or parsed.fragment
    ):
        raise DomainError("DATABASE_URL_INVALID", "PostgreSQL URL coordinate is invalid")
    query = parse_qs(parsed.query, keep_blank_values=True)
    coordinate = _DatabaseCoordinate(parsed.hostname.lower().rstrip("."), port, database)
    return coordinate, unquote(parsed.username or ""), query


def _verify_full(url: str) -> bool:
    _coordinate, _user, query = _database_url_parts(url)
    roots = query.get("sslrootcert", ())
    return (
        query.get("sslmode") == ["verify-full"]
        and len(roots) == 1
        and bool(unquote(roots[0]).strip())
    )


def _ordered_rows_digest(
    rows: Iterable[Mapping[str, object]], *, domain: str
) -> dict[str, int | str]:
    """Digest an already canonically ordered row stream without retaining it."""

    digest = hashlib.sha256()
    digest.update(b"industrial-shadow-ordered-multiset-v2\x00")
    encoded_domain = domain.encode("utf-8")
    digest.update(len(encoded_domain).to_bytes(8, "big"))
    digest.update(encoded_domain)
    count = 0
    for row in rows:
        encoded = canonical_json(row).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        count += 1
    digest.update(count.to_bytes(16, "big"))
    return {"count": count, "sha256": digest.hexdigest()}


def _table_inventory(store: SqlAlchemyStore) -> dict[str, dict[str, int | str]]:
    tables = [
        str(row["tablename"])
        for row in store.query(
            """SELECT relation.relname AS tablename
                 FROM pg_class relation
                 JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
                WHERE namespace.nspname='public'
                  AND relation.relkind IN ('r', 'p', 'm')
                  AND NOT relation.relispartition
             ORDER BY relation.relname COLLATE \"C\""""
        )
    ]
    inventory: dict[str, dict[str, int | str]] = {}
    for table in tables:
        quoted = '"' + table.replace('"', '""') + '"'
        rows = store.iterate(
            f"""SELECT TO_JSONB(item)::text AS row_json
                  FROM public.{quoted} AS item
              ORDER BY (TO_JSONB(item)::text) COLLATE \"C\"""",
            batch_size=32,
        )
        inventory[table] = _ordered_rows_digest(rows, domain=f"table:public.{table}")
    return inventory


def _rls_inventory(store: SqlAlchemyStore) -> dict[str, int | str]:
    return _ordered_rows_digest(
        store.iterate(
            """SELECT policyname, tablename, permissive, roles::text AS roles,
                      cmd, COALESCE(qual, '') AS using_expression,
                      COALESCE(with_check, '') AS check_expression
                 FROM pg_policies
                WHERE schemaname='public'
             ORDER BY tablename COLLATE \"C\", policyname COLLATE \"C\""""
        ),
        domain="catalog:public.rls-policies",
    )


CATALOG_QUERIES: tuple[tuple[str, str], ...] = (
    (
        "server",
        """SELECT current_setting('server_version_num') AS server_version_num,
                  current_setting('integer_datetimes') AS integer_datetimes""",
    ),
    (
        "relations",
        """SELECT relation.relname AS object_name,
                  relation.relkind::text AS relation_kind,
                  relation.relpersistence::text AS persistence,
                  relation.relreplident::text AS replica_identity,
                  relation.relrowsecurity AS row_security,
                  relation.relforcerowsecurity AS force_row_security,
                  relation.relispartition AS is_partition,
                  COALESCE(pg_get_expr(relation.relpartbound, relation.oid, true), '')
                    AS partition_bound,
                  COALESCE(pg_get_partkeydef(relation.oid), '') AS partition_key,
                  owner.rolname AS owner,
                  COALESCE(tablespace.spcname, '') AS tablespace
             FROM pg_class relation
             JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
             JOIN pg_roles owner ON owner.oid=relation.relowner
        LEFT JOIN pg_tablespace tablespace ON tablespace.oid=relation.reltablespace
            WHERE namespace.nspname='public'
              AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
         ORDER BY relation.relkind::text COLLATE \"C\", relation.relname COLLATE \"C\"""",
    ),
    (
        "columns",
        """SELECT relation.relname AS relation_name,
                  attribute.attnum AS ordinal,
                  attribute.attname AS column_name,
                  format_type(attribute.atttypid, attribute.atttypmod) AS data_type,
                  attribute.attnotnull AS not_null,
                  attribute.attidentity::text AS identity_kind,
                  attribute.attgenerated::text AS generated_kind,
                  attribute.attstorage::text AS storage_kind,
                  attribute.attstattarget AS statistics_target,
                  COALESCE(collation.collname, '') AS collation,
                  COALESCE(pg_get_expr(default_value.adbin, default_value.adrelid, true), '')
                    AS default_expression
             FROM pg_attribute attribute
             JOIN pg_class relation ON relation.oid=attribute.attrelid
             JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
        LEFT JOIN pg_attrdef default_value
               ON default_value.adrelid=attribute.attrelid
              AND default_value.adnum=attribute.attnum
        LEFT JOIN pg_collation collation ON collation.oid=attribute.attcollation
            WHERE namespace.nspname='public'
              AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
              AND attribute.attnum > 0
              AND NOT attribute.attisdropped
         ORDER BY relation.relname COLLATE \"C\", attribute.attnum""",
    ),
    (
        "constraints",
        """SELECT relation.relname AS relation_name,
                  constraint_object.conname AS constraint_name,
                  constraint_object.contype::text AS constraint_kind,
                  constraint_object.condeferrable AS deferrable,
                  constraint_object.condeferred AS initially_deferred,
                  constraint_object.convalidated AS validated,
                  constraint_object.connoinherit AS no_inherit,
                  pg_get_constraintdef(constraint_object.oid, true) AS definition
             FROM pg_constraint constraint_object
             JOIN pg_class relation ON relation.oid=constraint_object.conrelid
             JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
            WHERE namespace.nspname='public'
         ORDER BY relation.relname COLLATE \"C\",
                  constraint_object.conname COLLATE \"C\"""",
    ),
    (
        "indexes",
        """SELECT table_relation.relname AS relation_name,
                  index_relation.relname AS index_name,
                  owner.rolname AS owner,
                  access_method.amname AS access_method,
                  index_state.indisunique AS is_unique,
                  index_state.indisprimary AS is_primary,
                  index_state.indisexclusion AS is_exclusion,
                  index_state.indisclustered AS is_clustered,
                  index_state.indisreplident AS is_replica_identity,
                  index_state.indisvalid AS is_valid,
                  index_state.indisready AS is_ready,
                  index_state.indislive AS is_live,
                  pg_get_indexdef(index_relation.oid) AS definition,
                  COALESCE(pg_get_expr(index_state.indpred, index_state.indrelid, true), '')
                    AS predicate
             FROM pg_index index_state
             JOIN pg_class index_relation ON index_relation.oid=index_state.indexrelid
             JOIN pg_class table_relation ON table_relation.oid=index_state.indrelid
             JOIN pg_namespace namespace ON namespace.oid=table_relation.relnamespace
             JOIN pg_roles owner ON owner.oid=index_relation.relowner
             JOIN pg_am access_method ON access_method.oid=index_relation.relam
            WHERE namespace.nspname='public'
         ORDER BY table_relation.relname COLLATE \"C\",
                  index_relation.relname COLLATE \"C\"""",
    ),
    (
        "sequences",
        """SELECT sequence_relation.relname AS sequence_name,
                  format_type(sequence_state.seqtypid, NULL) AS data_type,
                  sequence_state.seqstart::text AS start_value,
                  sequence_state.seqincrement::text AS increment_by,
                  sequence_state.seqmax::text AS maximum_value,
                  sequence_state.seqmin::text AS minimum_value,
                  sequence_state.seqcache::text AS cache_size,
                  sequence_state.seqcycle AS cycles,
                  COALESCE(owner_relation.relname, '') AS owned_by_relation,
                  COALESCE(owner_attribute.attname, '') AS owned_by_column
             FROM pg_sequence sequence_state
             JOIN pg_class sequence_relation ON sequence_relation.oid=sequence_state.seqrelid
             JOIN pg_namespace namespace ON namespace.oid=sequence_relation.relnamespace
        LEFT JOIN pg_depend dependency
               ON dependency.classid='pg_class'::regclass
              AND dependency.objid=sequence_relation.oid
              AND dependency.objsubid=0
              AND dependency.refclassid='pg_class'::regclass
              AND dependency.deptype IN ('a', 'i')
        LEFT JOIN pg_class owner_relation ON owner_relation.oid=dependency.refobjid
        LEFT JOIN pg_attribute owner_attribute
               ON owner_attribute.attrelid=dependency.refobjid
              AND owner_attribute.attnum=dependency.refobjsubid
            WHERE namespace.nspname='public'
         ORDER BY sequence_relation.relname COLLATE \"C\"""",
    ),
    (
        "sequence_state",
        """SELECT sequencename AS sequence_name, last_value::text AS last_value
             FROM pg_sequences
            WHERE schemaname='public'
         ORDER BY sequencename COLLATE \"C\"""",
    ),
    (
        "views",
        """SELECT relation.relname AS view_name,
                  relation.relkind::text AS view_kind,
                  relation.relispopulated AS populated,
                  COALESCE(array_to_string(relation.reloptions, E'\\n'), '') AS options,
                  pg_get_viewdef(relation.oid, false) AS definition
             FROM pg_class relation
             JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
            WHERE namespace.nspname='public' AND relation.relkind IN ('v', 'm')
         ORDER BY relation.relkind::text COLLATE \"C\", relation.relname COLLATE \"C\"""",
    ),
    (
        "routines",
        """SELECT routine.proname AS routine_name,
                  pg_get_function_identity_arguments(routine.oid) AS identity_arguments,
                  pg_get_function_result(routine.oid) AS result_type,
                  routine.prokind::text AS routine_kind,
                  language.lanname AS language,
                  routine.provolatile::text AS volatility,
                  routine.proparallel::text AS parallel_safety,
                  routine.prosecdef AS security_definer,
                  routine.proleakproof AS leakproof,
                  routine.proisstrict AS strict,
                  routine.proretset AS returns_set,
                  routine.prosrc AS source,
                  COALESCE(routine.probin, '') AS binary_path,
                  COALESCE(pg_get_expr(routine.proargdefaults, 0, true), '')
                    AS argument_defaults,
                  COALESCE((SELECT string_agg(option, E'\\n' ORDER BY option COLLATE \"C\")
                              FROM unnest(routine.proconfig) AS option), '') AS configuration,
                  owner.rolname AS owner
             FROM pg_proc routine
             JOIN pg_namespace namespace ON namespace.oid=routine.pronamespace
             JOIN pg_language language ON language.oid=routine.prolang
             JOIN pg_roles owner ON owner.oid=routine.proowner
            WHERE namespace.nspname='public'
         ORDER BY routine.proname COLLATE \"C\",
                  pg_get_function_identity_arguments(routine.oid) COLLATE \"C\"""",
    ),
)

CATALOG_SECURITY_QUERIES: tuple[tuple[str, str], ...] = (
    (
        "triggers",
        """SELECT relation.relname AS relation_name,
                  trigger_object.tgname AS trigger_name,
                  trigger_object.tgenabled::text AS enabled_mode,
                  trigger_object.tgdeferrable AS deferrable,
                  trigger_object.tginitdeferred AS initially_deferred,
                  pg_get_triggerdef(trigger_object.oid, true) AS definition
             FROM pg_trigger trigger_object
             JOIN pg_class relation ON relation.oid=trigger_object.tgrelid
             JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
            WHERE namespace.nspname='public' AND NOT trigger_object.tgisinternal
         ORDER BY relation.relname COLLATE \"C\", trigger_object.tgname COLLATE \"C\"""",
    ),
    (
        "rules",
        """SELECT tablename, rulename, definition
             FROM pg_rules
            WHERE schemaname='public'
         ORDER BY tablename COLLATE \"C\", rulename COLLATE \"C\"""",
    ),
    (
        "types",
        """SELECT type_object.typname AS type_name,
                  type_object.typtype::text AS type_kind,
                  type_object.typcategory::text AS category,
                  type_object.typispreferred AS preferred,
                  type_object.typnotnull AS not_null,
                  format_type(type_object.typbasetype, type_object.typtypmod) AS base_type,
                  COALESCE(format_type(type_object.typelem, NULL), '') AS element_type,
                  COALESCE(collation.collname, '') AS collation,
                  COALESCE(type_object.typdefault, '') AS default_value,
                  owner.rolname AS owner
             FROM pg_type type_object
             JOIN pg_namespace namespace ON namespace.oid=type_object.typnamespace
             JOIN pg_roles owner ON owner.oid=type_object.typowner
        LEFT JOIN pg_collation collation ON collation.oid=type_object.typcollation
            WHERE namespace.nspname='public'
         ORDER BY type_object.typname COLLATE \"C\"""",
    ),
    (
        "enum_labels",
        """SELECT type_object.typname AS type_name,
                  enum_value.enumsortorder::text AS sort_order,
                  enum_value.enumlabel AS label
             FROM pg_enum enum_value
             JOIN pg_type type_object ON type_object.oid=enum_value.enumtypid
             JOIN pg_namespace namespace ON namespace.oid=type_object.typnamespace
            WHERE namespace.nspname='public'
         ORDER BY type_object.typname COLLATE \"C\", enum_value.enumsortorder""",
    ),
    (
        "extensions",
        """SELECT extension.extname AS extension_name,
                  extension.extversion AS version,
                  extension.extrelocatable AS relocatable,
                  namespace.nspname AS schema_name,
                  owner.rolname AS owner
             FROM pg_extension extension
             JOIN pg_namespace namespace ON namespace.oid=extension.extnamespace
             JOIN pg_roles owner ON owner.oid=extension.extowner
         ORDER BY extension.extname COLLATE \"C\"""",
    ),
    (
        "policies",
        """SELECT policyname, tablename, permissive, roles::text AS roles,
                  cmd, COALESCE(qual, '') AS using_expression,
                  COALESCE(with_check, '') AS check_expression
             FROM pg_policies
            WHERE schemaname='public'
         ORDER BY tablename COLLATE \"C\", policyname COLLATE \"C\"""",
    ),
    (
        "ownership",
        """SELECT object_kind, object_identity, owner
             FROM (
                   SELECT 'database' AS object_kind, '<database>' AS object_identity,
                          owner.rolname AS owner
                     FROM pg_database database_object
                     JOIN pg_roles owner ON owner.oid=database_object.datdba
                    WHERE database_object.datname=current_database()
                   UNION ALL
                   SELECT 'schema', namespace.nspname, owner.rolname
                     FROM pg_namespace namespace
                     JOIN pg_roles owner ON owner.oid=namespace.nspowner
                    WHERE namespace.nspname='public'
                   UNION ALL
                   SELECT 'relation:' || relation.relkind::text, relation.relname, owner.rolname
                     FROM pg_class relation
                     JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
                     JOIN pg_roles owner ON owner.oid=relation.relowner
                    WHERE namespace.nspname='public'
                   UNION ALL
                   SELECT 'routine', routine.proname || '(' ||
                          pg_get_function_identity_arguments(routine.oid) || ')', owner.rolname
                     FROM pg_proc routine
                     JOIN pg_namespace namespace ON namespace.oid=routine.pronamespace
                     JOIN pg_roles owner ON owner.oid=routine.proowner
                    WHERE namespace.nspname='public'
                   UNION ALL
                   SELECT 'type', type_object.typname, owner.rolname
                     FROM pg_type type_object
                     JOIN pg_namespace namespace ON namespace.oid=type_object.typnamespace
                     JOIN pg_roles owner ON owner.oid=type_object.typowner
                    WHERE namespace.nspname='public'
                   UNION ALL
                   SELECT 'extension', extension.extname, owner.rolname
                     FROM pg_extension extension
                     JOIN pg_roles owner ON owner.oid=extension.extowner
                  ) AS owned_objects
         ORDER BY object_kind COLLATE \"C\", object_identity COLLATE \"C\"""",
    ),
    (
        "object_privileges",
        """WITH secured_objects AS (
                  SELECT 'database' AS object_kind, '<database>' AS object_identity,
                         database_object.datdba AS owner_oid,
                         database_object.datacl AS acl, CAST('d' AS \"char\") AS default_kind
                    FROM pg_database database_object
                   WHERE database_object.datname=current_database()
                  UNION ALL
                  SELECT 'schema', namespace.nspname, namespace.nspowner,
                         namespace.nspacl, CAST('n' AS \"char\")
                    FROM pg_namespace namespace WHERE namespace.nspname='public'
                  UNION ALL
                  SELECT 'relation:' || relation.relkind::text, relation.relname,
                         relation.relowner, relation.relacl,
                         CASE WHEN relation.relkind='S' THEN CAST('S' AS \"char\")
                              ELSE CAST('r' AS \"char\") END
                    FROM pg_class relation
                    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
                   WHERE namespace.nspname='public'
                     AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
                  UNION ALL
                  SELECT 'routine', routine.proname || '(' ||
                         pg_get_function_identity_arguments(routine.oid) || ')',
                         routine.proowner, routine.proacl, CAST('f' AS \"char\")
                    FROM pg_proc routine
                    JOIN pg_namespace namespace ON namespace.oid=routine.pronamespace
                   WHERE namespace.nspname='public'
             )
           SELECT secured_objects.object_kind, secured_objects.object_identity,
                  grantor.rolname AS grantor,
                  CASE WHEN privilege.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END AS grantee,
                  privilege.privilege_type, privilege.is_grantable
             FROM secured_objects
       CROSS JOIN LATERAL aclexplode(
                  COALESCE(secured_objects.acl,
                           acldefault(secured_objects.default_kind, secured_objects.owner_oid))
             ) AS privilege
        LEFT JOIN pg_roles grantor ON grantor.oid=privilege.grantor
        LEFT JOIN pg_roles grantee ON grantee.oid=privilege.grantee
         ORDER BY secured_objects.object_kind COLLATE \"C\",
                  secured_objects.object_identity COLLATE \"C\",
                  grantee COLLATE \"C\", privilege.privilege_type COLLATE \"C\",
                  grantor COLLATE \"C\"""",
    ),
    (
        "default_privileges",
        """SELECT owner, schema_name, object_kind, grantor, grantee,
                  privilege_type, is_grantable
             FROM (
                   SELECT owner.rolname AS owner,
                          COALESCE(namespace.nspname, '') AS schema_name,
                          defaults.defaclobjtype::text AS object_kind,
                          '<entry>' AS grantor, '<entry>' AS grantee,
                          '<entry>' AS privilege_type, false AS is_grantable
                     FROM pg_default_acl defaults
                     JOIN pg_roles owner ON owner.oid=defaults.defaclrole
                LEFT JOIN pg_namespace namespace ON namespace.oid=defaults.defaclnamespace
                   UNION ALL
                   SELECT owner.rolname, COALESCE(namespace.nspname, ''),
                          defaults.defaclobjtype::text,
                          grantor.rolname,
                          CASE WHEN privilege.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,
                          privilege.privilege_type, privilege.is_grantable
                     FROM pg_default_acl defaults
                     JOIN pg_roles owner ON owner.oid=defaults.defaclrole
                LEFT JOIN pg_namespace namespace ON namespace.oid=defaults.defaclnamespace
               CROSS JOIN LATERAL aclexplode(
                          COALESCE(defaults.defaclacl, '{}'::aclitem[])
                     ) AS privilege
                LEFT JOIN pg_roles grantor ON grantor.oid=privilege.grantor
                LEFT JOIN pg_roles grantee ON grantee.oid=privilege.grantee
                  ) AS normalized_defaults
         ORDER BY owner COLLATE \"C\", schema_name COLLATE \"C\",
                  object_kind COLLATE \"C\", grantor COLLATE \"C\",
                  grantee COLLATE \"C\", privilege_type COLLATE \"C\",
                  is_grantable""",
    ),
)


def _sequence_runtime_state_inventory(store: SqlAlchemyStore) -> dict[str, int | str]:
    names = [
        str(row["sequence_name"])
        for row in store.query(
            """SELECT sequence.relname AS sequence_name
                 FROM pg_class sequence
                 JOIN pg_namespace namespace ON namespace.oid=sequence.relnamespace
                WHERE namespace.nspname='public' AND sequence.relkind='S'
             ORDER BY sequence.relname COLLATE \"C\""""
        )
    ]

    def rows() -> Iterable[Mapping[str, object]]:
        for name in names:
            quoted = '"' + name.replace('"', '""') + '"'
            state = tuple(
                store.iterate(
                    f"SELECT last_value::text AS last_value, is_called FROM public.{quoted}",
                    batch_size=1,
                )
            )
            if len(state) != 1:
                raise DomainError(
                    "RESTORE_SEQUENCE_STATE_INVALID",
                    "a public sequence did not expose exactly one runtime state row",
                    {"sequence": name},
                )
            yield {"sequence_name": name, **state[0]}

    return _ordered_rows_digest(rows(), domain="catalog:sequence-runtime-state")


def _catalog_inventory(store: SqlAlchemyStore) -> dict[str, object]:
    sections: dict[str, dict[str, int | str]] = {}
    for name, sql in (*CATALOG_QUERIES, *CATALOG_SECURITY_QUERIES):
        sections[name] = _ordered_rows_digest(
            store.iterate(sql, batch_size=128), domain=f"catalog:{name}"
        )
    sections["sequence_runtime_state"] = _sequence_runtime_state_inventory(store)
    return {
        "sha256": canonical_digest(sections),
        "objects": sum(int(section["count"]) for section in sections.values()),
        "sections": sections,
    }


class PostgreSqlRestoreDrill:
    """Restore one immutable, version-bound backup into a disposable managed database."""

    def __init__(
        self,
        source_url: str,
        target_url: str,
        *,
        allow_restore: bool,
        application_target_url: str | None = None,
        backup_target_url: str | None = None,
        tenant_roles: Sequence[str] = (),
        maintenance_role: str | None = None,
        backup_role: str | None = None,
        maximum_restore_seconds: int = 1800,
        maximum_archive_bytes: int = 100 * 1024 * 1024 * 1024,
        managed_provider: str | None = None,
        managed_instance_digest: str | None = None,
        require_managed_coordinates: bool = False,
        object_storage: ObjectStorage | None = None,
        backup_receipt_path: str | Path | None = None,
        kms_key_id: str | None = None,
        maximum_rpo_seconds: int = 86400,
        require_immutable_backup: bool = False,
    ) -> None:
        source_coordinate, source_user, _source_query = _database_url_parts(source_url)
        target_coordinate, target_user, _target_query = _database_url_parts(target_url)
        source_name = source_coordinate.database
        target_name = target_coordinate.database
        if source_coordinate == target_coordinate:
            raise DomainError("RESTORE_TARGET_INVALID", "source and restore target must differ")
        if not re.fullmatch(r"[a-zA-Z0-9_]*restore_drill[a-zA-Z0-9_]*", target_name):
            raise DomainError(
                "RESTORE_TARGET_INVALID", "target database name must contain restore_drill"
            )
        if not allow_restore:
            raise DomainError(
                "RESTORE_CONFIRMATION_REQUIRED",
                "explicit destructive restore confirmation is required",
            )
        self.source_url = source_url
        self.target_url = target_url
        self.source_name = source_name
        self.target_name = target_name
        self.source_coordinate = source_coordinate
        self.target_coordinate = target_coordinate
        self.application_target_url = application_target_url
        self.backup_target_url = backup_target_url
        self.application_role: str | None = None
        self.restore_role = target_user
        self.tenant_roles = tuple(tenant_roles)
        self.maintenance_role = maintenance_role
        self.backup_role = backup_role
        self.maximum_restore_seconds = maximum_restore_seconds
        self.maximum_archive_bytes = maximum_archive_bytes
        self.managed_provider = managed_provider
        self.managed_instance_digest = managed_instance_digest
        self.object_storage = object_storage
        self.backup_receipt_path = backup_receipt_path
        self.kms_key_id = kms_key_id
        self.maximum_rpo_seconds = maximum_rpo_seconds
        self.require_immutable_backup = require_immutable_backup
        if maximum_restore_seconds < 1 or maximum_archive_bytes < 1 or maximum_rpo_seconds < 1:
            raise DomainError("RESTORE_THRESHOLD_INVALID", "restore thresholds must be positive")
        if require_immutable_backup and (
            object_storage is None
            or backup_receipt_path is None
            or not kms_key_id
            or not kms_key_id.startswith("arn:aws:kms:")
        ):
            raise DomainError(
                "IMMUTABLE_BACKUP_REQUIRED",
                "production restore requires object storage, a backup receipt, and a KMS key ARN",
            )
        if require_managed_coordinates and (
            not managed_provider
            or managed_provider.lower() in {"local", "localhost", "self-managed"}
            or not managed_instance_digest
            or not re.fullmatch(r"[a-f0-9]{64}", managed_instance_digest)
        ):
            raise DomainError(
                "MANAGED_POSTGRESQL_COORDINATES_REQUIRED",
                "managed provider and instance digest are required",
            )
        role_configuration_supplied = any(
            (
                application_target_url,
                backup_target_url,
                tenant_roles,
                maintenance_role,
                backup_role,
            )
        )
        role_configuration_complete = bool(
            application_target_url
            and backup_target_url
            and tenant_roles
            and maintenance_role
            and backup_role
        )
        if (
            role_configuration_supplied or require_managed_coordinates
        ) and not role_configuration_complete:
            raise DomainError(
                "RESTORE_ROLE_CONFIG_INVALID",
                "application URL and all runtime role names must be supplied together",
            )
        if role_configuration_complete:
            application_coordinate, application_user, _application_query = _database_url_parts(
                str(application_target_url)
            )
            backup_coordinate, backup_user, _backup_query = _database_url_parts(
                str(backup_target_url)
            )
            if (
                application_coordinate != target_coordinate
                or backup_coordinate != target_coordinate
            ):
                raise DomainError(
                    "RESTORE_TARGET_BINDING_INVALID",
                    "application and backup checks must connect to the exact restore target",
                )
            runtime_roles = {*self.tenant_roles, str(maintenance_role), str(backup_role)}
            if (
                not target_user
                or target_user in runtime_roles
                or source_user != backup_role
                or application_user not in self.tenant_roles
                or backup_user != backup_role
            ):
                raise DomainError(
                    "RESTORE_ROLE_BINDING_INVALID",
                    "database URL users must match the migration, tenant, and backup role contract",
                )
            self.application_role = application_user
        if require_managed_coordinates and not all(
            _verify_full(value)
            for value in (
                source_url,
                target_url,
                str(application_target_url or ""),
                str(backup_target_url or ""),
            )
        ):
            raise DomainError(
                "MANAGED_POSTGRESQL_TLS_REQUIRED",
                "managed restore connections require verify-full and an explicit CA root",
            )

    @staticmethod
    def _run(command: list[str], environment: dict[str, str], timeout: int) -> None:
        completed = subprocess.run(
            command,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode:
            raise DomainError(
                "RESTORE_COMMAND_FAILED",
                "PostgreSQL backup or restore command failed",
                {"command": command[0], "exit_code": completed.returncode},
                status=503,
            )

    def _fetch_immutable_backup(
        self,
        directory: Path,
        *,
        receipt: BackupRestoreReceipt,
        kms_key_digest: str,
    ) -> tuple[Path, ObjectRef, ObjectRef, float]:
        if self.object_storage is None:
            raise DomainError("IMMUTABLE_BACKUP_REQUIRED", "object storage is required")
        manifest_path = directory / "backup.manifest.json"
        fetch_started = time.monotonic()
        manifest_reference = self.object_storage.get_file(
            receipt.manifest.key,
            manifest_path,
            maximum_bytes=MAXIMUM_MANIFEST_BYTES,
            expected_sha256=receipt.manifest.sha256,
            version_id=receipt.manifest.version_id,
        )
        if not receipt.manifest.matches(manifest_reference):
            raise DomainError(
                "BACKUP_MANIFEST_INVALID",
                "object storage returned a different backup manifest version",
            )
        _load_immutable_manifest(
            manifest_path,
            receipt=receipt,
            expected_kms_key_digest=kms_key_digest,
        )
        archive = directory / "database.dump"
        archive_reference = self.object_storage.get_file(
            receipt.archive.key,
            archive,
            maximum_bytes=self.maximum_archive_bytes,
            expected_sha256=receipt.archive.sha256,
            version_id=receipt.archive.version_id,
        )
        if not receipt.archive.matches(archive_reference):
            raise DomainError(
                "BACKUP_ARCHIVE_INVALID",
                "object storage returned a different backup archive version",
            )
        return (
            archive,
            manifest_reference,
            archive_reference,
            time.monotonic() - fetch_started,
        )

    def run(self) -> GateEvidence:
        started = utc_now()
        restore_started = time.monotonic()
        if self.object_storage is None or self.backup_receipt_path is None or not self.kms_key_id:
            raise DomainError(
                "IMMUTABLE_BACKUP_REQUIRED",
                "restore drills require an immutable version-bound backup receipt",
            )
        receipt = BackupRestoreReceipt.load(
            self.backup_receipt_path,
            expected_source_database_digest=self.source_coordinate.digest,
        )
        backup_age_seconds = receipt.age_seconds()
        if backup_age_seconds < -300:
            raise DomainError("BACKUP_RECEIPT_INVALID", "backup timestamp is in the future")
        kms_key_digest = canonical_digest({"kms_key_id": self.kms_key_id})
        source = SqlAlchemyStore(self.source_url)
        target = SqlAlchemyStore(self.target_url)
        try:
            existing = target.query(
                """SELECT COUNT(*) AS count
                     FROM (
                           SELECT relation.oid
                             FROM pg_class relation
                             JOIN pg_namespace namespace
                               ON namespace.oid=relation.relnamespace
                            WHERE namespace.nspname='public'
                              AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
                           UNION ALL
                           SELECT routine.oid
                             FROM pg_proc routine
                             JOIN pg_namespace namespace
                               ON namespace.oid=routine.pronamespace
                            WHERE namespace.nspname='public'
                           UNION ALL
                           SELECT type_object.oid
                             FROM pg_type type_object
                             JOIN pg_namespace namespace
                               ON namespace.oid=type_object.typnamespace
                            WHERE namespace.nspname='public'
                         ) AS existing_objects"""
            )[0]
            if int(existing["count"]):
                raise DomainError(
                    "RESTORE_TARGET_NOT_EMPTY",
                    "restore target public schema must contain no pre-existing objects",
                )
            source_inventory = _table_inventory(source)
            source_policies = _rls_inventory(source)
            source_catalog = _catalog_inventory(source)
            source_role_valid = True
            if self.backup_role:
                source_role = source.query(
                    """SELECT current_user AS role, roles.rolbypassrls AS bypass,
                              EXISTS (
                                SELECT 1 FROM pg_class relation
                                JOIN pg_namespace namespace
                                  ON namespace.oid=relation.relnamespace
                                WHERE namespace.nspname='public'
                                  AND relation.relowner=roles.oid
                              ) AS owns_tables,
                              EXISTS (
                                SELECT 1 FROM pg_proc routine
                                JOIN pg_namespace namespace
                                  ON namespace.oid=routine.pronamespace
                                WHERE namespace.nspname='public'
                                  AND routine.proowner=roles.oid
                              ) AS owns_routines
                         FROM pg_roles roles WHERE roles.rolname=current_user"""
                )[0]
                source_matrix = role_access_matrix(source, self.backup_role)
                source_role_valid = (
                    source_role["role"] == self.backup_role
                    and bool(source_role["bypass"])
                    and not bool(source_role["owns_tables"])
                    and not bool(source_role["owns_routines"])
                    and role_matrix_is_exact(source_matrix, read_write=False)
                )
            with tempfile.TemporaryDirectory(prefix="shadow-restore-drill-") as directory:
                directory_path = Path(directory)
                (
                    archive,
                    manifest_reference,
                    archive_reference,
                    object_fetch_seconds,
                ) = self._fetch_immutable_backup(
                    directory_path,
                    receipt=receipt,
                    kms_key_digest=kms_key_digest,
                )
                database_restore_started = time.monotonic()
                self._run(
                    ["pg_restore", "--list", str(archive)],
                    postgres_environment(self.target_url),
                    300,
                )
                self._run(
                    [
                        "pg_restore",
                        "--exit-on-error",
                        "--no-owner",
                        "--no-acl",
                        "--single-transaction",
                        "--dbname",
                        self.target_name,
                        str(archive),
                    ],
                    postgres_environment(self.target_url),
                    3600,
                )
                database_restore_seconds = time.monotonic() - database_restore_started
                archive_digest = archive_reference.sha256
                archive_bytes = archive_reference.size

            role_result: Mapping[str, object] = {}
            if self.application_target_url:
                role_result = DatabaseRoleConfigurator(
                    target,
                    tenant_roles=self.tenant_roles,
                    maintenance_role=str(self.maintenance_role),
                    backup_role=str(self.backup_role),
                ).configure()

            target_inventory = _table_inventory(target)
            target_policies = _rls_inventory(target)
            target_catalog = _catalog_inventory(target)
            source_versions = tuple(
                int(item["version"])
                for item in source.query("SELECT version FROM schema_migrations ORDER BY version")
            )
            target_versions = tuple(
                int(item["version"])
                for item in target.query("SELECT version FROM schema_migrations ORDER BY version")
            )
            source_head = source_versions[-1] if source_versions else 0
            target_integrity = target.query(
                """SELECT NOT pg_is_in_recovery() AS writable,
                          current_database() AS database,
                          current_user AS role"""
            )[0]
            integrity = target.query(
                """SELECT
                       (SELECT COUNT(*) FROM pg_constraint WHERE NOT convalidated) AS invalid_constraints,
                       (SELECT COUNT(*) FROM pg_index WHERE NOT indisvalid) AS invalid_indexes"""
            )[0]
            checks_list = [
                GateCheck("immutable_backup_receipt", bool(receipt.receipt_digest)),
                GateCheck("manifest_version_bound", receipt.manifest.matches(manifest_reference)),
                GateCheck("archive_version_bound", receipt.archive.matches(archive_reference)),
                GateCheck(
                    "backup_rpo",
                    0 <= backup_age_seconds <= self.maximum_rpo_seconds,
                    {"maximum_seconds": self.maximum_rpo_seconds},
                ),
                GateCheck("source_backup_role", source_role_valid),
                GateCheck(
                    "migration_history",
                    source_versions == target_versions
                    and source_versions == tuple(range(1, source_head + 1)),
                ),
                GateCheck("table_inventory", set(source_inventory) == set(target_inventory)),
                GateCheck("row_content_fingerprints", source_inventory == target_inventory),
                GateCheck(
                    "rls_policies",
                    source_policies == target_policies and int(target_policies["count"]) > 0,
                ),
                GateCheck(
                    "catalog_equivalence",
                    source_catalog == target_catalog,
                    {
                        "catalog_sections": len(CATALOG_QUERIES)
                        + len(CATALOG_SECURITY_QUERIES)
                        + 1
                    },
                ),
                GateCheck(
                    "restored_database_online",
                    bool(target_integrity["writable"])
                    and target_integrity["database"] == self.target_name
                    and target_integrity["role"] == self.restore_role,
                ),
                GateCheck(
                    "archive_size_bound",
                    0 < archive_bytes <= self.maximum_archive_bytes,
                    {"maximum_bytes": self.maximum_archive_bytes},
                ),
                GateCheck(
                    "catalog_integrity",
                    int(integrity["invalid_constraints"]) == 0
                    and int(integrity["invalid_indexes"]) == 0,
                ),
            ]
            if self.application_target_url:
                application = SqlAlchemyStore(self.application_target_url)
                try:
                    role = application.query(
                        """SELECT current_user AS role,
                                  roles.rolbypassrls AS bypass,
                                  EXISTS (
                                    SELECT 1 FROM pg_class relation
                                    JOIN pg_namespace namespace
                                      ON namespace.oid=relation.relnamespace
                                    WHERE namespace.nspname='public'
                                      AND relation.relowner=roles.oid
                                  ) AS owns_tables,
                                  EXISTS (
                                    SELECT 1 FROM pg_proc routine
                                    JOIN pg_namespace namespace
                                      ON namespace.oid=routine.pronamespace
                                    WHERE namespace.nspname='public'
                                      AND routine.proowner=roles.oid
                                  ) AS owns_routines
                             FROM pg_roles roles WHERE roles.rolname=current_user"""
                    )[0]
                    application_matrix = role_access_matrix(
                        application, str(self.application_role)
                    )
                    workspaces = target.query(
                        """SELECT workspace_id, COUNT(*) AS count FROM domain_resources
                             GROUP BY workspace_id ORDER BY workspace_id LIMIT 1"""
                    )
                    unscoped = application.query("SELECT COUNT(*) AS count FROM domain_resources")
                    scoped_count = 0
                    if workspaces:
                        with workspace_scope(str(workspaces[0]["workspace_id"])):
                            scoped_count = int(
                                application.query("SELECT COUNT(*) AS count FROM domain_resources")[
                                    0
                                ]["count"]
                            )
                    checks_list.extend(
                        (
                            GateCheck(
                                "runtime_role_least_privilege",
                                role["role"] == self.application_role
                                and not bool(role["bypass"])
                                and not bool(role["owns_tables"])
                                and not bool(role["owns_routines"])
                                and role_matrix_is_exact(
                                    application_matrix, read_write=True
                                ),
                            ),
                            GateCheck(
                                "restored_rls_unscoped_denial",
                                bool(workspaces) and int(unscoped[0]["count"]) == 0,
                            ),
                            GateCheck("restored_rls_workspace_visibility", scoped_count > 0),
                            GateCheck("runtime_grants_reapplied", bool(role_result)),
                        )
                    )
                finally:
                    application.close()
                backup = SqlAlchemyStore(str(self.backup_target_url))
                try:
                    backup_state = backup.query(
                        """SELECT current_user AS role, roles.rolbypassrls AS bypass,
                                  EXISTS (
                                    SELECT 1 FROM pg_class relation
                                    JOIN pg_namespace namespace
                                      ON namespace.oid=relation.relnamespace
                                    WHERE namespace.nspname='public'
                                      AND relation.relowner=roles.oid
                                  ) AS owns_tables,
                                  EXISTS (
                                    SELECT 1 FROM pg_proc routine
                                    JOIN pg_namespace namespace
                                      ON namespace.oid=routine.pronamespace
                                    WHERE namespace.nspname='public'
                                      AND routine.proowner=roles.oid
                                  ) AS owns_routines
                             FROM pg_roles roles WHERE roles.rolname=current_user"""
                    )[0]
                    backup_matrix = role_access_matrix(backup, str(self.backup_role))
                    backup_rows = int(
                        backup.query("SELECT COUNT(*) AS count FROM domain_resources")[0]["count"]
                    )
                    expected_rows = int(
                        target.query("SELECT COUNT(*) AS count FROM domain_resources")[0]["count"]
                    )
                    checks_list.extend(
                        (
                            GateCheck(
                                "backup_role_identity",
                                backup_state["role"] == self.backup_role
                                and bool(backup_state["bypass"])
                                and not bool(backup_state["owns_tables"])
                                and not bool(backup_state["owns_routines"]),
                            ),
                            GateCheck(
                                "backup_role_read_only",
                                role_matrix_is_exact(backup_matrix, read_write=False),
                            ),
                            GateCheck(
                                "backup_role_complete_visibility",
                                backup_rows == expected_rows,
                            ),
                        )
                    )
                finally:
                    backup.close()
            restore_seconds = time.monotonic() - restore_started
            checks_list.append(
                GateCheck(
                    "restore_rto",
                    restore_seconds <= self.maximum_restore_seconds,
                    {"maximum_seconds": self.maximum_restore_seconds},
                )
            )
            checks = tuple(checks_list)
            return complete(
                "backup_restore",
                started_at=started,
                coordinates={
                    "source_database_digest": self.source_coordinate.digest,
                    "target_database_digest": self.target_coordinate.digest,
                    "archive_digest": archive_digest,
                    "archive_version_digest": canonical_digest(
                        {"version_id": receipt.archive.version_id}
                    ),
                    "backup_manifest_digest": receipt.manifest_digest,
                    "backup_receipt_digest": receipt.receipt_digest,
                    "restored_catalog_digest": str(target_catalog["sha256"]),
                    "kms_key_id_digest": kms_key_digest,
                    "managed_provider": self.managed_provider or "not-required",
                    "managed_instance_digest": self.managed_instance_digest or "not-required",
                },
                checks=checks,
                metrics={
                    "tables": len(target_inventory),
                    "rows": sum(int(item["count"]) for item in target_inventory.values()),
                    "migration_head": source_head,
                    "rls_policies": int(target_policies["count"]),
                    "catalog_objects": int(str(target_catalog["objects"])),
                    "archive_bytes": archive_bytes,
                    "backup_age_seconds": round(max(0.0, backup_age_seconds), 3),
                    "object_fetch_seconds": round(object_fetch_seconds, 3),
                    "database_restore_seconds": round(database_restore_seconds, 3),
                    "restore_seconds": round(restore_seconds, 3),
                },
            )
        finally:
            source.close()
            target.close()
