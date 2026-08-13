from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .models import ActorContext, DomainError, canonical_digest, canonical_json, utc_now
from .store import Store

try:
    from sqlalchemy.exc import IntegrityError as SqlAlchemyIntegrityError
except ImportError:
    SqlAlchemyIntegrityError = type("SqlAlchemyIntegrityError", (Exception,), {})


@dataclass(frozen=True, slots=True)
class Resource:
    resource_type: str
    resource_id: str
    tenant_id: str
    workspace_id: str
    state: str
    version: int
    payload: Mapping[str, Any]
    digest: str
    sealed: bool
    created_at: str
    updated_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "tenant_id": self.tenant_id,
            "workspace_id": self.workspace_id,
            "state": self.state,
            "version": self.version,
            "payload": dict(self.payload),
            "digest": self.digest,
            "sealed": self.sealed,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class ResourceRepository:
    """Tenant-scoped CRUD with history, optimistic locking and immutable seals."""

    def __init__(self, store: Store) -> None:
        self.store = store

    @staticmethod
    def _decode(row: Mapping[str, Any]) -> Resource:
        return Resource(
            resource_type=str(row["resource_type"]),
            resource_id=str(row["resource_id"]),
            tenant_id=str(row.get("tenant_id", "")),
            workspace_id=str(row["workspace_id"]),
            state=str(row["state"]),
            version=int(row["version"]),
            payload=json.loads(str(row["payload"])),
            digest=str(row["digest"]),
            sealed=bool(row.get("sealed", 1)),
            created_at=str(row["created_at"]),
            updated_at=str(row.get("updated_at", row["created_at"])),
        )

    def create(
        self,
        actor: ActorContext,
        resource_type: str,
        resource_id: str,
        payload: Mapping[str, Any],
        *,
        state: str = "DRAFT",
        sealed: bool = False,
    ) -> Resource:
        now = utc_now()
        digest = canonical_digest(payload)
        encoded = canonical_json(payload)
        try:
            with self.store.transaction() as tx:
                tx.execute(
                    """INSERT INTO domain_resources
                       (resource_type, resource_id, tenant_id, workspace_id, state,
                        version, payload, digest, sealed, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)""",
                    (
                        resource_type,
                        resource_id,
                        actor.tenant_id,
                        actor.workspace_id,
                        state,
                        encoded,
                        digest,
                        sealed,
                        now,
                        now,
                    ),
                )
                tx.execute(
                    """INSERT INTO domain_resource_versions
                       (resource_type, resource_id, workspace_id, version, state,
                        payload, digest, created_at)
                       VALUES (?, ?, ?, 1, ?, ?, ?, ?)""",
                    (resource_type, resource_id, actor.workspace_id, state, encoded, digest, now),
                )
        except (sqlite3.IntegrityError, SqlAlchemyIntegrityError) as exc:
            raise DomainError(
                "RESOURCE_EXISTS", f"{resource_type} already exists", status=409
            ) from exc
        return self.get(actor, resource_type, resource_id)

    def get(self, actor: ActorContext, resource_type: str, resource_id: str) -> Resource:
        rows = self.store.query(
            """SELECT * FROM domain_resources
               WHERE resource_type=? AND resource_id=? AND workspace_id=?""",
            (resource_type, resource_id, actor.workspace_id),
        )
        if not rows:
            raise DomainError("RESOURCE_NOT_FOUND", f"{resource_type} not found", status=404)
        return self._decode(rows[0])

    def get_version(
        self, actor: ActorContext, resource_type: str, resource_id: str, version: int
    ) -> Resource:
        rows = self.store.query(
            """SELECT resource_type, resource_id, '' AS tenant_id, workspace_id,
                      state, version, payload, digest, 1 AS sealed,
                      created_at, created_at AS updated_at
                 FROM domain_resource_versions
                WHERE resource_type=? AND resource_id=? AND workspace_id=? AND version=?""",
            (resource_type, resource_id, actor.workspace_id, version),
        )
        if not rows:
            raise DomainError(
                "RESOURCE_VERSION_NOT_FOUND", "resource version not found", status=404
            )
        return self._decode(rows[0])

    def list(
        self,
        actor: ActorContext,
        resource_type: str,
        *,
        state: str | None = None,
        limit: int = 100,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        if not 1 <= limit <= 500:
            raise DomainError("INVALID_LIMIT", "limit must be within 1..500")
        sql = "SELECT * FROM domain_resources WHERE resource_type=? AND workspace_id=?"
        params: list[Any] = [resource_type, actor.workspace_id]
        if state:
            sql += " AND state=?"
            params.append(state)
        if cursor:
            sql += " AND resource_id>?"
            params.append(cursor)
        sql += " ORDER BY resource_id LIMIT ?"
        params.append(limit + 1)
        resources = [self._decode(row) for row in self.store.query(sql, params)]
        next_cursor = resources[limit - 1].resource_id if len(resources) > limit else None
        return {
            "items": [item.as_dict() for item in resources[:limit]],
            "next_cursor": next_cursor,
        }

    def update(
        self,
        actor: ActorContext,
        resource_type: str,
        resource_id: str,
        payload: Mapping[str, Any],
        *,
        expected_version: int,
        state: str | None = None,
        seal: bool = False,
    ) -> Resource:
        now = utc_now()
        digest = canonical_digest(payload)
        encoded = canonical_json(payload)
        with self.store.transaction() as tx:
            row = tx.execute(
                """SELECT * FROM domain_resources
                   WHERE resource_type=? AND resource_id=? AND workspace_id=?""",
                (resource_type, resource_id, actor.workspace_id),
            ).fetchone()
            if not row:
                raise DomainError("RESOURCE_NOT_FOUND", f"{resource_type} not found", status=404)
            if row["sealed"]:
                raise DomainError("RESOURCE_SEALED", "sealed resources are immutable", status=409)
            if int(row["version"]) != expected_version:
                raise DomainError("STALE_VERSION", "resource version changed", status=409)
            next_version = expected_version + 1
            next_state = state or str(row["state"])
            tx.execute(
                """UPDATE domain_resources SET state=?, version=?, payload=?, digest=?,
                          sealed=?, updated_at=?
                     WHERE resource_type=? AND resource_id=? AND workspace_id=?""",
                (
                    next_state,
                    next_version,
                    encoded,
                    digest,
                    seal,
                    now,
                    resource_type,
                    resource_id,
                    actor.workspace_id,
                ),
            )
            tx.execute(
                """INSERT INTO domain_resource_versions
                   (resource_type, resource_id, workspace_id, version, state,
                    payload, digest, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    resource_type,
                    resource_id,
                    actor.workspace_id,
                    next_version,
                    next_state,
                    encoded,
                    digest,
                    now,
                ),
            )
        return self.get(actor, resource_type, resource_id)
