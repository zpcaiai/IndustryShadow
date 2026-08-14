from __future__ import annotations

import inspect
import unittest
from collections.abc import Iterator, Sequence

from shadow_sandbox.common.sqlalchemy_store import SqlAlchemyStore
from shadow_sandbox.operations.restore_drill import (
    CATALOG_QUERIES,
    CATALOG_SECURITY_QUERIES,
    _catalog_inventory,
    _table_inventory,
)


class TableInventoryStore:
    def __init__(self, physical_rows: Sequence[dict[str, str]]) -> None:
        self.physical_rows = tuple(physical_rows)
        self.batch_sizes: list[int] = []
        self.sql: list[str] = []

    def query(self, sql: str, _parameters: object = ()) -> list[dict[str, str]]:
        if "AS tablename" not in sql or "relation.relkind IN ('r', 'p', 'm')" not in sql:
            raise AssertionError(sql)
        return [{"tablename": "events"}]

    def iterate(
        self, sql: str, _parameters: object = (), *, batch_size: int = 128
    ) -> Iterator[dict[str, str]]:
        self.sql.append(sql)
        self.batch_sizes.append(batch_size)
        if "ORDER BY (TO_JSONB(item)::text) COLLATE \"C\"" not in sql:
            raise AssertionError("table digest query must impose a canonical database order")
        yield from sorted(self.physical_rows, key=lambda row: row["row_json"])


class CatalogStore:
    def __init__(self, overrides: dict[str, str] | None = None) -> None:
        self.overrides = overrides or {}
        self.by_sql = {
            sql: name for name, sql in (*CATALOG_QUERIES, *CATALOG_SECURITY_QUERIES)
        }

    def query(self, sql: str, _parameters: object = ()) -> list[dict[str, str]]:
        if "AS sequence_name" not in sql:
            raise AssertionError(sql)
        return []

    def iterate(
        self, sql: str, _parameters: object = (), *, batch_size: int = 128
    ) -> Iterator[dict[str, str]]:
        if batch_size != 128:
            raise AssertionError("catalog reads must remain bounded")
        name = self.by_sql[sql]
        yield {"catalog_value": self.overrides.get(name, name)}


class PostgreSqlRestoreCatalogTests(unittest.TestCase):
    def test_table_digest_is_sha256_order_independent_and_multiplicity_sensitive(
        self,
    ) -> None:
        one = {"row_json": '{"id":1,"value":"one"}'}
        two = {"row_json": '{"id":2,"value":"two"}'}
        forward = TableInventoryStore((one, two, one))
        reverse = TableInventoryStore((one, two, one)[::-1])

        forward_inventory = _table_inventory(forward)  # type: ignore[arg-type]
        reverse_inventory = _table_inventory(reverse)  # type: ignore[arg-type]

        self.assertEqual(forward_inventory, reverse_inventory)
        self.assertEqual(3, forward_inventory["events"]["count"])
        self.assertEqual(64, len(str(forward_inventory["events"]["sha256"])))
        without_duplicate = _table_inventory(  # type: ignore[arg-type]
            TableInventoryStore((one, two))
        )
        self.assertNotEqual(
            forward_inventory["events"]["sha256"],
            without_duplicate["events"]["sha256"],
        )
        self.assertEqual([32], forward.batch_sizes)
        self.assertNotIn("MD5", forward.sql[0].upper())
        self.assertNotIn("STRING_AGG", forward.sql[0].upper())

    def test_catalog_digest_binds_all_restore_sensitive_sections(self) -> None:
        names = {
            name for name, _sql in (*CATALOG_QUERIES, *CATALOG_SECURITY_QUERIES)
        }
        self.assertTrue(
            {
                "sequences",
                "sequence_state",
                "sequence_runtime_state",
                "views",
                "routines",
                "triggers",
                "extensions",
                "ownership",
                "object_privileges",
                "default_privileges",
                "policies",
            }.issubset({*names, "sequence_runtime_state"})
        )
        baseline = _catalog_inventory(CatalogStore())  # type: ignore[arg-type]
        changed = _catalog_inventory(  # type: ignore[arg-type]
            CatalogStore({"triggers": "different-trigger-definition"})
        )
        self.assertNotEqual(baseline["sha256"], changed["sha256"])
        self.assertEqual(len(names) + 1, len(baseline["sections"]))  # type: ignore[arg-type]

    def test_streaming_store_uses_server_cursor_and_utc_rendering(self) -> None:
        source = inspect.getsource(SqlAlchemyStore.iterate)
        self.assertIn("stream_results=True", source)
        self.assertIn("max_row_buffer=batch_size", source)
        self.assertIn("yield_per=batch_size", source)
        self.assertIn("SET LOCAL TIME ZONE 'UTC'", source)
        self.assertNotIn("fetchall", source)


if __name__ == "__main__":
    unittest.main()
