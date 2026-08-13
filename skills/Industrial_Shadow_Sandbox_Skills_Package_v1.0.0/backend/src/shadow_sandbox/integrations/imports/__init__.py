from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import math
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shadow_sandbox.common import DomainError

UNIT_CONVERSIONS: dict[tuple[str, str], tuple[float, float]] = {
    ("C", "degC"): (1.0, 0.0),
    ("degF", "degC"): (5 / 9, -32 * 5 / 9),
    ("L/s", "m3/s"): (0.001, 0.0),
    ("bar", "Pa"): (100000.0, 0.0),
    ("rpm", "rpm"): (1.0, 0.0),
    ("%", "%"): (1.0, 0.0),
    ("m", "m"): (1.0, 0.0),
}


@dataclass(frozen=True, slots=True)
class SignalMapping:
    source_tag: str
    signal_key: str
    source_unit: str
    target_unit: str
    timestamp_field: str
    value_field: str
    quality_field: str | None
    timezone: str
    confidence: float
    reviewer: str | None

    def validate(self) -> None:
        if (self.source_unit, self.target_unit) not in UNIT_CONVERSIONS:
            raise DomainError("INCOMPATIBLE_UNIT", "no registered dimensional conversion")
        if not 0 <= self.confidence <= 1:
            raise DomainError("INVALID_MAPPING_CONFIDENCE", "confidence outside 0..1")
        if self.confidence < 0.8 and not self.reviewer:
            raise DomainError("MAPPING_REVIEW_REQUIRED", "low-confidence mapping requires review")


@dataclass(frozen=True, slots=True)
class SourceProfile:
    format: str
    columns: tuple[str, ...]
    row_count: int
    missing_by_column: Mapping[str, int]
    warnings: tuple[str, ...]
    source_hash: str


@dataclass(frozen=True, slots=True)
class NormalizedRow:
    signal_key: str
    value: float | str | bool
    original_value: Any
    source_timestamp: str
    original_timestamp: str
    status_code: str
    original_quality: Any
    source_row: int


class HistoricalImporter:
    def __init__(
        self, allowed_directory: str | Path, max_bytes: int = 100_000_000, max_rows: int = 5_000_000
    ) -> None:
        self.allowed_directory = Path(allowed_directory).resolve()
        self.max_bytes = max_bytes
        self.max_rows = max_rows

    def _safe_path(self, path: str | Path) -> Path:
        candidate = Path(path).resolve()
        if candidate != self.allowed_directory and self.allowed_directory not in candidate.parents:
            raise DomainError(
                "UNSAFE_IMPORT_PATH", "import path escapes allowed directory", status=403
            )
        if not candidate.is_file() or candidate.stat().st_size > self.max_bytes:
            raise DomainError("IMPORT_SOURCE_INVALID", "source missing or exceeds size limit")
        if candidate.suffix.lower() not in {".csv", ".jsonl", ".parquet"}:
            raise DomainError("IMPORT_FORMAT_DENIED", "unsupported source format")
        return candidate

    def rows(self, path: str | Path) -> Iterator[dict[str, Any]]:
        source = self._safe_path(path)
        suffix = source.suffix.lower()
        if suffix == ".csv":
            with source.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                for index, row in enumerate(reader, 1):
                    if index > self.max_rows:
                        raise DomainError("IMPORT_ROW_LIMIT", "row limit exceeded")
                    for value in row.values():
                        if isinstance(value, str) and value.lstrip().startswith(
                            ("=", "+", "-", "@")
                        ):
                            raise DomainError(
                                "CSV_FORMULA_DENIED", "spreadsheet formula cells are forbidden"
                            )
                    yield dict(row)
        elif suffix == ".jsonl":
            with source.open("r", encoding="utf-8") as handle:
                for index, line in enumerate(handle, 1):
                    if index > self.max_rows:
                        raise DomainError("IMPORT_ROW_LIMIT", "row limit exceeded")
                    if len(line) > 1_000_000:
                        raise DomainError("IMPORT_FIELD_TOO_LARGE", "JSONL row exceeds limit")
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise DomainError("IMPORT_ROW_INVALID", "JSONL rows must be objects")
                    yield value
        else:
            try:
                import pyarrow.parquet as pq  # type: ignore[import-not-found]
            except ImportError as exc:
                raise DomainError(
                    "PARQUET_DEPENDENCY_UNAVAILABLE", "PyArrow required", status=503
                ) from exc
            parquet = pq.ParquetFile(source)
            count = 0
            for batch in parquet.iter_batches(batch_size=4096):
                for value in batch.to_pylist():
                    count += 1
                    if count > self.max_rows:
                        raise DomainError("IMPORT_ROW_LIMIT", "row limit exceeded")
                    yield value

    def profile(self, path: str | Path) -> SourceProfile:
        source = self._safe_path(path)
        columns: set[str] = set()
        missing: dict[str, int] = {}
        count = 0
        for row in self.rows(source):
            count += 1
            columns.update(row)
            for key, value in row.items():
                if value in {None, ""}:
                    missing[key] = missing.get(key, 0) + 1
        warnings = tuple(
            f"missing:{key}:{value}" for key, value in sorted(missing.items()) if value
        )
        return SourceProfile(
            source.suffix.lstrip("."),
            tuple(sorted(columns)),
            count,
            missing,
            warnings,
            hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    def normalize(
        self, path: str | Path, mappings: Sequence[SignalMapping]
    ) -> Iterator[NormalizedRow]:
        by_tag = {mapping.source_tag: mapping for mapping in mappings}
        for mapping in mappings:
            mapping.validate()
        for index, row in enumerate(self.rows(path), 1):
            tag = str(row.get("tag", ""))
            mapping = by_tag.get(tag)
            if not mapping:
                continue
            raw_value = row.get(mapping.value_field)
            if raw_value is None:
                raise DomainError("IMPORT_VALUE_INVALID", f"row {index} has no value")
            scale, offset = UNIT_CONVERSIONS[(mapping.source_unit, mapping.target_unit)]
            try:
                numeric = float(raw_value)
            except (TypeError, ValueError) as exc:
                raise DomainError("IMPORT_VALUE_INVALID", f"row {index} is non-numeric") from exc
            if not math.isfinite(numeric):
                raise DomainError("IMPORT_VALUE_INVALID", f"row {index} is non-finite")
            original_time = str(row.get(mapping.timestamp_field, ""))
            timestamp = dt.datetime.fromisoformat(original_time)
            if timestamp.tzinfo is None:
                if mapping.timezone != "UTC":
                    raise DomainError(
                        "AMBIGUOUS_TIMEZONE", "naive timestamp requires explicit UTC in MVP"
                    )
                timestamp = timestamp.replace(tzinfo=dt.UTC)
            quality = row.get(mapping.quality_field) if mapping.quality_field else "Good"
            canonical_quality = "Good" if str(quality).lower() in {"good", "0", "ok"} else "Bad"
            yield NormalizedRow(
                mapping.signal_key,
                numeric * scale + offset,
                raw_value,
                timestamp.astimezone(dt.UTC).isoformat().replace("+00:00", "Z"),
                original_time,
                canonical_quality,
                quality,
                index,
            )
