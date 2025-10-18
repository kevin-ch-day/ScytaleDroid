"""Database diagnostics helpers shared across CLI tools.

The functions in this module wrap low-level :mod:`db_core` primitives so
operational commands (menus, scripts, or ad-hoc tooling) can introspect the
current MySQL schema without reimplementing connection lifecycle management.

They intentionally mirror the documentation in
``docs/database/permission_analysis_schema.md`` and
``docs/static_analysis/static_analysis_data_model.md`` so analysts can jump
between the docs and code when validating deployments.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from scytaledroid.Database.db_core import DatabaseEngine, database_session

from .table_snapshot import ColumnInfo, IndexInfo, TableSnapshot


@contextmanager
def _connected_engine(*, reuse_connection: bool = False) -> Iterable[DatabaseEngine]:
    """Yield a :class:`DatabaseEngine` bound to a managed session."""

    with database_session(reuse_connection=reuse_connection) as engine:
        yield engine


def check_connection() -> bool:
    """Return ``True`` if a database connection can be established."""

    try:
        with _connected_engine(reuse_connection=False) as engine:
            engine.fetch_one("SELECT 1")
        return True
    except Exception as exc:  # pragma: no cover - relies on external MySQL
        print(f"[DB_UTILS] Connection check failed: {exc}")
        return False


def get_server_info() -> Dict[str, Any]:
    """Return a mapping with ``database``, ``version``, and ``user`` details."""

    info: Dict[str, Any] = {}
    try:
        with _connected_engine() as engine:
            result = engine.fetch_one("SELECT DATABASE();")
            info["database"] = result[0] if result else None

            result = engine.fetch_one("SELECT VERSION();")
            info["version"] = result[0] if result else None

            result = engine.fetch_one("SELECT USER();")
            info["user"] = result[0] if result else None
    except Exception as exc:  # pragma: no cover - relies on external MySQL
        print(f"[DB_UTILS] Failed to get server info: {exc}")
    return info


def check_required_tables(required_tables: list[str]) -> Dict[str, bool]:
    """Return a mapping of table name → existence flag for *required_tables*."""

    status: Dict[str, bool] = {}
    try:
        with _connected_engine() as engine:
            for table in required_tables:
                result = engine.fetch_one(
                    "SELECT COUNT(*) FROM information_schema.tables "
                    "WHERE table_schema = DATABASE() AND table_name = %s;",
                    (table,),
                )
                status[table] = bool(result and int(result[0]) > 0)
    except Exception as exc:  # pragma: no cover - relies on external MySQL
        print(f"[DB_UTILS] Failed to check tables: {exc}")
        for table in required_tables:
            status.setdefault(table, False)
    return status


def list_tables() -> List[str]:
    """Return a sorted list of table names for the active schema."""

    try:
        with _connected_engine() as engine:
            rows = engine.fetch_all("SHOW TABLES;")
    except Exception as exc:  # pragma: no cover - relies on external MySQL
        print(f"[DB_UTILS] Failed to list tables: {exc}")
        return []

    tables: List[str] = []
    for row in rows or []:
        if isinstance(row, (list, tuple)) and row:
            tables.append(str(row[0]))
    return sorted(tables)


def table_counts(table_names: list[str]) -> Dict[str, Optional[int]]:
    """Return a mapping of table name → row count (or ``None`` on failure)."""

    counts: Dict[str, Optional[int]] = {}
    try:
        with _connected_engine() as engine:
            for table in table_names:
                try:
                    row = engine.fetch_one(f"SELECT COUNT(*) FROM `{table}`;")
                    counts[table] = int(row[0]) if row else 0
                except Exception as inner_error:
                    print(f"[DB_UTILS] Failed to count rows for {table}: {inner_error}")
                    counts[table] = None
    except Exception as exc:  # pragma: no cover - relies on external MySQL
        print(f"[DB_UTILS] Unable to compute table counts: {exc}")
        for table in table_names:
            counts.setdefault(table, None)
    return counts


def get_table_columns(table_name: str) -> List[str] | None:
    """Return column names for *table_name* or ``None`` if inspection fails."""

    try:
        with _connected_engine() as engine:
            rows = engine.fetch_all(
                "SELECT COLUMN_NAME FROM information_schema.columns "
                "WHERE table_schema = DATABASE() AND table_name = %s "
                "ORDER BY ORDINAL_POSITION;",
                (table_name,),
            )
    except Exception as exc:  # pragma: no cover - relies on external MySQL
        print(f"[DB_UTILS] Failed to inspect table {table_name}: {exc}")
        return None

    return [str(row[0]) for row in rows] if rows else []


def compare_columns(table_name: str, expected: Set[str]) -> Dict[str, List[str]]:
    """Compare actual vs *expected* columns for *table_name*."""

    actual = get_table_columns(table_name)
    if actual is None:
        return {"actual": [], "unexpected": [], "missing": sorted(expected)}

    actual_set = set(actual)
    unexpected = sorted(actual_set - expected)
    missing = sorted(expected - actual_set)
    return {"actual": actual, "unexpected": unexpected, "missing": missing}


def build_table_snapshot(table_name: str) -> Optional[TableSnapshot]:
    """Collect metadata, example rows, and index info for *table_name*."""

    safe_name = _quote_identifier(table_name)
    try:
        with _connected_engine() as engine:
            table_type = _fetch_table_type(engine, table_name)
            columns = _fetch_columns(engine, table_name)
            row_count = _fetch_row_count(engine, safe_name)
            indexes = _fetch_indexes(engine, safe_name)
            order_column = _select_order_column(columns)
            timestamp_column = _select_timestamp_column(columns)
            max_timestamp = (
                _fetch_max_timestamp(engine, safe_name, timestamp_column) if timestamp_column else None
            )
            rows = _fetch_example_rows(engine, safe_name, order_column)
    except Exception as exc:  # pragma: no cover - relies on external MySQL
        print(f"[DB_UTILS] Failed to build snapshot for {table_name}: {exc}")
        return None

    return TableSnapshot(
        name=table_name,
        table_type=table_type,
        row_count=row_count,
        max_timestamp=max_timestamp,
        timestamp_column=timestamp_column,
        columns=columns,
        example_rows=rows,
        indexes=indexes,
        order_column=order_column,
    )


def _fetch_columns(db: DatabaseEngine, table_name: str) -> List[ColumnInfo]:
    query = (
        "SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_KEY, "
        "EXTRA, COLUMN_COMMENT FROM information_schema.columns "
        "WHERE table_schema = DATABASE() AND table_name = %s ORDER BY ORDINAL_POSITION;"
    )
    rows = db.fetch_all_dict(query, (table_name,))
    columns: List[ColumnInfo] = []
    for raw in rows:
        row = {str(key).lower(): value for key, value in raw.items()}
        default_value = row.get("column_default")
        if isinstance(default_value, bytes):
            default_value = default_value.decode("utf-8", "ignore")
        elif default_value is not None and not isinstance(default_value, str):
            default_value = str(default_value)
        notes = _combine_notes(row.get("extra"), row.get("column_comment"))
        columns.append(
            ColumnInfo(
                name=str(row.get("column_name", "")),
                data_type=str(row.get("column_type", "")),
                is_nullable=str(row.get("is_nullable", "")).upper() == "YES",
                default=default_value,
                is_primary=str(row.get("column_key", "")).upper() == "PRI",
                notes=notes,
            )
        )
    return columns


def _combine_notes(extra: Any, comment: Any) -> Optional[str]:
    parts: List[str] = []
    if extra:
        parts.append(str(extra))
    if comment:
        parts.append(str(comment))
    if not parts:
        return None
    return "; ".join(part for part in parts if part)


def _fetch_row_count(db: DatabaseEngine, safe_name: str) -> Optional[int]:
    try:
        row = db.fetch_one(f"SELECT COUNT(*) FROM {safe_name};")
    except Exception as exc:  # pragma: no cover - relies on external MySQL
        print(f"[DB_UTILS] Failed to count rows for {safe_name}: {exc}")
        return None
    if not row:
        return None
    try:
        return int(row[0])
    except (TypeError, ValueError):
        return None


def _fetch_indexes(db: DatabaseEngine, safe_name: str) -> List[IndexInfo]:
    try:
        rows = db.fetch_all_dict(f"SHOW INDEX FROM {safe_name};")
    except Exception as exc:  # pragma: no cover - relies on external MySQL
        print(f"[DB_UTILS] Failed to read indexes for {safe_name}: {exc}")
        return []

    grouped: Dict[str, Dict[str, Any]] = {}
    for raw in rows:
        row = {str(key).lower(): value for key, value in raw.items()}
        key_name = str(row.get("key_name", ""))
        entry = grouped.setdefault(
            key_name,
            {"unique": not bool(row.get("non_unique", 1)), "columns": []},
        )
        seq = int(row.get("seq_in_index", 0) or 0)
        column_name = str(row.get("column_name", ""))
        entry["columns"].append((seq, column_name))

    indexes: List[IndexInfo] = []
    for name, info in grouped.items():
        columns_sorted = [col for _, col in sorted(info["columns"], key=lambda item: item[0])]
        indexes.append(IndexInfo(name=name or "<unnamed>", columns=columns_sorted, unique=info["unique"]))
    indexes.sort(key=lambda item: item.name)
    return indexes


def _select_order_column(columns: Sequence[ColumnInfo]) -> Optional[str]:
    preferred = [
        "updated_at",
        "observed_at",
        "created_at",
        "captured_at",
        "recorded_at",
        "harvested_at",
        "timestamp",
    ]
    available = {col.name for col in columns}
    for candidate in preferred:
        if candidate in available:
            return candidate

    primary_columns = [col.name for col in columns if col.is_primary]
    if len(primary_columns) == 1:
        return primary_columns[0]

    return None


def _select_timestamp_column(columns: Sequence[ColumnInfo]) -> Optional[str]:
    for column in columns:
        if column.name.lower() == "updated_at":
            return column.name
    return None


def _fetch_max_timestamp(db: DatabaseEngine, safe_name: str, column_name: str) -> Optional[str]:
    try:
        column_expr = _quote_identifier(column_name)
        row = db.fetch_one(f"SELECT MAX({column_expr}) FROM {safe_name};")
    except Exception as exc:  # pragma: no cover - relies on external MySQL
        print(f"[DB_UTILS] Failed to compute MAX({column_name}) for {safe_name}: {exc}")
        return None
    if not row:
        return None
    value = row[0]
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat(sep=" ")
    return str(value)


def _fetch_table_type(db: DatabaseEngine, table_name: str) -> Optional[str]:
    try:
        row = db.fetch_one(
            "SELECT TABLE_TYPE FROM information_schema.tables "
            "WHERE table_schema = DATABASE() AND table_name = %s;",
            (table_name,),
        )
    except Exception as exc:  # pragma: no cover - relies on external MySQL
        print(f"[DB_UTILS] Failed to fetch table type for {table_name}: {exc}")
        return None
    if not row:
        return None
    value = row[0]
    return str(value) if value is not None else None


def _fetch_example_rows(
    db: DatabaseEngine, safe_name: str, order_column: Optional[str]
) -> List[dict[str, Any]]:
    if order_column:
        order_expr = _quote_identifier(order_column)
        query = f"SELECT * FROM {safe_name} ORDER BY {order_expr} DESC LIMIT 3;"
    else:
        query = f"SELECT * FROM {safe_name} LIMIT 3;"

    try:
        rows = db.fetch_all_dict(query)
    except Exception as exc:  # pragma: no cover - relies on external MySQL
        print(f"[DB_UTILS] Failed to fetch sample rows for {safe_name}: {exc}")
        return []
    sanitized: List[dict[str, Any]] = []
    for row in rows:
        sanitized.append({str(key): value for key, value in row.items()})
    return sanitized


def _quote_identifier(identifier: str) -> str:
    safe = identifier.replace("`", "``")
    return f"`{safe}`"


__all__ = [
    "check_connection",
    "get_server_info",
    "check_required_tables",
    "list_tables",
    "table_counts",
    "get_table_columns",
    "compare_columns",
    "build_table_snapshot",
]
