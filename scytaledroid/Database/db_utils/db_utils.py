"""
db_utils.py - Helper utilities for database
"""

from mysql.connector import Error
from typing import Dict, Any, List, Optional, Sequence, Set

from ..db_core.db_engine import DatabaseEngine
from .table_snapshot import ColumnInfo, IndexInfo, TableSnapshot


def check_connection() -> bool:
    """
    Test whether the database connection can be established.
    Returns True if connected, False otherwise.
    """
    try:
        db = DatabaseEngine()
        db.close()
        return True
    except Exception as e:
        print(f"[DB_UTILS] Connection check failed: {e}")
        return False


def get_server_info() -> Dict[str, Any]:
    """
    Return basic server information such as:
      - database name
      - server version
      - current user
    """
    info: Dict[str, Any] = {}
    try:
        db = DatabaseEngine()
        result = db.fetch_one("SELECT DATABASE();")
        info["database"] = result[0] if result else None

        result = db.fetch_one("SELECT VERSION();")
        info["version"] = result[0] if result else None

        result = db.fetch_one("SELECT USER();")
        info["user"] = result[0] if result else None

        db.close()
    except Error as e:
        print(f"[DB_UTILS] Failed to get server info: {e}")
    return info


def check_required_tables(required_tables: list[str]) -> Dict[str, bool]:
    """
    Check if the required tables exist in the current database.
    Returns a dictionary mapping table name -> True/False.
    """
    status: Dict[str, bool] = {}
    try:
        db = DatabaseEngine()
        for table in required_tables:
            result = db.fetch_one(
                "SELECT COUNT(*) FROM information_schema.tables "
                "WHERE table_schema = DATABASE() AND table_name = %s;",
                (table,),
            )
            status[table] = result[0] > 0 if result else False
        db.close()
    except Error as e:
        print(f"[DB_UTILS] Failed to check tables: {e}")
        for table in required_tables:
            status[table] = False
    return status


def list_tables() -> List[str]:
    """Return a list of table names in the active database."""

    try:
        db = DatabaseEngine()
        rows = db.fetch_all("SHOW TABLES;")
        db.close()
    except Error as e:
        print(f"[DB_UTILS] Failed to list tables: {e}")
        return []

    tables: List[str] = []
    for row in rows or []:
        if isinstance(row, (list, tuple)) and row:
            tables.append(str(row[0]))
    return tables


def table_counts(table_names: list[str]) -> Dict[str, Optional[int]]:
    """Return row counts for the given table names."""

    counts: Dict[str, Optional[int]] = {}
    try:
        db = DatabaseEngine()
        for table in table_names:
            try:
                row = db.fetch_one(f"SELECT COUNT(*) FROM `{table}`;")
                counts[table] = int(row[0]) if row else 0
            except Error as inner_error:
                print(f"[DB_UTILS] Failed to count rows for {table}: {inner_error}")
                counts[table] = None
        db.close()
    except Error as e:
        print(f"[DB_UTILS] Unable to compute table counts: {e}")
        for table in table_names:
            counts.setdefault(table, None)
    return counts


def get_table_columns(table_name: str) -> List[str] | None:
    """Return column names for *table_name* or ``None`` if the query fails."""

    try:
        db = DatabaseEngine()
        rows = db.fetch_all(
            "SELECT COLUMN_NAME FROM information_schema.columns "
            "WHERE table_schema = DATABASE() AND table_name = %s ORDER BY ORDINAL_POSITION;",
            (table_name,),
        )
        db.close()
    except Error as e:
        print(f"[DB_UTILS] Failed to inspect table {table_name}: {e}")
        return None

    return [str(row[0]) for row in rows] if rows else []


def compare_columns(table_name: str, expected: Set[str]) -> Dict[str, List[str]]:
    """Compare actual columns with an expected set and report differences."""

    actual = get_table_columns(table_name)
    if actual is None:
        return {"actual": [], "unexpected": [], "missing": sorted(expected)}

    actual_set = set(actual)
    unexpected = sorted(actual_set - expected)
    missing = sorted(expected - actual_set)
    return {"actual": actual, "unexpected": unexpected, "missing": missing}


def build_table_snapshot(table_name: str) -> Optional[TableSnapshot]:
    """Collect metadata, row samples, and index information for *table_name*."""

    safe_name = _quote_identifier(table_name)
    try:
        db = DatabaseEngine()
    except Exception as exc:  # pragma: no cover - connection failure path
        print(f"[DB_UTILS] Failed to connect for snapshot: {exc}")
        return None

    try:
        columns = _fetch_columns(db, table_name)
        row_count = _fetch_row_count(db, safe_name)
        indexes = _fetch_indexes(db, safe_name)
        order_column = _select_order_column(columns)
        rows = _fetch_example_rows(db, safe_name, order_column)
        return TableSnapshot(
            name=table_name,
            row_count=row_count,
            columns=columns,
            example_rows=rows,
            indexes=indexes,
            order_column=order_column,
        )
    finally:
        db.close()


def provision_permission_analysis_tables(*, seed_defaults: bool = True) -> dict[str, dict[str, object]]:
    """Ensure helper tables for permission analytics are present.

    Returns a dictionary with two nested dictionaries:

    ``{"created": {...}, "seeded": {...}}``
    """

    try:
        from scytaledroid.Database.db_func import permission_support as support
    except Exception:
        return {"created": {}, "seeded": {}}

    created = support.ensure_all()
    seeded: dict[str, object]
    if seed_defaults:
        try:
            seeded = support.seed_defaults()
        except Exception:
            seeded = {}
    else:
        seeded = {}
    return {"created": created, "seeded": seeded}


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
    parts = []
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
    except Exception as exc:  # pragma: no cover - relies on external DB
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
    except Exception as exc:  # pragma: no cover - relies on external DB
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

    # Fall back to a single primary key column if present.
    primary_columns = [col.name for col in columns if col.is_primary]
    if len(primary_columns) == 1:
        return primary_columns[0]

    return None


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
    except Exception as exc:  # pragma: no cover - relies on external DB
        print(f"[DB_UTILS] Failed to fetch sample rows for {safe_name}: {exc}")
        return []
    sanitized: List[dict[str, Any]] = []
    for row in rows:
        sanitized.append({str(key): value for key, value in row.items()})
    return sanitized


def _quote_identifier(identifier: str) -> str:
    safe = identifier.replace("`", "``")
    return f"`{safe}`"
