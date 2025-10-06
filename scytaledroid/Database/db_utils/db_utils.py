"""
db_utils.py - Helper utilities for database
"""

from mysql.connector import Error
from typing import Dict, Any, List, Optional, Set

from ..db_core.db_engine import DatabaseEngine


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
