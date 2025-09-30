"""
db_utils.py - Helper utilities for database
"""

from mysql.connector import Error
from typing import Dict, Any

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
