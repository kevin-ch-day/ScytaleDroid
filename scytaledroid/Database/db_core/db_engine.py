"""
db_engine.py - Database connection engine for ScytaleDroid
"""

from pathlib import Path  # noqa: F401 (kept for future admin helpers)
from typing import Any, Dict, List, Optional, Tuple, cast

import mysql.connector
from mysql.connector import Error
from mysql.connector.abstracts import MySQLConnectionAbstract

from . import db_config


class DatabaseEngine:
    """
    Database engine wrapper for MySQL operations.
    Provides connection handling and basic CRUD helpers.
    """

    def __init__(self) -> None:
        self.conn: Optional[MySQLConnectionAbstract] = None
        self._connect()

    def _load_overrides(self) -> Dict[str, Any]:
        """Overrides disabled: use only hardcoded DB_CONFIG values.

        This app is configured to rely on the static values defined in
        scytaledroid.Database.db_core.db_config. We intentionally ignore any
        environment variables or config/db.json file to keep deployment simple.
        """
        return {}

    def _effective_config(self) -> Dict[str, Any]:
        cfg = dict(db_config.DB_CONFIG)
        # Overrides deliberately disabled; rely on hardcoded DB_CONFIG only.
        return cfg

    def _connect(self) -> None:
        """Establish a database connection using effective configuration."""
        try:
            cfg = self._effective_config()
            raw_conn = mysql.connector.connect(**cfg)
            # Explicitly cast to the abstract type for typing purposes
            self.conn = cast(MySQLConnectionAbstract, raw_conn)
            if not self.conn.is_connected():
                raise RuntimeError("Connection failed, but no exception raised.")
        except Error as e:
            raise RuntimeError(f"[DB_ENGINE] Database connection failed: {e}")

    def reconnect(self) -> None:
        """Reconnect if the connection is closed or lost."""
        if self.conn is None or not self.conn.is_connected():
            self._connect()

    def close(self) -> None:
        """Close the current database connection."""
        if self.conn and self.conn.is_connected():
            self.conn.close()
            self.conn = None

    def execute(self, query: str, params: Optional[Tuple[Any, ...]] = None) -> None:
        """Execute an INSERT/UPDATE/DELETE query (auto-commit)."""
        self.reconnect()
        assert self.conn is not None
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, params or ())
            self.conn.commit()
            cursor.close()
        except Error as e:
            raise RuntimeError(f"[DB_ENGINE] Query execution failed: {e}")
        finally:
            try:
                # Ensure no unread results remain on the connection
                if hasattr(self.conn, "consume_results"):
                    self.conn.consume_results()  # type: ignore[attr-defined]
            except Exception:
                pass

    # Server-level helpers (no default database) for admin operations
    @staticmethod
    def create_database_if_missing(db_name: str, *, charset: str = "utf8mb4") -> bool:
        """Create database if it does not exist using effective overrides.

        Connects without selecting a default database.
        """
        try:
            from . import db_config as _dbc

            # Build config without database to connect to server
            cfg = dict(_dbc.DB_CONFIG)
            cfg.pop("database", None)
            conn = mysql.connector.connect(**cfg)
            cur = conn.cursor()
            cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}` DEFAULT CHARACTER SET {charset};")
            conn.commit()
            cur.close()
            conn.close()
            return True
        except Exception:
            return False

    def execute_with_lastrowid(
        self, query: str, params: Optional[Tuple[Any, ...]] = None
    ) -> int:
        """Execute a statement and return the lastrowid when available."""
        self.reconnect()
        assert self.conn is not None
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, params or ())
            self.conn.commit()
            last_row_id = cursor.lastrowid or 0
            cursor.close()
            return int(last_row_id)
        except Error as e:
            raise RuntimeError(f"[DB_ENGINE] Query execution (with lastrowid) failed: {e}")
        finally:
            try:
                if hasattr(self.conn, "consume_results"):
                    self.conn.consume_results()  # type: ignore[attr-defined]
            except Exception:
                pass

    def fetch_one(
        self, query: str, params: Optional[Tuple[Any, ...]] = None
    ) -> Optional[Tuple[Any, ...]]:
        """Fetch a single row from a SELECT query (always as tuple)."""
        self.reconnect()
        assert self.conn is not None
        try:
            cursor = self.conn.cursor(dictionary=False, buffered=True)
            cursor.execute(query, params or ())
            result = cursor.fetchone()
            cursor.close()
            return cast(Optional[Tuple[Any, ...]], result)
        except Error as e:
            raise RuntimeError(f"[DB_ENGINE] Query fetch_one failed: {e}")
        finally:
            try:
                if hasattr(self.conn, "consume_results"):
                    self.conn.consume_results()  # type: ignore[attr-defined]
            except Exception:
                pass

    def fetch_all(
        self, query: str, params: Optional[Tuple[Any, ...]] = None
    ) -> List[Tuple[Any, ...]]:
        """Fetch all rows from a SELECT query (always as tuples)."""
        self.reconnect()
        assert self.conn is not None
        try:
            cursor = self.conn.cursor(dictionary=False, buffered=True)
            cursor.execute(query, params or ())
            results = cursor.fetchall()
            cursor.close()
            return cast(List[Tuple[Any, ...]], results)
        except Error as e:
            raise RuntimeError(f"[DB_ENGINE] Query fetch_all failed: {e}")
        finally:
            try:
                if hasattr(self.conn, "consume_results"):
                    self.conn.consume_results()  # type: ignore[attr-defined]
            except Exception:
                pass

    def fetch_one_dict(
        self, query: str, params: Optional[Tuple[Any, ...]] = None
    ) -> Optional[Dict[str, Any]]:
        """Fetch a single row and return it as a dictionary."""
        self.reconnect()
        assert self.conn is not None
        try:
            cursor = self.conn.cursor(dictionary=True, buffered=True)
            cursor.execute(query, params or ())
            result = cursor.fetchone()
            cursor.close()
            return cast(Optional[Dict[str, Any]], result)
        except Error as e:
            raise RuntimeError(f"[DB_ENGINE] Query fetch_one_dict failed: {e}")
        finally:
            try:
                if hasattr(self.conn, "consume_results"):
                    self.conn.consume_results()  # type: ignore[attr-defined]
            except Exception:
                pass

    def fetch_all_dict(
        self, query: str, params: Optional[Tuple[Any, ...]] = None
    ) -> List[Dict[str, Any]]:
        """Fetch all rows as dictionaries."""
        self.reconnect()
        assert self.conn is not None
        try:
            cursor = self.conn.cursor(dictionary=True, buffered=True)
            cursor.execute(query, params or ())
            results = cursor.fetchall()
            cursor.close()
            return cast(List[Dict[str, Any]], results)
        except Error as e:
            raise RuntimeError(f"[DB_ENGINE] Query fetch_all_dict failed: {e}")
        finally:
            try:
                if hasattr(self.conn, "consume_results"):
                    self.conn.consume_results()  # type: ignore[attr-defined]
            except Exception:
                pass
