"""
db_engine.py - Database connection engine for ScytaleDroid
"""

import mysql.connector
from mysql.connector import Error
from mysql.connector.abstracts import MySQLConnectionAbstract
from typing import Optional, Tuple, List, cast, Any

from . import db_config


class DatabaseEngine:
    """
    Database engine wrapper for MySQL operations.
    Provides connection handling and basic CRUD helpers.
    """

    def __init__(self) -> None:
        self.conn: Optional[MySQLConnectionAbstract] = None
        self._connect()

    def _connect(self) -> None:
        """Establish a database connection."""
        try:
            raw_conn = mysql.connector.connect(**db_config.DB_CONFIG)
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

    def fetch_one(
        self, query: str, params: Optional[Tuple[Any, ...]] = None
    ) -> Optional[Tuple[Any, ...]]:
        """Fetch a single row from a SELECT query (always as tuple)."""
        self.reconnect()
        assert self.conn is not None
        try:
            cursor = self.conn.cursor(dictionary=False)
            cursor.execute(query, params or ())
            result = cursor.fetchone()
            cursor.close()
            return cast(Optional[Tuple[Any, ...]], result)
        except Error as e:
            raise RuntimeError(f"[DB_ENGINE] Query fetch_one failed: {e}")

    def fetch_all(
        self, query: str, params: Optional[Tuple[Any, ...]] = None
    ) -> List[Tuple[Any, ...]]:
        """Fetch all rows from a SELECT query (always as tuples)."""
        self.reconnect()
        assert self.conn is not None
        try:
            cursor = self.conn.cursor(dictionary=False)
            cursor.execute(query, params or ())
            results = cursor.fetchall()
            cursor.close()
            return cast(List[Tuple[Any, ...]], results)
        except Error as e:
            raise RuntimeError(f"[DB_ENGINE] Query fetch_all failed: {e}")
