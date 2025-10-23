"""
db_engine.py - Database connection engine for ScytaleDroid
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, cast

import mysql.connector
from mysql.connector import Error
from mysql.connector.abstracts import MySQLConnectionAbstract

from . import db_config


# MySQL transient error codes that are safe to retry
_RETRYABLE_ERRNOS = {1205, 1213}  # 1205: lock wait timeout, 1213: deadlock found


class DatabaseEngine:
    """
    Database engine wrapper for MySQL operations.
    Provides connection handling and basic CRUD helpers.
    """

    def __init__(self) -> None:
        self.conn: Optional[MySQLConnectionAbstract] = None
        self._read_only: bool = False  # software-enforced "role" without changing creds
        self._connect()

    # -------------------------
    # Config / connection wiring
    # -------------------------

    def _load_overrides(self) -> Dict[str, Any]:
        """Overrides disabled: use only hardcoded DB_CONFIG values.

        This app is configured to rely on the static values defined in
        scytaledroid.Database.db_core.db_config. We intentionally ignore any
        environment variables or config files to keep deployment simple.
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
        if self.conn is None:
            self._connect()
            return
        try:
            # Prefer ping-based health check if available
            if hasattr(self.conn, "ping"):
                # type: ignore[attr-defined]
                self.conn.ping(reconnect=True, attempts=1, delay=0)  # noqa: E1101
            else:
                if not self.conn.is_connected():
                    self._connect()
        except Exception:
            self._connect()

    def close(self) -> None:
        """Close the current database connection."""
        if self.conn and self.conn.is_connected():
            try:
                self.conn.close()
            finally:
                self.conn = None

    # -------------------------
    # Role helpers (software guard)
    # -------------------------

    def as_reader(self) -> "DatabaseEngine":
        """Return a handle that blocks any DML/DDL via a software guard."""
        self._read_only = True
        return self

    def _guard_write(self, sql: str) -> None:
        if not self._read_only:
            return
        head = sql.lstrip().split(None, 1)[0].upper() if sql.strip() else ""
        if head in {"INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "ALTER", "DROP", "TRUNCATE"}:
            raise RuntimeError("[DB_ENGINE] Write blocked on read-only handle")

    # -------------------------
    # Transaction support
    # -------------------------

    @contextmanager
    def transaction(self):
        """
        Atomic transaction context manager.

        Usage:
            with db.transaction():
                db.execute("INSERT ...", params)
                db.execute("UPDATE ...", params)
        """
        self.reconnect()
        assert self.conn is not None
        prev_autocommit = getattr(self.conn, "autocommit", True)
        try:
            self.conn.autocommit = False  # type: ignore[attr-defined]
            yield self
            self.conn.commit()
        except Exception:
            try:
                self.conn.rollback()
            finally:
                # Always restore autocommit even if rollback fails
                self.conn.autocommit = prev_autocommit  # type: ignore[attr-defined]
            raise
        else:
            # Success path: restore autocommit
            self.conn.autocommit = prev_autocommit  # type: ignore[attr-defined]

    # -------------------------
    # Core exec primitives (with retries)
    # -------------------------

    def _run_with_retry(
        self,
        fn,
        sql: str,
        params: Optional[Sequence[Any]] = None,
        *,
        retries: int = 3,
    ):
        self.reconnect()
        last_exc: Optional[Error] = None
        for attempt in range(1, max(1, retries) + 1):
            try:
                return fn(sql, params)
            except Error as e:
                # Retry only for known transient concurrency errors
                if e.errno in _RETRYABLE_ERRNOS and attempt < retries:
                    # Small linear backoff (avoid importing time if not needed elsewhere)
                    for _ in range(attempt * 2_000_000):  # ~2ms, ~4ms, ~6ms busy-wait
                        pass
                    last_exc = e
                    continue
                raise RuntimeError(f"[DB_ENGINE] Query failed: {e}") from e
        # If we exit loop without return, raise last error (defensive)
        if last_exc:
            raise RuntimeError(f"[DB_ENGINE] Query failed after retries: {last_exc}") from last_exc

    # -------------------------
    # Public API (kept stable)
    # -------------------------

    def execute(self, query: str, params: Optional[Tuple[Any, ...]] = None) -> None:
        """Execute an INSERT/UPDATE/DELETE query (auto-commit)."""
        self._guard_write(query)

        def _do(sql: str, p: Optional[Sequence[Any]]):
            assert self.conn is not None
            cursor = self.conn.cursor()
            try:
                cursor.execute(sql, p or ())
                self.conn.commit()
            finally:
                try:
                    cursor.close()
                except Exception:
                    pass
                self._consume_leftovers()

        self._run_with_retry(_do, query, params)

    def execute_many(self, query: str, param_rows: Iterable[Tuple[Any, ...]]) -> None:
        """
        Execute a batched INSERT/UPDATE with many parameter rows (auto-commit).
        Prefer wrapping in `with db.transaction():` for atomicity across multiple calls.
        """
        self._guard_write(query)
        rows = list(param_rows)

        if not rows:
            return

        def _do(sql: str, _: Optional[Sequence[Any]]):
            assert self.conn is not None
            cursor = self.conn.cursor()
            try:
                cursor.executemany(sql, rows)
                self.conn.commit()
            finally:
                try:
                    cursor.close()
                except Exception:
                    pass
                self._consume_leftovers()

        self._run_with_retry(_do, query, None)

    def execute_with_lastrowid(
        self, query: str, params: Optional[Tuple[Any, ...]] = None
    ) -> int:
        """Execute a statement and return the lastrowid when available."""
        self._guard_write(query)

        def _do(sql: str, p: Optional[Sequence[Any]]):
            assert self.conn is not None
            cursor = self.conn.cursor()
            try:
                cursor.execute(sql, p or ())
                self.conn.commit()
                return int(cursor.lastrowid or 0)
            finally:
                try:
                    cursor.close()
                except Exception:
                    pass
                self._consume_leftovers()

        return cast(int, self._run_with_retry(_do, query, params))

    def fetch_one(
        self, query: str, params: Optional[Tuple[Any, ...]] = None
    ) -> Optional[Tuple[Any, ...]]:
        """Fetch a single row from a SELECT query (always as tuple)."""
        def _do(sql: str, p: Optional[Sequence[Any]]):
            self.reconnect()
            assert self.conn is not None
            cursor = self.conn.cursor(dictionary=False, buffered=True)
            try:
                cursor.execute(sql, p or ())
                return cursor.fetchone()
            finally:
                try:
                    cursor.close()
                except Exception:
                    pass
                self._consume_leftovers()

        return cast(Optional[Tuple[Any, ...]], self._run_with_retry(_do, query, params))

    def fetch_all(
        self, query: str, params: Optional[Tuple[Any, ...]] = None
    ) -> List[Tuple[Any, ...]]:
        """Fetch all rows from a SELECT query (always as tuples)."""
        def _do(sql: str, p: Optional[Sequence[Any]]):
            self.reconnect()
            assert self.conn is not None
            cursor = self.conn.cursor(dictionary=False, buffered=True)
            try:
                cursor.execute(sql, p or ())
                return cursor.fetchall()
            finally:
                try:
                    cursor.close()
                except Exception:
                    pass
                self._consume_leftovers()

        return cast(List[Tuple[Any, ...]], self._run_with_retry(_do, query, params))

    def fetch_one_dict(
        self, query: str, params: Optional[Tuple[Any, ...]] = None
    ) -> Optional[Dict[str, Any]]:
        """Fetch a single row and return it as a dictionary."""
        def _do(sql: str, p: Optional[Sequence[Any]]):
            self.reconnect()
            assert self.conn is not None
            cursor = self.conn.cursor(dictionary=True, buffered=True)
            try:
                cursor.execute(sql, p or ())
                return cursor.fetchone()
            finally:
                try:
                    cursor.close()
                except Exception:
                    pass
                self._consume_leftovers()

        return cast(Optional[Dict[str, Any]], self._run_with_retry(_do, query, params))

    def fetch_all_dict(
        self, query: str, params: Optional[Tuple[Any, ...]] = None
    ) -> List[Dict[str, Any]]:
        """Fetch all rows as dictionaries."""
        def _do(sql: str, p: Optional[Sequence[Any]]):
            self.reconnect()
            assert self.conn is not None
            cursor = self.conn.cursor(dictionary=True, buffered=True)
            try:
                cursor.execute(sql, p or ())
                return cursor.fetchall()
            finally:
                try:
                    cursor.close()
                except Exception:
                    pass
                self._consume_leftovers()

        return cast(List[Dict[str, Any]], self._run_with_retry(_do, query, params))

    # -------------------------
    # Server-level helpers
    # -------------------------

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
            try:
                cur.execute(
                    f"CREATE DATABASE IF NOT EXISTS `{db_name}` "
                    f"DEFAULT CHARACTER SET {charset};"
                )
                conn.commit()
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass
            return True
        except Exception:
            return False

    # -------------------------
    # Internal helpers
    # -------------------------

    def _consume_leftovers(self) -> None:
        """Ensure no unread results remain on the connection.

        With buffered cursors this is typically unnecessary, but we keep it
        to be defensive when a non-buffered cursor slips in.
        """
        try:
            if self.conn and hasattr(self.conn, "consume_results"):
                self.conn.consume_results()  # type: ignore[attr-defined]
        except Exception:
            pass
