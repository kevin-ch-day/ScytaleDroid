"""Database execution helpers and connection management for ScytaleDroid.

The module centralises all low-level database behaviour so other packages only
need to focus on business queries.  It normalises parameter styles (supporting
both ``%s`` and ``%(name)s`` placeholders), adds rich structured logging, and
provides a single place to tune retry, timeout and diagnostic policies.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Iterator, MutableMapping, Optional, Tuple

import pymysql
from pymysql import err
from pymysql.cursors import Cursor, DictCursor

from .db_config import DB_CONFIG

try:  # pragma: no cover - logging configuration may be unavailable in tests
    from scytaledroid.Utils.LoggingUtils import logging_engine as _logging_engine
except Exception:  # pragma: no cover - fallback to stdlib logger
    _logging_engine = None


if _logging_engine is not None:  # pragma: no cover - exercised via integration tests
    _LOG = _logging_engine.get_db_logger()
else:  # pragma: no cover - default logger is rarely hit in production
    _LOG = logging.getLogger("scytaledroid.database")


NAMED_PARAM_PATTERN = re.compile(r"%\(([^)]+)\)s")
TRANSIENT_ERRNOS = {1205, 1213, 2006}
MAX_RETRIES = 3

SENSITIVE_KEYS = {"api_key", "auth", "authorization", "password", "secret", "token"}

_ENV_LOGGED = False

_SCALAR_SEQUENCE_TYPES = (str, bytes, bytearray, memoryview)


class DatabaseError(RuntimeError):
    """Base exception for database engine failures."""


class ParamStyleError(DatabaseError):
    """Raised when a SQL statement mixes placeholder styles or is malformed."""


class TransientDbError(DatabaseError):
    """Raised for transient errors after retry exhaustion."""


class IntegrityDbError(DatabaseError):
    """Raised for integrity violations reported by the server."""


@dataclass(slots=True)
class _NormalisedStatement:
    sql: str
    params: Optional[Sequence[Any]]
    detected_style: str
    batch_size: Optional[int] = None


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        redacted: MutableMapping[str, Any] = type(value)()
        for key, val in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                redacted[key] = "***"
            else:
                redacted[key] = _redact(val)
        return redacted
    if isinstance(value, (list, tuple)):
        return type(value)(_redact(v) for v in value)
    return value


def _normalise_single(sql: str, params: Optional[Any]) -> _NormalisedStatement:
    has_named = bool(NAMED_PARAM_PATTERN.search(sql))
    has_positional = "%s" in sql and not has_named

    if has_named and has_positional:
        raise ParamStyleError("Statement mixes named and positional placeholders")

    if params is None:
        detected = "named" if has_named else "positional"
        return _NormalisedStatement(sql=sql, params=None, detected_style=detected)

    if has_named:
        if not isinstance(params, Mapping):
            raise ParamStyleError("Named placeholders require a mapping of parameters")
        names = NAMED_PARAM_PATTERN.findall(sql)
        if not names:
            raise ParamStyleError("Named style detected but no placeholders found")
        try:
            ordered = tuple(params[name] for name in names)
        except KeyError as exc:  # pragma: no cover - guarded by query definitions
            raise ParamStyleError(f"Missing parameter for placeholder: {exc.args[0]}") from exc
        rewritten = NAMED_PARAM_PATTERN.sub("%s", sql)
        return _NormalisedStatement(sql=rewritten, params=ordered, detected_style="named")

    # Positional placeholders
    if isinstance(params, Mapping):
        raise ParamStyleError("Positional placeholders require a sequence of parameters")
    if isinstance(params, Sequence) and not isinstance(params, _SCALAR_SEQUENCE_TYPES):
        return _NormalisedStatement(sql=sql, params=tuple(params), detected_style="positional")
    return _NormalisedStatement(sql=sql, params=(params,), detected_style="positional")


def _normalise_many(sql: str, rows: Sequence[Any]) -> _NormalisedStatement:
    if not rows:
        return _NormalisedStatement(sql=sql, params=(), detected_style="positional", batch_size=0)

    has_named = bool(NAMED_PARAM_PATTERN.search(sql))
    has_positional = "%s" in sql and not has_named

    if has_named and has_positional:
        raise ParamStyleError("Statement mixes named and positional placeholders")

    if has_named:
        names = NAMED_PARAM_PATTERN.findall(sql)
        rewritten = NAMED_PARAM_PATTERN.sub("%s", sql)
        ordered_rows: list[Sequence[Any]] = []
        for row in rows:
            if not isinstance(row, Mapping):
                raise ParamStyleError("Named placeholders require mappings for each row")
            try:
                ordered_rows.append(tuple(row[name] for name in names))
            except KeyError as exc:  # pragma: no cover - guarded by query definitions
                raise ParamStyleError(f"Missing parameter for placeholder: {exc.args[0]}") from exc
        return _NormalisedStatement(
            sql=rewritten,
            params=ordered_rows,
            detected_style="named",
            batch_size=len(ordered_rows),
        )

    # Positional rows
    positional_rows: list[Sequence[Any]] = []
    for row in rows:
        if isinstance(row, Mapping):
            raise ParamStyleError("Positional placeholders require sequence rows")
        if isinstance(row, Sequence) and not isinstance(row, _SCALAR_SEQUENCE_TYPES):
            positional_rows.append(tuple(row))
        else:
            positional_rows.append((row,))
    return _NormalisedStatement(
        sql=sql,
        params=positional_rows,
        detected_style="positional",
        batch_size=len(positional_rows),
    )


def _summarise_params(params: Any, *, many: bool) -> Dict[str, Any]:
    if params is None:
        return {"params_present": False}
    if many:
        if isinstance(params, Sequence):
            size = len(params)
            summary: Dict[str, Any] = {
                "params_present": bool(size),
                "batch_size": size,
            }
            if size:
                summary["sample"] = _redact(params[0])
            return summary
        batch = list(params)
        size = len(batch)
        summary = {"params_present": bool(size), "batch_size": size}
        if batch:
            summary["sample"] = _redact(batch[0])
        return summary
    return {"params_present": True, "params": _redact(params)}


def _is_transient(exc: Exception) -> bool:
    return isinstance(exc, err.OperationalError) and getattr(exc, "errno", None) in TRANSIENT_ERRNOS


def _log_env_once(connection: pymysql.Connection) -> None:
    global _ENV_LOGGED
    if _ENV_LOGGED:
        return
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT VERSION() AS version")
            version_row = cur.fetchone()
            version = version_row[0] if isinstance(version_row, (list, tuple)) else version_row
            cur.execute("SELECT @@sql_mode AS sql_mode")
            mode_row = cur.fetchone()
            sql_mode = mode_row[0] if isinstance(mode_row, (list, tuple)) else mode_row
    except Exception:  # pragma: no cover - defensive logging only
        return

    _LOG.info(
        "db.env",
        extra={
            "event": "db.env",
            "driver": "pymysql",
            "server_version": version,
            "sql_mode": sql_mode,
        },
    )
    _ENV_LOGGED = True


def _connect() -> pymysql.Connection:
    connection = pymysql.connect(
        host=str(DB_CONFIG.get("host", "localhost")),
        user=str(DB_CONFIG.get("user", "")),
        password=str(DB_CONFIG.get("password", "")),
        database=str(DB_CONFIG.get("database", "")),
        port=int(DB_CONFIG.get("port", 3306)),
        charset=str(DB_CONFIG.get("charset", "utf8mb4")),
        autocommit=False,
        connect_timeout=int(DB_CONFIG.get("connect_timeout", 5)),
        read_timeout=int(DB_CONFIG.get("read_timeout", 30)),
        write_timeout=int(DB_CONFIG.get("write_timeout", 30)),
    )
    _log_env_once(connection)
    return connection


@contextmanager
def connect() -> Iterator[pymysql.Connection]:
    connection = _connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        try:
            connection.rollback()
        except Exception:  # pragma: no cover - defensive cleanup
            pass
        raise
    finally:
        try:
            connection.close()
        except Exception:  # pragma: no cover - defensive cleanup
            pass


def _execute(
    cursor: Cursor,
    sql: str,
    params: Optional[Any],
    *,
    query_name: str,
    context: Optional[Mapping[str, Any]],
    many: bool,
) -> _NormalisedStatement:
    trace_id = uuid.uuid4().hex[:8]
    base_extra: Dict[str, Any] = {
        "event": "db.exec",
        "query": query_name or "sql",
        "trace_id": trace_id,
    }
    if context:
        base_extra.update(context)

    try:
        normalised = (
            _normalise_many(sql, params if params is not None else [])
            if many
            else _normalise_single(sql, params)
        )
    except ParamStyleError as exc:
        summary = _summarise_params(params, many=many)
        _LOG.error(
            "db.exec.paramstyle",
            extra={**base_extra, **summary, "event": "db.exec.paramstyle"},
            exc_info=True,
        )
        raise

    summary = _summarise_params(normalised.params, many=many)

    attempt = 0
    while True:
        attempt += 1
        start = time.perf_counter()
        try:
            if many:
                assert normalised.params is not None
                cursor.executemany(normalised.sql, normalised.params)
            else:
                cursor.execute(normalised.sql, normalised.params)
            elapsed = int((time.perf_counter() - start) * 1000)
            _LOG.debug(
                "db.exec.ok",
                extra={
                    **base_extra,
                    **summary,
                    "event": "db.exec.ok",
                    "detected_style": normalised.detected_style,
                    "elapsed_ms": elapsed,
                    "attempt": attempt,
                },
            )
            return normalised
        except err.IntegrityError as exc:
            _LOG.error(
                "db.exec.integrity",
                extra={
                    **base_extra,
                    **summary,
                    "event": "db.exec.integrity",
                    "detected_style": normalised.detected_style,
                    "err_class": exc.__class__.__name__,
                    "err_code": getattr(exc, "errno", None),
                    "sqlstate": getattr(exc, "sqlstate", None),
                },
                exc_info=True,
            )
            raise IntegrityDbError(str(exc)) from exc
        except err.MySQLError as exc:
            transient = _is_transient(exc)
            _LOG.error(
                "db.exec.failed",
                extra={
                    **base_extra,
                    **summary,
                    "event": "db.exec.failed",
                    "detected_style": normalised.detected_style,
                    "err_class": exc.__class__.__name__,
                    "err_code": getattr(exc, "errno", None),
                    "sqlstate": getattr(exc, "sqlstate", None),
                    "attempt": attempt,
                    "transient": transient,
                },
                exc_info=True,
            )
            if transient and attempt < MAX_RETRIES:
                time.sleep(0.2 * attempt)
                try:
                    cursor.connection.ping(reconnect=True)
                except Exception:  # pragma: no cover - reconnect best effort
                    pass
                continue
            if transient:
                raise TransientDbError(str(exc)) from exc
            raise DatabaseError(str(exc)) from exc


class DatabaseEngine:
    """Convenience wrapper around a dedicated PyMySQL connection."""

    def __init__(self) -> None:
        self._connection: Optional[pymysql.Connection] = _connect()
        self._read_only = False

    def _ensure_connection(self) -> pymysql.Connection:
        connection = self._connection
        if connection is None or not getattr(connection, "open", False):
            connection = _connect()
            self._connection = connection
        return connection

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------
    def reconnect(self) -> None:
        connection = self._ensure_connection()
        try:
            connection.ping(reconnect=True)
        except Exception as exc:  # pragma: no cover - ping failures rare
            _LOG.warning("db.reconnect", extra={"event": "db.reconnect", "error": str(exc)})
            try:
                connection.close()
            finally:
                self._connection = _connect()

    def close(self) -> None:
        connection = self._connection
        if connection is None:
            return
        try:
            connection.close()
        except Exception:  # pragma: no cover - defensive close
            pass
        finally:
            self._connection = None

    # ------------------------------------------------------------------
    # Role helpers
    # ------------------------------------------------------------------
    def as_reader(self) -> "DatabaseEngine":
        self._read_only = True
        return self

    def _guard_write(self, sql: str) -> None:
        if not self._read_only:
            return
        keyword = sql.lstrip().split(None, 1)[0].upper() if sql.strip() else ""
        if keyword in {"INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "ALTER", "DROP", "TRUNCATE"}:
            raise DatabaseError("Write attempt via read-only DatabaseEngine handle")

    # ------------------------------------------------------------------
    # Transaction context
    # ------------------------------------------------------------------
    @contextmanager
    def transaction(self) -> Iterator["DatabaseEngine"]:
        connection = self._ensure_connection()
        prev_autocommit = connection.get_autocommit()
        connection.autocommit(False)
        try:
            yield self
            connection.commit()
        except Exception:
            try:
                connection.rollback()
            finally:
                connection.autocommit(prev_autocommit)
            raise
        else:
            connection.autocommit(prev_autocommit)

    # ------------------------------------------------------------------
    # Execution primitives
    # ------------------------------------------------------------------
    def execute(
        self,
        sql: str,
        params: Optional[Any] = None,
        *,
        query_name: str | None = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self._guard_write(sql)
        connection = self._ensure_connection()
        with connection.cursor() as cursor:
            _execute(cursor, sql, params, query_name=query_name or "execute", context=context, many=False)
        connection.commit()

    def execute_many(
        self,
        sql: str,
        param_rows: Iterable[Any],
        *,
        query_name: str | None = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> None:
        rows = list(param_rows)
        if not rows:
            return
        self._guard_write(sql)
        connection = self._ensure_connection()
        with connection.cursor() as cursor:
            _execute(cursor, sql, rows, query_name=query_name or "execute_many", context=context, many=True)
        connection.commit()

    def execute_with_lastrowid(
        self,
        sql: str,
        params: Optional[Any] = None,
        *,
        query_name: str | None = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> int:
        self._guard_write(sql)
        connection = self._ensure_connection()
        with connection.cursor() as cursor:
            _execute(cursor, sql, params, query_name=query_name or "execute_with_lastrowid", context=context, many=False)
            lastrowid = cursor.lastrowid
        connection.commit()
        return int(lastrowid or 0)

    def fetch_one(
        self,
        sql: str,
        params: Optional[Any] = None,
        *,
        query_name: str | None = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Optional[Tuple[Any, ...]]:
        connection = self._ensure_connection()
        with connection.cursor() as cursor:
            _execute(cursor, sql, params, query_name=query_name or "fetch_one", context=context, many=False)
            row = cursor.fetchone()
        return tuple(row) if row is not None else None

    def fetch_all(
        self,
        sql: str,
        params: Optional[Any] = None,
        *,
        query_name: str | None = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> list[Tuple[Any, ...]]:
        connection = self._ensure_connection()
        with connection.cursor() as cursor:
            _execute(cursor, sql, params, query_name=query_name or "fetch_all", context=context, many=False)
            rows = cursor.fetchall()
        return [tuple(row) for row in rows]

    def fetch_one_dict(
        self,
        sql: str,
        params: Optional[Any] = None,
        *,
        query_name: str | None = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        connection = self._ensure_connection()
        with connection.cursor(DictCursor) as cursor:
            _execute(cursor, sql, params, query_name=query_name or "fetch_one_dict", context=context, many=False)
            row = cursor.fetchone()
        return dict(row) if row is not None else None

    def fetch_all_dict(
        self,
        sql: str,
        params: Optional[Any] = None,
        *,
        query_name: str | None = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> list[Dict[str, Any]]:
        connection = self._ensure_connection()
        with connection.cursor(DictCursor) as cursor:
            _execute(cursor, sql, params, query_name=query_name or "fetch_all_dict", context=context, many=False)
            rows = cursor.fetchall()
        return [dict(row) for row in rows]


def sanity_probe() -> None:
    """Execute a pair of probe queries to validate driver and param handling."""

    with connect() as connection:
        with connection.cursor() as cursor:
            _execute(cursor, "SELECT %s + %s", (1, 2), query_name="probe.pos", context={"probe": True}, many=False)
            cursor.fetchone()
        with connection.cursor() as cursor:
            _execute(
                cursor,
                "SELECT %(a)s + %(b)s",
                {"a": 1, "b": 2},
                query_name="probe.named",
                context={"probe": True},
                many=False,
            )
            cursor.fetchone()


__all__ = [
    "DatabaseEngine",
    "DatabaseError",
    "IntegrityDbError",
    "ParamStyleError",
    "TransientDbError",
    "connect",
    "sanity_probe",
]

