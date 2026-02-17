"""Database execution helpers and connection management for ScytaleDroid.

The module centralises all low-level database behaviour so other packages only
need to focus on business queries.  It normalises parameter styles (supporting
both ``%s`` and ``%(name)s`` placeholders), adds rich structured logging, and
provides a single place to tune retry, timeout and diagnostic policies.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import time
import uuid
from collections.abc import Iterable, Iterator, Mapping, MutableMapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
# Retry transient transport/lock failures. 2013/2014 are common disconnect/read timeout
# codes seen in long-running static persistence sessions.
TRANSIENT_ERRNOS = {1205, 1213, 2006, 2013, 2014}
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
    params: Sequence[Any] | None
    detected_style: str
    batch_size: int | None = None


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


def _normalise_single(sql: str, params: Any | None) -> _NormalisedStatement:
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


def _summarise_params(params: Any, *, many: bool) -> dict[str, Any]:
    if params is None:
        return {"params_present": False}
    if many:
        if isinstance(params, Sequence):
            size = len(params)
            summary: dict[str, Any] = {
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
    return isinstance(exc, err.OperationalError) and _mysql_errno(exc) in TRANSIENT_ERRNOS


def _mysql_errno(exc: Exception) -> int | None:
    code = getattr(exc, "errno", None)
    if isinstance(code, int):
        return code
    args = getattr(exc, "args", None)
    if isinstance(args, tuple) and args:
        first = args[0]
        if isinstance(first, int):
            return first
    return None


def _cursor_in_transaction(cursor: Cursor, *, dialect: str) -> bool:
    connection = getattr(cursor, "connection", None)
    if connection is None:
        return False
    if dialect == "mysql":
        try:
            # MySQL/PyMySQL transaction scope is represented by autocommit=False.
            return not bool(connection.get_autocommit())
        except Exception:
            return False
    try:
        return bool(getattr(connection, "in_transaction", False))
    except Exception:
        return False


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


def _connect_mysql() -> pymysql.Connection:
    connection = pymysql.connect(
        host=str(DB_CONFIG.get("host", "localhost")),
        user=str(DB_CONFIG.get("user", "")),
        password=str(DB_CONFIG.get("password", "")),
        database=str(DB_CONFIG.get("database", "")),
        port=int(DB_CONFIG.get("port", 3306)),
        charset=str(DB_CONFIG.get("charset", "utf8mb4")),
        # Autocommit keeps single-statement writes durable for FK-linked tables.
        autocommit=True,
        connect_timeout=int(DB_CONFIG.get("connect_timeout", 5)),
        read_timeout=int(DB_CONFIG.get("read_timeout", 30)),
        write_timeout=int(DB_CONFIG.get("write_timeout", 30)),
    )
    _log_env_once(connection)
    return connection


def _connect_sqlite() -> sqlite3.Connection:
    db_path = Path(str(DB_CONFIG.get("database", "scytaledroid.sqlite")))
    readonly = bool(DB_CONFIG.get("readonly", False))
    if not readonly:
        db_path.parent.mkdir(parents=True, exist_ok=True)
    if readonly:
        uri = f"file:{db_path}?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
    else:
        connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    connection.isolation_level = None  # explicit commit/rollback control
    return connection


def _rewrite_for_sqlite(sql: str) -> str:
    """Convert %s placeholders into SQLite's '?'."""
    return sql.replace("%s", "?")


@contextmanager
def _cursor_ctx(connection: Any, *, dict_mode: bool = False):
    if dict_mode and not isinstance(connection, sqlite3.Connection):
        cursor = connection.cursor(DictCursor)
    else:
        cursor = connection.cursor()
    try:
        yield cursor
    finally:
        try:
            cursor.close()
        except Exception:
            pass


@contextmanager
def connect() -> Iterator[Any]:
    engine = DatabaseEngine()
    connection = engine._ensure_connection()
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
    params: Any | None,
    *,
    query_name: str,
    context: Mapping[str, Any] | None,
    many: bool,
) -> _NormalisedStatement:
    dialect = "sqlite" if isinstance(cursor, sqlite3.Cursor) else "mysql"
    trace_id = uuid.uuid4().hex[:8]
    base_extra: dict[str, Any] = {
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
    except ParamStyleError:
        summary = _summarise_params(params, many=many)
        _LOG.error(
            "db.exec.paramstyle",
            extra={**base_extra, **summary, "event": "db.exec.paramstyle"},
            exc_info=True,
        )
        raise

    summary = _summarise_params(normalised.params, many=many)
    effective_sql = normalised.sql if dialect == "mysql" else _rewrite_for_sqlite(normalised.sql)
    exec_params = normalised.params
    if dialect == "sqlite" and exec_params is None:
        exec_params = ()

    attempt = 0
    while True:
        attempt += 1
        start_ts = time.perf_counter()
        in_transaction = _cursor_in_transaction(cursor, dialect=dialect)
        try:
            if many:
                assert normalised.params is not None
                cursor.executemany(effective_sql, exec_params)
            else:
                cursor.execute(effective_sql, exec_params)
            elapsed = int((time.perf_counter() - start_ts) * 1000)
            _LOG.debug(
                "db.exec.ok",
                extra={
                    **base_extra,
                    **summary,
                    "event": "db.exec.ok",
                    "detected_style": normalised.detected_style,
                    "elapsed_ms": elapsed,
                    "attempt": attempt,
                    "in_transaction": in_transaction,
                },
            )
            return normalised
        except sqlite3.IntegrityError as exc:
            _LOG.error(
                "db.exec.integrity",
                extra={
                    **base_extra,
                    **summary,
                    "event": "db.exec.integrity",
                    "detected_style": normalised.detected_style,
                    "err_class": exc.__class__.__name__,
                },
                exc_info=True,
            )
            raise IntegrityDbError(str(exc)) from exc
        except err.IntegrityError as exc:
            _LOG.error(
                "db.exec.integrity",
                extra={
                    **base_extra,
                    **summary,
                    "event": "db.exec.integrity",
                    "detected_style": normalised.detected_style,
                    "err_class": exc.__class__.__name__,
                    "err_code": _mysql_errno(exc),
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
                    "err_code": _mysql_errno(exc),
                    "sqlstate": getattr(exc, "sqlstate", None),
                    "attempt": attempt,
                    "transient": transient,
                    "in_transaction": in_transaction,
                },
                exc_info=True,
            )
            # Never reconnect/retry inside an active transaction. Let the caller
            # roll back the unit of work and retry from the outer boundary.
            if transient and in_transaction:
                raise TransientDbError(str(exc)) from exc
            if transient and attempt < MAX_RETRIES:
                time.sleep(0.2 * attempt)
                try:
                    cursor.connection.ping(reconnect=True)
                except Exception:
                    pass
                continue
            if transient:
                raise TransientDbError(str(exc)) from exc
            raise DatabaseError(str(exc)) from exc
        except sqlite3.DatabaseError as exc:
            _LOG.error(
                "db.exec.failed",
                extra={
                    **base_extra,
                    **summary,
                    "event": "db.exec.failed",
                    "detected_style": normalised.detected_style,
                    "err_class": exc.__class__.__name__,
                    "attempt": attempt,
                },
                exc_info=True,
            )
            raise DatabaseError(str(exc)) from exc
        except Exception as exc:
            _LOG.error(
                "db.exec.failed",
                extra={
                    **base_extra,
                    **summary,
                    "event": "db.exec.failed",
                    "detected_style": normalised.detected_style,
                    "err_class": exc.__class__.__name__,
                    "attempt": attempt,
                },
                exc_info=True,
            )
            raise DatabaseError(str(exc)) from exc
class DatabaseEngine:
    """Convenience wrapper around a dedicated database connection (MySQL or SQLite)."""

    def __init__(self) -> None:
        self._dialect = str(DB_CONFIG.get("engine", "sqlite")).lower()
        self._connection: Any | None = self._connect_any()
        self._read_only = False

    def _connect_any(self) -> Any:
        if self._dialect == "mysql":
            return _connect_mysql()
        return _connect_sqlite()

    def _ensure_connection(self) -> Any:
        connection = self._connection
        if self._dialect == "mysql":
            if connection is None or not getattr(connection, "open", False):
                connection = _connect_mysql()
                self._connection = connection
        else:
            if connection is None:
                connection = _connect_sqlite()
                self._connection = connection
        return connection

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------
    def reconnect(self) -> None:
        connection = self._ensure_connection()
        if self._dialect == "mysql":
            try:
                connection.ping(reconnect=True)
            except Exception as exc:  # pragma: no cover - ping failures rare
                _LOG.warning("db.reconnect", extra={"event": "db.reconnect", "error": str(exc)})
                try:
                    connection.close()
                finally:
                    self._connection = _connect_mysql()
        else:
            try:
                connection.cursor().execute("SELECT 1")
            except Exception:
                self._connection = _connect_sqlite()

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
    def as_reader(self) -> DatabaseEngine:
        self._read_only = True
        return self

    def _guard_write(self, sql: str) -> None:
        if not self._read_only:
            return
        keyword = sql.lstrip().split(None, 1)[0].upper() if sql.strip() else ""
        if keyword in {"INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "ALTER", "DROP", "TRUNCATE"}:
            raise DatabaseError("Write attempt via read-only DatabaseEngine handle")

    def _should_commit(self, connection: Any) -> bool:
        if self._dialect == "mysql":
            try:
                return bool(connection.get_autocommit())
            except Exception:
                return True
        return not bool(getattr(connection, "in_transaction", False))

    # ------------------------------------------------------------------
    # Transaction context
    # ------------------------------------------------------------------
    @contextmanager
    def transaction(self) -> Iterator[DatabaseEngine]:
        connection = self._ensure_connection()
        if self._dialect == "mysql":
            prev_autocommit = connection.get_autocommit()
            connection.autocommit(False)
        else:
            prev_autocommit = None
            # sqlite in autocommit mode needs an explicit BEGIN for atomicity
            if not bool(getattr(connection, "in_transaction", False)):
                try:
                    connection.execute("BEGIN")
                except sqlite3.OperationalError:
                    pass
        try:
            yield self
            connection.commit()
        except Exception:
            try:
                connection.rollback()
            finally:
                if self._dialect == "mysql":
                    connection.autocommit(prev_autocommit)
            raise
        else:
            if self._dialect == "mysql":
                connection.autocommit(prev_autocommit)

    # ------------------------------------------------------------------
    # Execution primitives
    # ------------------------------------------------------------------
    def execute(
        self,
        sql: str,
        params: Any | None = None,
        *,
        query_name: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        self._guard_write(sql)
        connection = self._ensure_connection()
        with _cursor_ctx(connection) as cursor:
            _execute(cursor, sql, params, query_name=query_name or "execute", context=context, many=False)
        if self._should_commit(connection):
            connection.commit()

    def execute_with_rowcount(
        self,
        sql: str,
        params: Any | None = None,
        *,
        query_name: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> int:
        self._guard_write(sql)
        connection = self._ensure_connection()
        with _cursor_ctx(connection) as cursor:
            _execute(
                cursor,
                sql,
                params,
                query_name=query_name or "execute_with_rowcount",
                context=context,
                many=False,
            )
            rowcount = int(getattr(cursor, "rowcount", 0) or 0)
        if self._should_commit(connection):
            connection.commit()
        return rowcount

    def execute_many(
        self,
        sql: str,
        param_rows: Iterable[Any],
        *,
        query_name: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        rows = list(param_rows)
        if not rows:
            return
        self._guard_write(sql)
        connection = self._ensure_connection()
        with _cursor_ctx(connection) as cursor:
            _execute(cursor, sql, rows, query_name=query_name or "execute_many", context=context, many=True)
        if self._should_commit(connection):
            connection.commit()

    def execute_with_lastrowid(
        self,
        sql: str,
        params: Any | None = None,
        *,
        query_name: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> int:
        self._guard_write(sql)
        connection = self._ensure_connection()
        with _cursor_ctx(connection) as cursor:
            _execute(cursor, sql, params, query_name=query_name or "execute_with_lastrowid", context=context, many=False)
            lastrowid = getattr(cursor, "lastrowid", None)
        if self._should_commit(connection):
            connection.commit()
        return int(lastrowid or 0)

    def fetch_one(
        self,
        sql: str,
        params: Any | None = None,
        *,
        query_name: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> tuple[Any, ...] | None:
        connection = self._ensure_connection()
        with _cursor_ctx(connection) as cursor:
            _execute(cursor, sql, params, query_name=query_name or "fetch_one", context=context, many=False)
            row = cursor.fetchone()
        if row is None:
            return None
        if isinstance(row, sqlite3.Row):
            return tuple(row)
        return tuple(row)

    def fetch_all(
        self,
        sql: str,
        params: Any | None = None,
        *,
        query_name: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> list[tuple[Any, ...]]:
        connection = self._ensure_connection()
        with _cursor_ctx(connection) as cursor:
            _execute(cursor, sql, params, query_name=query_name or "fetch_all", context=context, many=False)
            rows = cursor.fetchall()
        converted = []
        for row in rows:
            if isinstance(row, sqlite3.Row):
                converted.append(tuple(row))
            else:
                converted.append(tuple(row))
        return converted

    def fetch_one_dict(
        self,
        sql: str,
        params: Any | None = None,
        *,
        query_name: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        connection = self._ensure_connection()
        if self._dialect == "mysql":
            with _cursor_ctx(connection, dict_mode=True) as cursor:
                _execute(cursor, sql, params, query_name=query_name or "fetch_one_dict", context=context, many=False)
                row = cursor.fetchone()
        else:
            with _cursor_ctx(connection) as cursor:
                _execute(cursor, sql, params, query_name=query_name or "fetch_one_dict", context=context, many=False)
                row = cursor.fetchone()
        if row is None:
            return None
        if isinstance(row, sqlite3.Row):
            return dict(row)
        return dict(row)

    def fetch_all_dict(
        self,
        sql: str,
        params: Any | None = None,
        *,
        query_name: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        connection = self._ensure_connection()
        if self._dialect == "mysql":
            with _cursor_ctx(connection, dict_mode=True) as cursor:
                _execute(cursor, sql, params, query_name=query_name or "fetch_all_dict", context=context, many=False)
                rows = cursor.fetchall()
        else:
            with _cursor_ctx(connection) as cursor:
                _execute(cursor, sql, params, query_name=query_name or "fetch_all_dict", context=context, many=False)
                rows = cursor.fetchall()
        return [dict(row) if not isinstance(row, sqlite3.Row) else dict(row) for row in rows]


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
    "ensure_db_ready",
]


def ensure_db_ready(*, require_schema: bool = True) -> None:
    """Fail fast when MariaDB is configured but unreachable or missing schema."""

    dialect = str(DB_CONFIG.get("engine", "sqlite")).lower()
    if dialect != "mysql":
        return

    def _fmt_cfg(key: str, default: str = "<unknown>") -> str:
        val = DB_CONFIG.get(key)
        return str(val) if val not in (None, "") else default

    try:
        engine = DatabaseEngine()
        engine.fetch_one("SELECT 1")
    except Exception as exc:
        raise SystemExit(
            f"Database connection failed for configured MariaDB backend "
            f"({DB_CONFIG.get('user', '<unknown>')}@{_fmt_cfg('host')}:{_fmt_cfg('port')}/{_fmt_cfg('database')}): {exc}\n"
            "Fix credentials/host or unset SCYTALEDROID_DB_URL to use SQLite."
        ) from exc

    if not require_schema:
        return
    try:
        row = engine.fetch_one(
            "SELECT version, applied_at_utc FROM schema_version ORDER BY applied_at_utc DESC LIMIT 1"
        )
        if not row:
            raise RuntimeError("schema_version table empty")
    except Exception as exc:
        raise SystemExit(
            f"Database schema missing or incompatible for {DB_CONFIG.get('database')}: {exc}\n"
            "Run: python -m scytaledroid.Database.tools.bootstrap (or db migrate/init) against your MariaDB."
        ) from exc
