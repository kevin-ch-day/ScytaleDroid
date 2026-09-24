"""Database execution helpers and connection management for ScytaleDroid.

The module centralises all low-level database behaviour so other packages only
need to focus on business queries.  It normalises parameter styles (supporting
both ``%s`` and ``%(name)s`` placeholders), adds rich structured logging, and
provides a single place to tune retry, timeout and diagnostic policies.
"""

from __future__ import annotations

import hashlib
import logging
import re
import sqlite3
import time
import uuid
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

import pymysql
from pymysql import err
from pymysql.cursors import Cursor, DictCursor
from scytaledroid.Utils.LoggingUtils.redaction import redact_log_value

from . import db_config
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

_ENV_LOGGED = False

_SCALAR_SEQUENCE_TYPES = (str, bytes, bytearray, memoryview)
_T = TypeVar("_T")
_SQLITE_MARIADB_COLLATE_RE = re.compile(r"\s+COLLATE\s+utf8mb4_[A-Za-z0-9_]+", re.IGNORECASE)
_WRITE_KEYWORDS = frozenset(
    {"INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "ALTER", "DROP", "TRUNCATE"}
)


class DatabaseError(RuntimeError):
    """Base exception for database engine failures."""

    def __init__(
        self,
        message: str,
        *,
        errno: int | None = None,
        sqlstate: str | None = None,
    ) -> None:
        super().__init__(message)
        self.errno = errno
        self.sqlstate = sqlstate


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


def _iter_unquoted_percent_indices(sql: str) -> Iterator[int]:
    """Yield indexes of unquoted ``%`` tokens, skipping ``%%`` escapes."""

    index = 0
    length = len(sql)
    while index < length:
        char = sql[index]
        if char == "'":
            index += 1
            while index < length:
                if sql[index] == "'":
                    if index + 1 < length and sql[index + 1] == "'":
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            continue
        if char == "`":
            index += 1
            while index < length:
                if sql[index] == "`":
                    if index + 1 < length and sql[index + 1] == "`":
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            continue
        if char == '"':
            index += 1
            while index < length:
                if sql[index] == '"':
                    if index + 1 < length and sql[index + 1] == '"':
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            continue
        if char == "-" and index + 1 < length and sql[index + 1] == "-":
            index += 2
            while index < length and sql[index] not in {"\n", "\r"}:
                index += 1
            continue
        if char == "/" and index + 1 < length and sql[index + 1] == "*":
            index += 2
            while index + 1 < length and not (sql[index] == "*" and sql[index + 1] == "/"):
                index += 1
            index = min(length, index + 2)
            continue
        if char == "%":
            if index + 1 < length and sql[index + 1] == "%":
                index += 2
                continue
            yield index
        index += 1


def _percent_token_kind(sql: str, pos: int) -> str:
    match = NAMED_PARAM_PATTERN.match(sql, pos)
    if match:
        return "named"
    if pos + 1 < len(sql) and sql[pos + 1] == "s":
        return "positional"
    return "other"


def detect_placeholder_style(sql: str) -> str:
    """Return ``named``, ``positional``, ``mixed``, or ``none`` for unquoted placeholders."""

    named = False
    positional = False
    for pos in _iter_unquoted_percent_indices(sql):
        kind = _percent_token_kind(sql, pos)
        if kind == "named":
            named = True
        elif kind == "positional":
            positional = True
        if named and positional:
            return "mixed"
    if named:
        return "named"
    if positional:
        return "positional"
    return "none"


def _unquoted_named_matches(sql: str) -> list[re.Match[str]]:
    matches: list[re.Match[str]] = []
    for pos in _iter_unquoted_percent_indices(sql):
        match = NAMED_PARAM_PATTERN.match(sql, pos)
        if match:
            matches.append(match)
    return matches


def _rewrite_unquoted_named_to_positional(sql: str) -> str:
    matches = _unquoted_named_matches(sql)
    if not matches:
        return sql
    parts: list[str] = []
    last = 0
    for match in matches:
        parts.append(sql[last : match.start()])
        parts.append("%s")
        last = match.end()
    parts.append(sql[last:])
    return "".join(parts)


def _redact(value: Any) -> Any:
    return redact_log_value(value)


def _sql_log_fields(sql: str) -> dict[str, str]:
    compact = " ".join(str(sql or "").split())
    return {
        "sql_preview": compact[:240],
        "sql_sha1": hashlib.sha1(compact.encode("utf-8")).hexdigest(),
    }


def _normalise_single(sql: str, params: Any | None) -> _NormalisedStatement:
    style = detect_placeholder_style(sql)
    if style == "mixed":
        raise ParamStyleError("Statement mixes named and positional placeholders")

    if params is None:
        detected = "named" if style == "named" else "positional"
        return _NormalisedStatement(sql=sql, params=None, detected_style=detected)

    if style == "named":
        if not isinstance(params, Mapping):
            raise ParamStyleError("Named placeholders require a mapping of parameters")
        names = [match.group(1) for match in _unquoted_named_matches(sql)]
        if not names:
            raise ParamStyleError("Named style detected but no placeholders found")
        try:
            ordered = tuple(params[name] for name in names)
        except KeyError as exc:  # pragma: no cover - guarded by query definitions
            raise ParamStyleError(f"Missing parameter for placeholder: {exc.args[0]}") from exc
        rewritten = _rewrite_unquoted_named_to_positional(sql)
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

    style = detect_placeholder_style(sql)
    if style == "mixed":
        raise ParamStyleError("Statement mixes named and positional placeholders")

    if style == "named":
        names = [match.group(1) for match in _unquoted_named_matches(sql)]
        rewritten = _rewrite_unquoted_named_to_positional(sql)
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
    if not isinstance(exc, err.OperationalError):
        return False
    errno = _mysql_errno(exc)
    if errno in TRANSIENT_ERRNOS:
        return True
    text = str(exc).lower()
    markers = (
        "lost connection",
        "server has gone away",
        "timed out",
        "(2013",
        "(2014",
    )
    return any(marker in text for marker in markers)


def _mysql_errno(exc: Exception) -> int | None:
    code = getattr(exc, "errno", None)
    if isinstance(code, int):
        return code
    args = getattr(exc, "args", None)
    if isinstance(args, tuple) and args:
        first = args[0]
        if isinstance(first, int):
            return first
    text = str(exc)
    match = re.search(r"\((\d{4})\b", text)
    if match:
        try:
            return int(match.group(1))
        except Exception:
            return None
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


def _connect_mysql(config: Mapping[str, Any] | None = None) -> pymysql.Connection:
    effective = config or DB_CONFIG
    connection = pymysql.connect(
        host=str(effective.get("host", "localhost")),
        user=str(effective.get("user", "")),
        password=str(effective.get("password", "")),
        database=str(effective.get("database", "")),
        port=int(effective.get("port", 3306)),
        charset=str(effective.get("charset", "utf8mb4")),
        # Autocommit keeps single-statement writes durable for FK-linked tables.
        autocommit=True,
        connect_timeout=int(effective.get("connect_timeout", 5)),
        read_timeout=int(effective.get("read_timeout", 120)),
        write_timeout=int(effective.get("write_timeout", 120)),
    )
    _log_env_once(connection)
    return connection


def _connect_sqlite(config: Mapping[str, Any] | None = None) -> sqlite3.Connection:
    effective = config or DB_CONFIG
    db_path = Path(str(effective.get("database", "scytaledroid.sqlite")))
    readonly = bool(effective.get("readonly", False))
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


def _leading_sql_keyword(sql: str) -> str:
    """Return the first SQL keyword, skipping leading whitespace and comments."""

    index = 0
    length = len(sql)
    while index < length:
        char = sql[index]
        if char.isspace():
            index += 1
            continue
        if char == "-" and index + 1 < length and sql[index + 1] == "-":
            index += 2
            while index < length and sql[index] not in {"\n", "\r"}:
                index += 1
            continue
        if char == "/" and index + 1 < length and sql[index + 1] == "*":
            index += 2
            while index + 1 < length and not (sql[index] == "*" and sql[index + 1] == "/"):
                index += 1
            index = min(length, index + 2)
            continue
        break
    if index >= length:
        return ""
    return sql[index:].split(None, 1)[0].upper()


def _rewrite_for_sqlite(sql: str) -> str:
    """Convert unquoted ``%s`` placeholders into SQLite's ``?`` and drop MariaDB collations."""

    parts: list[str] = []
    last = 0
    for pos in _iter_unquoted_percent_indices(sql):
        if _percent_token_kind(sql, pos) != "positional":
            continue
        parts.append(sql[last:pos])
        parts.append("?")
        last = pos + 2
    parts.append(sql[last:])
    rewritten = "".join(parts)
    return _SQLITE_MARIADB_COLLATE_RE.sub("", rewritten)


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
    committed = False
    try:
        yield connection
        connection.commit()
        committed = True
    except Exception:
        try:
            connection.rollback()
        except Exception:  # pragma: no cover - defensive cleanup
            pass
        raise
    finally:
        if not committed:
            try:
                connection.rollback()
            except Exception:  # pragma: no cover - defensive cleanup
                pass
        engine.close()


def _wrap_db_error(cls: type[DatabaseError], exc: Exception) -> DatabaseError:
    sqlstate_raw = getattr(exc, "sqlstate", None)
    sqlstate = str(sqlstate_raw) if sqlstate_raw not in (None, "") else None
    return cls(str(exc), errno=_mysql_errno(exc), sqlstate=sqlstate)


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
        **_sql_log_fields(sql),
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
        raise _wrap_db_error(IntegrityDbError, exc) from exc
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
        raise _wrap_db_error(IntegrityDbError, exc) from exc
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
                "transient": transient,
                "in_transaction": in_transaction,
            },
            exc_info=True,
        )
        # Do not ping/reconnect here: the caller's cursor would be stale after a
        # reconnect, and fetch would then run against the dead handle. Engine
        # methods retry with a fresh cursor outside an active transaction.
        if transient:
            raise _wrap_db_error(TransientDbError, exc) from exc
        raise _wrap_db_error(DatabaseError, exc) from exc
    except sqlite3.OperationalError as exc:
        # SQLite backends (tests / bootstrap) routinely hit DDL/view limits; avoid full tracebacks.
        _LOG.warning(
            "db.exec.sqlite_operational",
            extra={
                **base_extra,
                **summary,
                "event": "db.exec.sqlite_operational",
                "detected_style": normalised.detected_style,
                "err_class": exc.__class__.__name__,
            },
        )
        raise _wrap_db_error(DatabaseError, exc) from exc
    except sqlite3.DatabaseError as exc:
        _LOG.error(
            "db.exec.failed",
            extra={
                **base_extra,
                **summary,
                "event": "db.exec.failed",
                "detected_style": normalised.detected_style,
                "err_class": exc.__class__.__name__,
            },
            exc_info=True,
        )
        raise _wrap_db_error(DatabaseError, exc) from exc
    except Exception as exc:
        _LOG.error(
            "db.exec.failed",
            extra={
                **base_extra,
                **summary,
                "event": "db.exec.failed",
                "detected_style": normalised.detected_style,
                "err_class": exc.__class__.__name__,
            },
            exc_info=True,
        )
        raise _wrap_db_error(DatabaseError, exc) from exc


class DatabaseEngine:
    """Convenience wrapper around a dedicated database connection.

    OSS vNext posture:
    - DB is optional; when disabled, core workflows must not instantiate this class.
    - When enabled, MySQL/MariaDB is required (no SQLite fallback for operators).

    Unit tests may use SQLite as a local backend.
    """

    def __init__(
        self,
        *,
        config_override: Mapping[str, Any] | None = None,
        config_source: str | None = None,
    ) -> None:
        self._config = dict(config_override or DB_CONFIG)
        self._config_source = config_source or "default"
        self._dialect = str(self._config.get("engine", "disabled")).lower()
        if self._dialect == "disabled":
            raise RuntimeError(
                "Database is disabled. Configure SCYTALEDROID_DB_URL (mysql/mariadb) or "
                "SCYTALEDROID_DB_NAME/USER/PASSWD/HOST/PORT to enable DB features."
            )
        if self._dialect == "sqlite" and not db_config.is_test_env():
            raise RuntimeError(
                "SQLite backend is not supported for OSS operator runs. "
                "Remove DB config to disable DB, or configure a mysql/mariadb DSN."
            )
        self._connection: Any | None = self._connect_any()
        self._read_only = False
        self._txn_depth = 0

    def _connect_any(self) -> Any:
        if self._dialect == "mysql":
            return _connect_mysql(self._config)
        if self._dialect == "disabled":
            raise RuntimeError("Database is disabled (no backend configured).")
        return _connect_sqlite(self._config)

    def _ensure_connection(self) -> Any:
        connection = self._connection
        if self._dialect == "mysql":
            if connection is None or not getattr(connection, "open", False):
                connection = _connect_mysql(self._config)
                self._connection = connection
        else:
            if connection is None:
                connection = _connect_sqlite(self._config)
                self._connection = connection
        return connection

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------
    def in_transaction(self) -> bool:
        if self._txn_depth > 0:
            return True
        connection = self._connection
        if connection is None:
            return False
        if self._dialect == "mysql":
            try:
                return not bool(connection.get_autocommit())
            except Exception:
                return False
        try:
            return bool(getattr(connection, "in_transaction", False))
        except Exception:
            return False

    def connection_is_usable(self) -> bool:
        connection = self._connection
        if connection is None:
            return False
        if self._dialect == "mysql":
            return bool(getattr(connection, "open", False))
        return True

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
                    self._connection = _connect_mysql(self._config)
        else:
            try:
                connection.cursor().execute("SELECT 1")
            except Exception:
                self._connection = _connect_sqlite(self._config)

    def close(self) -> None:
        connection = self._connection
        try:
            if connection is not None:
                try:
                    connection.close()
                except Exception:  # pragma: no cover - defensive close
                    pass
        finally:
            self._connection = None
            self._txn_depth = 0

    # ------------------------------------------------------------------
    # Role helpers
    # ------------------------------------------------------------------
    def as_reader(self) -> DatabaseEngine:
        self._read_only = True
        return self

    def _guard_write(self, sql: str) -> None:
        if not self._read_only:
            return
        keyword = _leading_sql_keyword(sql)
        if keyword in _WRITE_KEYWORDS:
            raise DatabaseError("Write attempt via read-only DatabaseEngine handle")

    def _with_transient_retry(self, operation: Callable[[Any], _T]) -> _T:
        attempt = 0
        while True:
            attempt += 1
            connection = self._ensure_connection()
            try:
                return operation(connection)
            except TransientDbError:
                if self.in_transaction() or attempt >= MAX_RETRIES:
                    raise
                time.sleep(0.2 * attempt)
                try:
                    self.reconnect()
                except Exception:
                    pass

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
        is_nested = self._txn_depth > 0
        self._txn_depth += 1

        # Nested scopes share the outer transaction boundary. Do not
        # toggle autocommit or issue intermediate commit/rollback.
        if is_nested:
            try:
                yield self
            finally:
                self._txn_depth = max(0, self._txn_depth - 1)
            return

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
        committed = False
        try:
            yield self
            connection.commit()
            committed = True
        except Exception:
            try:
                connection.rollback()
            except Exception:
                pass
            raise
        finally:
            if not committed:
                try:
                    connection.rollback()
                except Exception:
                    pass
            if self._dialect == "mysql":
                try:
                    connection.autocommit(prev_autocommit)
                except Exception:
                    pass
            self._txn_depth = max(0, self._txn_depth - 1)

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

        def _op(connection: Any) -> None:
            with _cursor_ctx(connection) as cursor:
                _execute(
                    cursor,
                    sql,
                    params,
                    query_name=query_name or "execute",
                    context=context,
                    many=False,
                )

        self._with_transient_retry(_op)
        connection = self._ensure_connection()
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

        def _op(connection: Any) -> int:
            with _cursor_ctx(connection) as cursor:
                _execute(
                    cursor,
                    sql,
                    params,
                    query_name=query_name or "execute_with_rowcount",
                    context=context,
                    many=False,
                )
                return int(getattr(cursor, "rowcount", 0) or 0)

        rowcount = self._with_transient_retry(_op)
        connection = self._ensure_connection()
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

        def _op(connection: Any) -> None:
            with _cursor_ctx(connection) as cursor:
                _execute(
                    cursor,
                    sql,
                    rows,
                    query_name=query_name or "execute_many",
                    context=context,
                    many=True,
                )

        self._with_transient_retry(_op)
        connection = self._ensure_connection()
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

        def _op(connection: Any) -> int:
            with _cursor_ctx(connection) as cursor:
                _execute(
                    cursor,
                    sql,
                    params,
                    query_name=query_name or "execute_with_lastrowid",
                    context=context,
                    many=False,
                )
                return int(getattr(cursor, "lastrowid", None) or 0)

        lastrowid = self._with_transient_retry(_op)
        connection = self._ensure_connection()
        if self._should_commit(connection):
            connection.commit()
        return lastrowid

    def fetch_one(
        self,
        sql: str,
        params: Any | None = None,
        *,
        query_name: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> tuple[Any, ...] | None:
        def _op(connection: Any) -> tuple[Any, ...] | None:
            with _cursor_ctx(connection) as cursor:
                _execute(
                    cursor,
                    sql,
                    params,
                    query_name=query_name or "fetch_one",
                    context=context,
                    many=False,
                )
                row = cursor.fetchone()
            if row is None:
                return None
            if isinstance(row, sqlite3.Row):
                return tuple(row)
            return tuple(row)

        return self._with_transient_retry(_op)

    def fetch_all(
        self,
        sql: str,
        params: Any | None = None,
        *,
        query_name: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> list[tuple[Any, ...]]:
        def _op(connection: Any) -> list[tuple[Any, ...]]:
            with _cursor_ctx(connection) as cursor:
                _execute(
                    cursor,
                    sql,
                    params,
                    query_name=query_name or "fetch_all",
                    context=context,
                    many=False,
                )
                rows = cursor.fetchall()
            converted = []
            for row in rows:
                if isinstance(row, sqlite3.Row):
                    converted.append(tuple(row))
                else:
                    converted.append(tuple(row))
            return converted

        return self._with_transient_retry(_op)

    def fetch_one_dict(
        self,
        sql: str,
        params: Any | None = None,
        *,
        query_name: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        def _op(connection: Any) -> dict[str, Any] | None:
            dict_mode = self._dialect == "mysql"
            with _cursor_ctx(connection, dict_mode=dict_mode) as cursor:
                _execute(
                    cursor,
                    sql,
                    params,
                    query_name=query_name or "fetch_one_dict",
                    context=context,
                    many=False,
                )
                row = cursor.fetchone()
            if row is None:
                return None
            if isinstance(row, sqlite3.Row):
                return dict(row)
            return dict(row)

        return self._with_transient_retry(_op)

    def fetch_all_dict(
        self,
        sql: str,
        params: Any | None = None,
        *,
        query_name: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        def _op(connection: Any) -> list[dict[str, Any]]:
            dict_mode = self._dialect == "mysql"
            with _cursor_ctx(connection, dict_mode=dict_mode) as cursor:
                _execute(
                    cursor,
                    sql,
                    params,
                    query_name=query_name or "fetch_all_dict",
                    context=context,
                    many=False,
                )
                rows = cursor.fetchall()
            return [dict(row) if not isinstance(row, sqlite3.Row) else dict(row) for row in rows]

        return self._with_transient_retry(_op)


def sanity_probe() -> None:
    """Execute a pair of probe queries to validate driver and param handling."""

    with connect() as connection:
        with connection.cursor() as cursor:
            _execute(
                cursor,
                "SELECT %s + %s",
                (1, 2),
                query_name="probe.pos",
                context={"probe": True},
                many=False,
            )
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
    "detect_placeholder_style",
    "sanity_probe",
    "ensure_db_ready",
]


def ensure_db_ready(*, require_schema: bool = True) -> None:
    """Fail fast when MariaDB is configured but unreachable or missing schema."""

    dialect = str(DB_CONFIG.get("engine", "disabled")).lower()
    if dialect != "mysql":
        return

    def _fmt_cfg(key: str, default: str = "<unknown>") -> str:
        val = DB_CONFIG.get(key)
        return str(val) if val not in (None, "") else default

    engine: DatabaseEngine | None = None
    try:
        try:
            engine = DatabaseEngine()
            engine.fetch_one("SELECT 1")
        except Exception as exc:
            raise SystemExit(
                f"Database connection failed for configured MariaDB backend "
                f"({DB_CONFIG.get('user', '<unknown>')}@{_fmt_cfg('host')}:{_fmt_cfg('port')}/{_fmt_cfg('database')}): {exc}\n"
                "Fix credentials/host, or disable DB by unsetting SCYTALEDROID_DB_URL (filesystem remains canonical)."
            ) from exc

        if not require_schema:
            return
        try:
            row = engine.fetch_one(
                "SELECT version, applied_at_utc FROM schema_version ORDER BY applied_at_utc DESC LIMIT 1"
            )
            if not row:
                raise RuntimeError("schema_version table empty")
        except TransientDbError as exc:
            raise SystemExit(
                f"Database connection failed for configured MariaDB backend "
                f"({DB_CONFIG.get('user', '<unknown>')}@{_fmt_cfg('host')}:{_fmt_cfg('port')}/{_fmt_cfg('database')}): {exc}\n"
                "Fix credentials/host, or disable DB by unsetting SCYTALEDROID_DB_URL (filesystem remains canonical)."
            ) from exc
        except Exception as exc:
            raise SystemExit(
                f"Database schema missing or incompatible for {DB_CONFIG.get('database')}: {exc}\n"
                "Run: python -m scytaledroid.Database.tools.bootstrap (or db migrate/init) against your MariaDB."
            ) from exc
    finally:
        if engine is not None:
            try:
                engine.close()
            except Exception:
                pass
