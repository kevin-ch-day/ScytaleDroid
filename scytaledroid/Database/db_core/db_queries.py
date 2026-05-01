"""SQL execution helper used by database query modules."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .db_engine import DatabaseEngine
from .session import database_session, get_current_engine

ParamsType = Sequence[Any] | Mapping[str, Any] | None
ParamRow = tuple[Any, ...]

_PLACEHOLDER_SCAN_RE = re.compile("%")


def _prepare_params(
    params: tuple[Any, ...] | Mapping[str, Any]
) -> tuple[Any, ...] | Mapping[str, Any] | None:
    """Return None when the parameter payload is empty; otherwise the original."""

    if isinstance(params, tuple) and not params:
        return None
    if isinstance(params, Mapping) and not params:
        return None
    return params


def _normalise_params(params: ParamsType) -> tuple[Any, ...] | Mapping[str, Any]:
    """Coerce params to a tuple or mapping suitable for the database engine."""
    if params is None:
        return ()
    if isinstance(params, Mapping):
        return params
    if isinstance(params, tuple):
        return params
    if isinstance(params, list):
        return tuple(params)
    # Single scalar positional
    return (params,)


def _detect_placeholder_style(query: str) -> str:
    """Return 'named', 'positional', 'mixed', or 'none' for *query*."""

    named = False
    positional = False

    index = 0
    length = len(query)
    while index < length:
        match = _PLACEHOLDER_SCAN_RE.search(query, index)
        if not match:
            break
        pos = match.start()
        if pos + 1 >= length:
            break
        next_char = query[pos + 1]
        if next_char == "%":
            index = pos + 2
            continue
        if next_char == "(":
            named = True
        else:
            positional = True
        if named and positional:
            return "mixed"
        index = pos + 1

    if named:
        return "named"
    if positional:
        return "positional"
    return "none"


def _validate_placeholder_style(query: str, params: tuple[Any, ...] | Mapping[str, Any]) -> None:
    """Ensure SQL placeholders and provided params are compatible."""

    style = _detect_placeholder_style(query)
    if style == "none":
        return
    if style == "mixed":
        raise ValueError("SQL query mixes named and positional placeholders; use a single style.")

    if style == "named":
        if not isinstance(params, Mapping):
            raise ValueError(
                "SQL query uses named placeholders but parameters were not provided as a mapping."
            )
        return

    # style == "positional"
    if isinstance(params, Mapping):
        raise ValueError(
            "SQL query uses positional placeholders but parameters were provided as a mapping."
        )


def _resolve_engine() -> DatabaseEngine:
    """Prefer a current (caller-managed) engine; otherwise create session-local."""
    eng = get_current_engine()
    if eng is not None:
        return eng
    # Fallback to a context-managed engine from session()
    # We return the session context object directly since it yields a DatabaseEngine.
    # The context is used only inside run_sql/ run_sql_many scopes below.
    return database_session()  # type: ignore[return-value]


def run_sql(
    query: str,
    params: ParamsType = None,
    *,
    fetch: str = "none",
    dictionary: bool = False,
    return_lastrowid: bool = False,
    query_name: str | None = None,
    context: Mapping[str, Any] | None = None,
) -> Any:
    """Execute SQL and return results based on the requested fetch mode.

    Args:
        query: The SQL statement to execute.
        params: Optional parameters (sequence or mapping).
        fetch: One of {"none","one","all"}; append "_dict" or set dictionary=True for dict rows.
        dictionary: If True, results use dict row format (requires fetch != "none").
        return_lastrowid: If True and fetch == "none", returns lastrowid for inserts.

    Returns:
        Query result depending on fetch mode, or lastrowid/None for writes.
    """
    normalised_params = _normalise_params(params)
    _validate_placeholder_style(query, normalised_params)

    # Normalize/validate fetch mode
    base = (fetch or "none").strip().lower()
    if base not in {"none", "one", "all", "one_dict", "all_dict"}:
        raise ValueError(f"Unsupported fetch mode: {fetch}")

    if dictionary:
        if base == "none":
            raise ValueError("dictionary=True requires fetch in {'one','all'}")
        if not base.endswith("_dict"):
            base = f"{base}_dict"

    # Obtain engine (existing or session-scoped)
    eng_or_ctx = _resolve_engine()
    # If we received a context manager from database_session(), enter/exit it here.
    if hasattr(eng_or_ctx, "__enter__") and hasattr(eng_or_ctx, "__exit__"):
        with eng_or_ctx as db:  # type: ignore[assignment]
            return _dispatch_single(
                db,
                query,
                normalised_params,
                base,
                return_lastrowid,
                query_name=query_name,
                context=context,
            )
    else:
        db = eng_or_ctx  # type: ignore[assignment]
        return _dispatch_single(
            db,
            query,
            normalised_params,
            base,
            return_lastrowid,
            query_name=query_name,
            context=context,
        )


def _dispatch_single(
    db: DatabaseEngine,
    query: str,
    params: tuple[Any, ...] | Mapping[str, Any],
    fetch_mode: str,
    return_lastrowid: bool,
    *,
    query_name: str | None,
    context: Mapping[str, Any] | None,
) -> Any:
    """Route to the appropriate DatabaseEngine method for single-statement exec."""
    exec_params = _prepare_params(params)

    effective_name = query_name or f"run_sql.{fetch_mode}"

    if fetch_mode in {"one", "one_tuple"}:
        return db.fetch_one(query, exec_params, query_name=effective_name, context=context)
    if fetch_mode == "one_dict":
        return db.fetch_one_dict(query, exec_params, query_name=effective_name, context=context)
    if fetch_mode in {"all", "all_tuple"}:
        return db.fetch_all(query, exec_params, query_name=effective_name, context=context)
    if fetch_mode == "all_dict":
        return db.fetch_all_dict(query, exec_params, query_name=effective_name, context=context)

    # fetch_mode == "none"
    if return_lastrowid:
        return db.execute_with_lastrowid(query, exec_params, query_name=effective_name, context=context)
    db.execute(query, exec_params, query_name=effective_name, context=context)
    return None


def run_sql_many(
    query: str,
    param_rows: Iterable[ParamRow],
    *,
    query_name: str | None = None,
    context: Mapping[str, Any] | None = None,
) -> None:
    """Execute a batched DML statement with many parameter rows.

    Notes:
        - This uses DatabaseEngine.execute_many (auto-commit behavior).
        - For atomic series of batched writes, wrap the caller’s sequence in:
              with db.transaction():
                  run_sql_many(...)
                  run_sql_many(...)

    Args:
        query: Parameterized SQL (e.g., INSERT ... VALUES (%s,%s,%s) ON DUPLICATE KEY UPDATE ...).
        param_rows: Iterable of tuples matching the placeholders in `query`.
    """
    rows = list(param_rows)
    if not rows:
        return

    style = _detect_placeholder_style(query)
    if style == "named":
        raise ValueError("run_sql_many requires positional placeholders when params are sequences.")
    if style == "mixed":
        raise ValueError("SQL query mixes named and positional placeholders; use a single style.")

    eng_or_ctx = _resolve_engine()
    if hasattr(eng_or_ctx, "__enter__") and hasattr(eng_or_ctx, "__exit__"):
        with eng_or_ctx as db:  # type: ignore[assignment]
            db.execute_many(query, rows, query_name=query_name, context=context)
    else:
        db = eng_or_ctx  # type: ignore[assignment]
        db.execute_many(query, rows, query_name=query_name, context=context)


def run_sql_write(
    query: str,
    params: ParamsType = None,
    *,
    query_name: str | None = None,
    context: Mapping[str, Any] | None = None,
) -> None:
    """Execute an idempotent write statement with centralized retry handling."""

    run_sql(
        query,
        params,
        fetch="none",
        query_name=query_name or "run_sql.write",
        context=context,
    )


def run_sql_rowcount(
    query: str,
    params: ParamsType = None,
    *,
    query_name: str | None = None,
    context: Mapping[str, Any] | None = None,
) -> int:
    """Execute a write statement and return affected row count."""

    normalised_params = _normalise_params(params)
    _validate_placeholder_style(query, normalised_params)
    exec_params = _prepare_params(normalised_params)
    eng_or_ctx = _resolve_engine()
    if hasattr(eng_or_ctx, "__enter__") and hasattr(eng_or_ctx, "__exit__"):
        with eng_or_ctx as db:  # type: ignore[assignment]
            return int(
                db.execute_with_rowcount(
                    query,
                    exec_params,
                    query_name=query_name or "run_sql.rowcount",
                    context=context,
                )
            )
    db = eng_or_ctx  # type: ignore[assignment]
    return int(
        db.execute_with_rowcount(
            query,
            exec_params,
            query_name=query_name or "run_sql.rowcount",
            context=context,
        )
    )


__all__ = ["run_sql", "run_sql_many", "run_sql_rowcount", "run_sql_write"]
