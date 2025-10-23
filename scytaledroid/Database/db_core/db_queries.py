"""SQL execution helper used by database query modules."""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple, Union

from .db_engine import DatabaseEngine
from .session import database_session, get_current_engine

ParamsType = Optional[Union[Sequence[Any], Mapping[str, Any]]]
ParamRow = Tuple[Any, ...]


def _normalise_params(params: ParamsType) -> Union[Tuple[Any, ...], Mapping[str, Any]]:
    """Coerce params to a tuple or mapping suitable for mysql.connector."""
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
            return _dispatch_single(db, query, normalised_params, base, return_lastrowid)
    else:
        db = eng_or_ctx  # type: ignore[assignment]
        return _dispatch_single(db, query, normalised_params, base, return_lastrowid)


def _dispatch_single(
    db: DatabaseEngine,
    query: str,
    params: Union[Tuple[Any, ...], Mapping[str, Any]],
    fetch_mode: str,
    return_lastrowid: bool,
) -> Any:
    """Route to the appropriate DatabaseEngine method for single-statement exec."""
    if fetch_mode in {"one", "one_tuple"}:
        return db.fetch_one(query, params if isinstance(params, tuple) else None)  # type: ignore[arg-type]
    if fetch_mode == "one_dict":
        return db.fetch_one_dict(query, params if isinstance(params, tuple) else None)  # type: ignore[arg-type]
    if fetch_mode in {"all", "all_tuple"}:
        return db.fetch_all(query, params if isinstance(params, tuple) else None)  # type: ignore[arg-type]
    if fetch_mode == "all_dict":
        return db.fetch_all_dict(query, params if isinstance(params, tuple) else None)  # type: ignore[arg-type]

    # fetch_mode == "none"
    if return_lastrowid:
        return db.execute_with_lastrowid(query, params if isinstance(params, tuple) else None)  # type: ignore[arg-type]
    db.execute(query, params if isinstance(params, tuple) else None)  # type: ignore[arg-type]
    return None


def run_sql_many(
    query: str,
    param_rows: Iterable[ParamRow],
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

    eng_or_ctx = _resolve_engine()
    if hasattr(eng_or_ctx, "__enter__") and hasattr(eng_or_ctx, "__exit__"):
        with eng_or_ctx as db:  # type: ignore[assignment]
            db.execute_many(query, rows)
    else:
        db = eng_or_ctx  # type: ignore[assignment]
        db.execute_many(query, rows)


__all__ = ["run_sql", "run_sql_many"]
