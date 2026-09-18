"""Allowlist quoting for interpolated SQL identifiers.

Table and column names cannot be bound as query parameters. Callers that
build DDL/DML from ``SHOW TABLES`` / ``information_schema`` must refuse
anything that is not a plain ``[A-Za-z_][A-Za-z0-9_]*`` ident.
"""

from __future__ import annotations

import re

_SAFE_SQL_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SAFE_VIEWLIKE_IDENT_RE = re.compile(r"^vw?_[A-Za-z0-9_]+$")


def quote_sql_ident(name: str) -> str | None:
    """Return a backtick-quoted identifier, or ``None`` when the name is unsafe."""

    if not _SAFE_SQL_IDENT_RE.fullmatch(str(name or "")):
        return None
    return f"`{name}`"


def require_sql_ident(name: str) -> str:
    """Return a backtick-quoted identifier, or raise ``ValueError``."""

    quoted = quote_sql_ident(name)
    if quoted is None:
        raise ValueError(f"refusing unsafe SQL identifier: {name!r}")
    return quoted


def quote_viewlike_ident(name: str) -> str | None:
    """Quote a ``v_*`` / ``vw_*`` identifier, or ``None`` when the name is unsafe."""

    text = str(name or "")
    if not _SAFE_VIEWLIKE_IDENT_RE.fullmatch(text):
        return None
    return f"`{text}`"
