"""Deprecated SQL statements for android_unknown_permissions (legacy)."""

from __future__ import annotations

import warnings

warnings.warn(
    "android_unknown_permissions is deprecated; use android_permission_dict_unknown.",
    DeprecationWarning,
    stacklevel=2,
)

_NOOP = ""
_ZERO = "SELECT 0"

CREATE_TABLE = _NOOP
ALTER_ADD_TRIAGE_COLUMNS = _NOOP
ALTER_ADD_GHOST_COLUMNS = _NOOP
UPSERT_UNKNOWN = _NOOP
UPDATE_GHOST = _NOOP
COUNT_ROWS = _ZERO
TABLE_EXISTS = _ZERO

__all__ = [
    "CREATE_TABLE",
    "ALTER_ADD_TRIAGE_COLUMNS",
    "ALTER_ADD_GHOST_COLUMNS",
    "UPSERT_UNKNOWN",
    "UPDATE_GHOST",
    "COUNT_ROWS",
    "TABLE_EXISTS",
]
