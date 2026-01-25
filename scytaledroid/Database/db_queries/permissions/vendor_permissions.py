"""Deprecated SQL statements for android_vendor_permissions (legacy)."""

from __future__ import annotations

import warnings

warnings.warn(
    "android_vendor_permissions is deprecated; use android_permission_dict_oem.",
    DeprecationWarning,
    stacklevel=2,
)

_NOOP = ""
_ZERO = "SELECT 0"

CREATE_TABLE = _NOOP
UPSERT_VENDOR = _NOOP
COUNT_ROWS = _ZERO
TABLE_EXISTS = _ZERO

__all__ = [
    "CREATE_TABLE",
    "UPSERT_VENDOR",
    "COUNT_ROWS",
    "TABLE_EXISTS",
]
