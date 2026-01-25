"""Deprecated SQL statements for legacy framework permission tables."""

import warnings

warnings.warn(
    "android_framework_permissions queries are deprecated; "
    "use android_permission_dict_aosp instead.",
    DeprecationWarning,
    stacklevel=2,
)

_NOOP = "SELECT 1"
_ZERO = "SELECT 0"

CREATE_TABLE = _NOOP

UPSERT_PERMISSION = _NOOP

COUNT_ROWS = _ZERO

TABLE_EXISTS = _ZERO

PROTECTION_COUNTS = _NOOP

SELECT_CATALOG = _NOOP

SELECT_UPDATED_FINGERPRINT = _ZERO

__all__ = [
    "CREATE_TABLE",
    "UPSERT_PERMISSION",
    "COUNT_ROWS",
    "TABLE_EXISTS",
    "PROTECTION_COUNTS",
    "SELECT_CATALOG",
    "SELECT_UPDATED_FINGERPRINT",
]
