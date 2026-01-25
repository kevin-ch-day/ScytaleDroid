"""Deprecated SQL for per-APK detected permissions (observations)."""

import warnings

warnings.warn(
    "android_detected_permissions queries are deprecated; "
    "use permission dict tables instead.",
    DeprecationWarning,
    stacklevel=2,
)

_NOOP = "SELECT 1"
_ZERO = "SELECT 0"

CREATE_TABLE = _NOOP

UPSERT_DETECTED = _NOOP

# Legacy upsert for deployments with the old schema (sha256-based uniqueness)
UPSERT_DETECTED_LEGACY = _NOOP

SELECT_FRAMEWORK_PROTECTION = _NOOP

TABLE_EXISTS = _ZERO

__all__ = [
    "CREATE_TABLE",
    "UPSERT_DETECTED",
    "UPSERT_DETECTED_LEGACY",
    "SELECT_FRAMEWORK_PROTECTION",
    "TABLE_EXISTS",
]
