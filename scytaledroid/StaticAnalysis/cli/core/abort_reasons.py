"""Controlled abort reason taxonomy for static analysis runs."""

from __future__ import annotations

from scytaledroid.Database.db_core import db_engine

ABORT_REASONS = {
    "stale_finalize",
    "persist_error",
    "enumeration_error",
    "artifact_missing",
    "adb_error",
    "user_abort",
    "config_error",
}

_ALIASES = {
    "sigint": "user_abort",
    "keyboardinterrupt": "user_abort",
    "missing_report": "artifact_missing",
    "missing_artifact": "artifact_missing",
    "artifact_missing": "artifact_missing",
    "persist_error": "persist_error",
}


def normalize_abort_reason(reason: str | None) -> str | None:
    if not reason:
        return None
    token = str(reason).strip()
    if not token:
        return None
    key = token.lower()
    mapped = _ALIASES.get(key)
    if mapped:
        return mapped
    if key in ABORT_REASONS:
        return key
    return "persist_error"


def classify_exception(exc: Exception) -> str:
    if isinstance(exc, (KeyboardInterrupt, SystemExit)):
        return "user_abort"
    if isinstance(
        exc,
        (
            db_engine.TransientDbError,
            db_engine.IntegrityDbError,
            db_engine.DatabaseError,
        ),
    ):
        return "persist_error"
    if isinstance(exc, FileNotFoundError):
        return "artifact_missing"
    return "enumeration_error"


__all__ = ["ABORT_REASONS", "normalize_abort_reason", "classify_exception"]