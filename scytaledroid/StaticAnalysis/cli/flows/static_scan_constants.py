"""Heartbeat / RUN_PHASE labels for static scan launch (single source of truth)."""

from __future__ import annotations

PHASE_ABORTING = "aborting"
PHASE_SCAN = "scan"
PHASE_PERSIST_SUMMARY = "persist_summary"
PHASE_POSTPROCESS = "postprocess"
PHASE_RUNTIME_EXCEPTION = "runtime_exception"
PHASE_REFRESH_VIEWS = "refresh_views"
PHASE_COMPLETED = "completed"
PHASE_FAILED = "failed"

__all__ = [
    "PHASE_ABORTING",
    "PHASE_COMPLETED",
    "PHASE_FAILED",
    "PHASE_PERSIST_SUMMARY",
    "PHASE_POSTPROCESS",
    "PHASE_REFRESH_VIEWS",
    "PHASE_RUNTIME_EXCEPTION",
    "PHASE_SCAN",
]
