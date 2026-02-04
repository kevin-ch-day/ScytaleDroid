"""Backward-compatible wrapper for the refactored persistence pipeline."""

from __future__ import annotations

from ..persistence.run_summary import (
    PersistenceOutcome,
    persist_run_summary,
    update_static_run_status,
)

__all__ = ["persist_run_summary", "update_static_run_status", "PersistenceOutcome"]