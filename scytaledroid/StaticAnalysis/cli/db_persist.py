"""Backward-compatible wrapper for the refactored persistence pipeline."""

from __future__ import annotations

from .persistence.run_summary import PersistenceOutcome, persist_run_summary

__all__ = ["persist_run_summary", "PersistenceOutcome"]
