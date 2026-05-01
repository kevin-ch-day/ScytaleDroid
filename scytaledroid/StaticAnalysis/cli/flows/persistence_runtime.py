"""Helpers for optional static-analysis persistence bootstrap and refresh."""

from __future__ import annotations

from scytaledroid.StaticAnalysis.persistence import ingest as canonical_ingest
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def persistence_enabled(*, dry_run: bool, persistence_ready: bool) -> bool:
    """Return True when DB-backed persistence work should run for this scan."""

    return not dry_run and bool(persistence_ready)


def bootstrap_runtime_persistence(
    *,
    session_stamp: str | None,
    dry_run: bool,
    persistence_ready: bool,
    strict_persistence: bool,
) -> None:
    """Prepare optional canonical persistence runtime state for a static run."""

    if not persistence_enabled(dry_run=dry_run, persistence_ready=persistence_ready):
        return
    try:
        canonical_ingest.ensure_provider_plumbing()
        if session_stamp:
            canonical_ingest.build_session_string_view(session_stamp)
    except Exception as exc:
        if strict_persistence:
            raise RuntimeError(f"Static analysis setup failed: {exc}") from exc
        log.warning(f"Static analysis setup warning: {exc}", category="static")
        print(status_messages.status(f"Static analysis setup warning: {exc}", level="warn"))


def refresh_session_views(
    *,
    session_stamp: str | None,
    dry_run: bool,
    persistence_ready: bool,
) -> None:
    """Refresh derived canonical session views after a completed persisted run."""

    if not session_stamp or not persistence_enabled(dry_run=dry_run, persistence_ready=persistence_ready):
        return
    canonical_ingest.upsert_base002_for_session(session_stamp)
    canonical_ingest.build_session_string_view(session_stamp)


__all__ = [
    "bootstrap_runtime_persistence",
    "persistence_enabled",
    "refresh_session_views",
]
