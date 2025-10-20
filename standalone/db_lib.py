"""Standalone helpers for preparing canonical database plumbing."""

from __future__ import annotations

from typing import Optional

from scytaledroid.StaticAnalysis.persistence import ingest as canonical_ingest


def ensure_provider_plumbing() -> bool:
    """Ensure canonical tables/views exist for provider analytics."""

    return canonical_ingest.ensure_provider_plumbing()


def upsert_base002_for_session(session_stamp: Optional[str]) -> int:
    """Promote provider exposure candidates into canonical findings."""

    return canonical_ingest.upsert_base002_for_session(session_stamp)


def build_session_string_view(session_stamp: Optional[str]) -> int:
    """Materialise the session-scoped string sample view."""

    return canonical_ingest.build_session_string_view(session_stamp)


__all__ = [
    "ensure_provider_plumbing",
    "upsert_base002_for_session",
    "build_session_string_view",
]
