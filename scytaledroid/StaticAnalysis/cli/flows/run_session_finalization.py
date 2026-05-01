"""Session finalization checks for static analysis run dispatch."""

from __future__ import annotations

from ..core.models import RunOutcome
from .run_session_map import _ensure_session_finalization_outputs


def _session_finalization_issues(
    *,
    outcome: RunOutcome | None,
    session_stamp: str | None,
    post_summary: object | None,
    summary_render_failed: bool,
    persistence_ready: bool,
    dry_run: bool = False,
) -> list[str]:
    """Return finalization issues that should fail a persisted run.

    Dry-run intentionally skips persistence, run-map creation, and session-link writes,
    so those missing outputs must not be treated as failures.
    """
    if dry_run:
        return []

    if outcome is None or not session_stamp or summary_render_failed or outcome.aborted or not persistence_ready:
        return []

    if not (outcome.results or []):
        return []

    issues: list[str] = []

    if post_summary is not None and getattr(post_summary, "linkage_blocked_reason", None):
        issues.append("session_linkage_blocked")
        return issues

    issues.extend(_ensure_session_finalization_outputs(session_stamp))
    return issues


__all__ = [
    "_session_finalization_issues",
]