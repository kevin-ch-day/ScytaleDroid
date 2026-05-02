"""Per-app and session aggregate final-status computation."""

from __future__ import annotations

from collections import Counter

from ...core.models import AppRunResult, RunOutcome
from .constants import FINAL_STATUSES
from .signals import string_summary_signals


def compute_app_final_status(
    app_result: AppRunResult,
    *,
    persistence_enabled: bool,
    persist_attempted_this_run: bool,
) -> str:
    """Return ``complete`` / ``partial`` / ``failed`` / ``skipped`` for one app.

    V1 heuristic (scan-phase; persistence reconciliation may downgrade in
    ``reconcile_app_final_status_after_persistence``):

    - **skipped**: harvest / policy excluded before substantive scan (exploratory-only gate).
    - **failed**: nothing useful was produced despite expecting artifacts.
    - **complete**: expected artifacts yielded reports; no detector errors/policy fails;
      no WARN outcomes; persistence did not fault (when persistence is enabled).
    - **partial**: at least one report exists but some gaps, warnings, or fallbacks occurred.
    """
    exploratory = bool(getattr(app_result, "exploratory_only", False))
    disc = int(getattr(app_result, "discovered_artifacts", 0) or 0)
    success_n = len(getattr(app_result, "artifacts", []) or ())
    failed_n = int(getattr(app_result, "failed_artifacts", 0) or 0)

    if exploratory and disc == 0 and success_n == 0:
        return "skipped"

    if disc == 0:
        return "failed"

    if success_n == 0:
        return "failed"

    from ..scan_report import _summarize_app_pipeline

    summary = _summarize_app_pipeline(app_result)

    errs = int(summary.get("error_count", 0) or 0)
    fails = int(summary.get("fail_count", 0) or 0)
    warns = int(summary.get("warn_count", 0) or 0)

    persisted_db_issue = False
    if persistence_enabled and persist_attempted_this_run:
        persisted_db_issue = bool(
            getattr(app_result, "persistence_failure_stage", None)
            or getattr(app_result, "persistence_exception_class", None)
        )

    str_sig = string_summary_signals(
        getattr(app_result, "base_string_data", None),
        discovered_artifacts=disc,
    )
    str_status = str(str_sig.get("string_summary_status") or "ok")

    parse_events = int(summary.get("parse_fallback_events_est", 0) or 0)

    strict_scan_ok = (
        failed_n == 0
        and success_n == disc
        and errs == 0
        and fails == 0
        and warns == 0
        and parse_events == 0
        and str_status == "ok"
        and not persisted_db_issue
    )

    if strict_scan_ok:
        return "complete"

    # Any successful report counts as partial rather than outright failed unless everything blew up.
    if success_n >= 1:
        return "partial"

    return "failed"


def reconcile_app_final_status_after_persistence(app_result: AppRunResult, *, persistence_enabled: bool) -> None:
    """Adjust ``final_status`` after DB persistence failures (caller sets phase)."""
    current = getattr(app_result, "final_status", None)
    if current not in FINAL_STATUSES:
        return
    if current in {"failed", "skipped"}:
        return
    if not persistence_enabled:
        return
    if getattr(app_result, "persistence_failure_stage", None) or getattr(app_result, "persistence_exception_class", None):
        if current == "complete":
            app_result.final_status = "partial"


def compute_run_aggregate_status(outcome: RunOutcome) -> str:
    statuses = [
        getattr(r, "final_status", None) for r in outcome.results if getattr(r, "final_status", None)
    ]
    if not statuses:
        if outcome.aborted:
            return "failed"
        return "failed"

    if outcome.aborted:
        # Surface operator-visible aborted runs as failed at session scope.
        if any(s == "complete" for s in statuses):
            return "partial"
        return "failed"

    ctr = Counter(str(s) for s in statuses)
    if ctr["failed"] == len(statuses):
        return "failed"
    if ctr["skipped"] == len(statuses):
        return "skipped"
    if ctr["complete"] == len(statuses):
        return "complete"
    return "partial"
