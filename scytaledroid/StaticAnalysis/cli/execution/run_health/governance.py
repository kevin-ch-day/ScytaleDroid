"""Session governance / persistence labels for run_health JSON."""

from __future__ import annotations

from ...core.models import RunOutcome, RunParameters


def infer_session_governance_snapshot(params: RunParameters) -> dict[str, object]:
    """Best-effort paper-grade vs experimental labeling (same resolver as finalize/doctor)."""

    grade = "experimental"
    reason: str | None = None
    if not getattr(params, "paper_grade_requested", True):
        reason = "canonical_grade_off"
        return {"governance_grade": grade, "governance_reason": reason}
    try:
        from scytaledroid.Database.db_core import permission_intel as intel_db
        from scytaledroid.StaticAnalysis.cli.execution.pipeline import governance_ready

        if not intel_db.is_permission_intel_configured():
            reason = "missing_permission_intel"
            return {"governance_grade": grade, "governance_reason": reason}
        ok, detail = governance_ready()
        if ok:
            return {"governance_grade": "paper_grade", "governance_reason": "ok"}
        reason = str(detail or "governance_check_failed")
        return {"governance_grade": grade, "governance_reason": reason}
    except Exception as exc:
        return {"governance_grade": grade, "governance_reason": f"query_failed:{exc}"}


def _session_db_persistence_label(
    outcome: RunOutcome,
    *,
    persistence_enabled: bool,
    persist_attempted: bool,
    params: RunParameters,
) -> str:
    if not persistence_enabled or not getattr(params, "persistence_ready", True):
        return "skipped"
    if not persist_attempted:
        return "skipped"
    if outcome.persistence_failed:
        return "failed"
    if any(
        getattr(app, "persistence_failure_stage", None) or getattr(app, "persistence_exception_class", None)
        for app in outcome.results
    ):
        return "partial"
    return "ok"


def _session_detector_pipeline_status(detector_errors_total: int, warn_total: int, fail_total: int) -> str:
    """Roll up detector *pipeline* stages for session status lines.

    ``detector_errors_total`` counts execution/traceback-style detector errors.
    ``fail_total`` counts policy/gate **fail** stages (not the same as execution errors).
    """

    if detector_errors_total > 0:
        if fail_total > 0 or warn_total > 0:
            return "execution_errors_with_pipeline_issues"
        return "execution_errors"
    if fail_total > 0:
        if warn_total > 0:
            return "warnings_and_policy_failures"
        return "policy_failures"
    if warn_total > 0:
        return "warnings"
    return "ok"


# Back-compat for imports; prefer `_session_detector_pipeline_status`.
_session_detector_status_label = _session_detector_pipeline_status
