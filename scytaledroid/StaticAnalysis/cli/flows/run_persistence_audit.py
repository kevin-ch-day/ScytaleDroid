"""Persistence audit summary helpers for static analysis run dispatch."""

from __future__ import annotations

from scytaledroid.Database.db_utils import diagnostics as db_diagnostics

from ..core.models import RunOutcome
from .run_persistence_queries import (
    _apply_direct_summary_fallback,
    _apply_reconcile_summary,
    _summary_section,
)
from .session_finalizer import emit_persistence_audit_artifact


def _expected_packages(outcome: RunOutcome) -> list[str]:
    """Return normalized package names expected in the persistence audit."""
    return sorted(
        {
            str(getattr(app, "package_name", "") or "").strip().lower()
            for app in outcome.results
            if str(getattr(app, "package_name", "") or "").strip()
        }
    )


def _collect_report_paths(outcome: RunOutcome) -> list[str]:
    """Return persisted JSON report paths recorded on artifact outcomes."""
    return sorted(
        {
            str(artifact.saved_path)
            for app in outcome.results
            for artifact in getattr(app, "artifacts", []) or []
            if getattr(artifact, "saved_path", None)
        }
    )


def _empty_audit_summary(
    *,
    expected_packages: list[str],
    outcome: RunOutcome,
    report_paths: list[str],
) -> dict[str, object]:
    """Build the default audit summary shape before DB reconciliation."""
    latest_report_paths = [path for path in report_paths if "/latest/" in path]
    archive_report_paths = [path for path in report_paths if "/archive/" in path]

    return {
        "expected_packages": len(expected_packages),
        "outcome": {
            "canonical_failed": bool(getattr(outcome, "canonical_failed", False)),
            "persistence_failed": bool(getattr(outcome, "persistence_failed", False)),
            "compat_export_failed": bool(getattr(outcome, "compat_export_failed", False)),
            "compat_export_stage": getattr(outcome, "compat_export_stage", None),
        },
        "canonical": {
            "run_statuses": {},
            "baseline_runs": 0,
            "handoff_paths": 0,
            "findings": 0,
            "permission_matrix": 0,
            "permission_risk": 0,
            "findings_summary_packages": 0,
            "string_summary_packages": 0,
        },
        "bridge": {
            "runs": 0,
            "risk_scores": 0,
            "secondary_compat_mirror_packages": 0,
            "metrics_packages": 0,
            "buckets_packages": 0,
            "contributors_packages": 0,
            "session_links": 0,
            "session_rollups": 0,
        },
        "reconciliation": {
            "missing_findings_summary_packages": [],
            "missing_findings_summary_count": 0,
            "missing_string_summary_packages": [],
            "missing_string_summary_count": 0,
            "missing_legacy_runs_packages": [],
            "missing_legacy_runs_count": 0,
            "missing_legacy_risk_packages": [],
            "missing_legacy_risk_count": 0,
            "missing_secondary_compat_mirror_count": 0,
            "bridge_only_runs_packages": [],
            "bridge_only_runs_count": 0,
            "bridge_only_risk_packages": [],
            "bridge_only_risk_count": 0,
        },
        "reports": {
            "json_report_paths": len(report_paths),
            "latest_json_paths": len(latest_report_paths),
            "archive_json_paths": len(archive_report_paths),
            "archive_present": bool(archive_report_paths),
        },
    }


def _has_run_statuses(summary: dict[str, object]) -> bool:
    """Return true when the audit summary already has canonical run statuses."""
    canonical = _summary_section(summary, "canonical")
    run_statuses = canonical.get("run_statuses")
    return bool(run_statuses)


def _apply_outcome_status_fallback(summary: dict[str, object], outcome: RunOutcome) -> None:
    """Use in-memory run outcome status when DB summaries are unavailable."""
    failures = list(getattr(outcome, "failures", []) or [])
    errors = list(getattr(outcome, "errors", []) or [])
    status = "FAILED" if failures or errors or bool(getattr(outcome, "canonical_failed", False)) else "COMPLETED"

    canonical = _summary_section(summary, "canonical")
    canonical["run_statuses"] = {status: len(outcome.results)}
    summary["canonical"] = canonical


def _build_persistence_audit_summary(
    *,
    outcome: RunOutcome,
    session_stamp: str,
) -> dict[str, object]:
    """Summarize canonical, bridge, and report coverage for persistence audits."""
    expected_packages = _expected_packages(outcome)
    report_paths = _collect_report_paths(outcome)
    summary = _empty_audit_summary(
        expected_packages=expected_packages,
        outcome=outcome,
        report_paths=report_paths,
    )

    _apply_reconcile_summary(summary, session_stamp)

    if not _has_run_statuses(summary):
        _apply_direct_summary_fallback(summary, session_stamp)

    if not _has_run_statuses(summary):
        _apply_outcome_status_fallback(summary, outcome)

    return summary


def _emit_missing_run_ids_artifact(
    *,
    outcome: RunOutcome,
    session_stamp: str | None,
    linkage_blocked_reason: str | None,
    missing_id_packages: list[str],
) -> None:
    emit_persistence_audit_artifact(
        outcome=outcome,
        session_stamp=session_stamp,
        linkage_blocked_reason=linkage_blocked_reason,
        missing_id_packages=missing_id_packages,
        db_schema_version=db_diagnostics.get_schema_version() or "<unknown>",
        build_summary=lambda current_outcome, stamp: _build_persistence_audit_summary(
            outcome=current_outcome,
            session_stamp=stamp,
        ),
        lock_health_snapshot=db_diagnostics.get_lock_health_snapshot,
        output_dir="output",
    )


__all__ = [
    "_build_persistence_audit_summary",
    "_emit_missing_run_ids_artifact",
]