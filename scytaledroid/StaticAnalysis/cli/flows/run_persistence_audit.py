"""Persistence audit summary helpers for static analysis run dispatch."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_utils import diagnostics as db_diagnostics
from scytaledroid.Database.db_utils.static_session_grain_integrity import (
    count_json_files_in_dir,
    reports_archive_dir,
)

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
    session_label: str,
    expected_packages: list[str],
    outcome: RunOutcome,
    report_paths: list[str],
) -> dict[str, object]:
    """Build the default audit summary shape before DB reconciliation."""
    latest_report_paths = [path for path in report_paths if "/latest/" in path]
    archive_report_paths = [path for path in report_paths if "/archive/" in path]
    archive_dir = reports_archive_dir(session_stamp=session_label, data_dir=app_config.DATA_DIR)
    archive_fs_count = count_json_files_in_dir(archive_dir)

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
            "recorded_archive_json_paths": len(archive_report_paths),
            "archive_json_paths": archive_fs_count,
            "archive_present": bool(archive_fs_count),
            "archive_dir": str(archive_dir),
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
    result_count = len(getattr(outcome, "results", []) or [])
    if result_count <= 0:
        try:
            result_count = max(int(summary.get("expected_packages") or 0), 0)
        except Exception:
            result_count = 0
    if result_count <= 0:
        return

    canonical = _summary_section(summary, "canonical")
    canonical["run_statuses"] = {status: result_count}
    summary["canonical"] = canonical


def _build_persistence_audit_summary(
    *,
    outcome: RunOutcome,
    session_label: str,
) -> dict[str, object]:
    """Summarize canonical, bridge, and report coverage for persistence audits."""
    expected_packages = _expected_packages(outcome)
    report_paths = _collect_report_paths(outcome)
    summary = _empty_audit_summary(
        session_label=session_label,
        expected_packages=expected_packages,
        outcome=outcome,
        report_paths=report_paths,
    )

    _apply_reconcile_summary(summary, session_label)

    if not _has_run_statuses(summary):
        _apply_direct_summary_fallback(summary, session_label)

    if not _has_run_statuses(summary):
        _apply_outcome_status_fallback(summary, outcome)

    return summary


def _int_or_zero(value: object) -> int:
    try:
        return max(int(value or 0), 0)
    except Exception:
        return 0


def _existing_payload_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = payload.get("rows")
    if not isinstance(rows, list):
        return []
    return [dict(row) for row in rows if isinstance(row, dict)]


def _existing_payload_expected_packages(payload: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(row.get("package_name") or "").strip().lower()
            for row in _existing_payload_rows(payload)
            if str(row.get("package_name") or "").strip()
        }
    )


def _existing_payload_report_paths(payload: dict[str, Any]) -> list[str]:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    reports = summary.get("reports") if isinstance(summary.get("reports"), dict) else {}
    rows = _existing_payload_rows(payload)

    total = _int_or_zero(reports.get("json_report_paths"))
    if total <= 0:
        total = sum(_int_or_zero(row.get("artifact_reports")) for row in rows)

    latest = _int_or_zero(reports.get("latest_json_paths"))
    archive = _int_or_zero(reports.get("recorded_archive_json_paths"))
    if latest <= 0 and total > 0 and archive == 0:
        latest = total
    if latest + archive > total:
        overflow = latest + archive - total
        if archive >= overflow:
            archive -= overflow
        else:
            latest = max(latest - (overflow - archive), 0)
            archive = 0
    other = max(total - latest - archive, 0)

    return (
        [f"/latest/rebuilt-{idx}.json" for idx in range(latest)]
        + [f"/archive/rebuilt-{idx}.json" for idx in range(archive)]
        + [f"/other/rebuilt-{idx}.json" for idx in range(other)]
    )


def refresh_existing_persistence_audit_payload(
    payload: dict[str, Any],
    *,
    session_label: str | None = None,
) -> dict[str, Any]:
    """Refresh an existing persistence audit summary from DB + filesystem truth.

    Historical artifacts do not store every artifact path, so this routine preserves
    the recorded path totals when present and recomputes canonical/bridge/archive
    sections using live DB reconciliation plus the archive filesystem count.
    """

    stamp = str(session_label or payload.get("session_stamp") or "").strip()
    if not stamp:
        raise ValueError("session_stamp is required to refresh a persistence audit payload")

    outcome_payload = payload.get("outcome") if isinstance(payload.get("outcome"), dict) else {}
    synthetic_outcome = SimpleNamespace(
        canonical_failed=bool(outcome_payload.get("canonical_failed", False)),
        persistence_failed=bool(outcome_payload.get("persistence_failed", False)),
        compat_export_failed=bool(outcome_payload.get("compat_export_failed", False)),
        compat_export_stage=outcome_payload.get("compat_export_stage"),
    )
    refreshed_summary = _empty_audit_summary(
        session_label=stamp,
        expected_packages=_existing_payload_expected_packages(payload),
        outcome=synthetic_outcome,
        report_paths=_existing_payload_report_paths(payload),
    )

    try:
        _apply_reconcile_summary(refreshed_summary, stamp)
    except Exception as exc:
        refreshed_summary["reconciliation_error"] = str(exc)

    if not _has_run_statuses(refreshed_summary):
        _apply_direct_summary_fallback(refreshed_summary, stamp)

    if not _has_run_statuses(refreshed_summary):
        _apply_outcome_status_fallback(refreshed_summary, synthetic_outcome)

    updated = dict(payload)
    updated["summary"] = refreshed_summary
    updated["summary_refreshed_at_utc"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    updated["summary_refresh_source"] = "db_and_filesystem_rebuild"
    return updated


def refresh_persistence_audit_artifact(
    path: str | Path,
    *,
    write: bool = True,
) -> dict[str, Any]:
    """Refresh a persisted audit artifact in-place, preserving row-level detail."""

    artifact_path = Path(path)
    payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    refreshed = refresh_existing_persistence_audit_payload(payload)
    if write:
        artifact_path.write_text(json.dumps(refreshed, indent=2, sort_keys=True), encoding="utf-8")
    return refreshed


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
            session_label=stamp,
        ),
        lock_health_snapshot=db_diagnostics.get_lock_health_snapshot,
        output_dir="output",
    )


__all__ = [
    "_build_persistence_audit_summary",
    "_emit_missing_run_ids_artifact",
    "refresh_existing_persistence_audit_payload",
    "refresh_persistence_audit_artifact",
]
