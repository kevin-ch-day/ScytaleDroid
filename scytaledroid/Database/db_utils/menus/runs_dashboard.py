"""Recent runs dashboard for Database Utilities menu."""

from __future__ import annotations

from typing import Any

from scytaledroid.Database.db_core import run_sql
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from .sql_helpers import coerce_datetime, format_session_stamp


def show_recent_runs_dashboard(limit: int = 5) -> None:
    print()
    menu_utils.print_header("Recent Runs Dashboard")
    menu_utils.print_hint(
        "Review recent persisted runs with finding, string, and permission surfaces."
    )

    runs = _fetch_recent_runs(limit)
    if runs is None:
        prompt_utils.press_enter_to_continue()
        return

    if not runs:
        print(status_messages.status("No runs available.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    for run in runs:
        _render_run_entry(run)

    prompt_utils.press_enter_to_continue()


def _fetch_recent_runs(limit: int) -> list[dict[str, Any]] | None:
    try:
        return run_sql(
            """
            SELECT
              sar.id AS static_run_id,
              a.package_name,
              av.version_name,
              av.version_code,
              av.target_sdk AS target_sdk,
              sar.created_at,
              sar.status,
              sar.session_stamp
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            ORDER BY sar.id DESC
            LIMIT %s
            """,
            (limit,),
            fetch="all",
            dictionary=True,
        )
    except Exception as exc:  # pragma: no cover - relies on external DB
        print(status_messages.status(f"Unable to query runs: {exc}", level="error"))
        return None


def _render_run_entry(run: dict[str, Any]) -> None:
    static_run_id = int(run.get("static_run_id") or 0)
    package = run.get("package_name") or "<unknown>"
    version_name = run.get("version_name") or "—"
    target_sdk = run.get("target_sdk")
    ts_value = run.get("created_at")
    ts_dt = coerce_datetime(ts_value)
    session_stamp = run.get("session_stamp") or (format_session_stamp(ts_dt) if ts_dt else None)
    status = run.get("status") or "—"

    header = (
        f"Static #{static_run_id or '—'}"
        + f"  {package}  v{version_name}  target={target_sdk or '—'}"
        + f"  status={status}  {ts_dt or ts_value}"
    )
    menu_utils.print_section(header)

    if session_stamp:
        _render_findings_summary(session_stamp, package)
        _render_string_summary(session_stamp, package)
    else:
        print("  findings: (session stamp unavailable)")
        print("  strings : (session stamp unavailable)")

    _render_permission_snapshot(session_stamp, package)
    print()


def _render_findings_summary(session_stamp: str, package: str) -> None:
    summary_from_view = _fetch_latest_finding_surfaces(package)
    if summary_from_view and summary_from_view.get("session_stamp") == session_stamp:
        print(
            f"  findings: H{summary_from_view.get('canonical_high', 0)}/"
            f"M{summary_from_view.get('canonical_med', 0)}/"
            f"L{summary_from_view.get('canonical_low', 0)}/"
            f"I{summary_from_view.get('canonical_info', 0)}"
        )
        return

    findings = run_sql(
        """
        SELECT
          SUM(CASE WHEN LOWER(COALESCE(f.severity, '')) = 'high' THEN 1 ELSE 0 END) AS high,
          SUM(CASE WHEN LOWER(COALESCE(f.severity, '')) = 'medium' THEN 1 ELSE 0 END) AS med,
          SUM(CASE WHEN LOWER(COALESCE(f.severity, '')) = 'low' THEN 1 ELSE 0 END) AS low,
          SUM(CASE WHEN LOWER(COALESCE(f.severity, '')) = 'info' THEN 1 ELSE 0 END) AS info
        FROM static_analysis_findings f
        JOIN static_analysis_runs sar ON sar.id = f.run_id
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        WHERE sar.session_stamp = %s
          AND a.package_name = %s
        """,
        (session_stamp, package),
        fetch="one",
        dictionary=True,
    )
    if findings:
        print(
            f"  findings: H{findings.get('high', 0)}/M{findings.get('med', 0)}/"
            f"L{findings.get('low', 0)}/I{findings.get('info', 0)}"
        )
    else:
        print("  findings: (no summary)")


def _render_string_summary(session_stamp: str, package: str) -> None:
    strings = run_sql(
        """
        SELECT package_name, endpoints, http_cleartext, high_entropy
        FROM static_string_summary
        WHERE session_stamp = %s AND package_name = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (session_stamp, package),
        fetch="one",
        dictionary=True,
    )
    if strings:
        print(
            "  strings : "
            f"endpoints={strings.get('endpoints', 0)}, "
            f"http={strings.get('http_cleartext', 0)}, "
            f"entropy={strings.get('high_entropy', 0)}"
        )
    else:
        print("  strings : (no summary)")


def _render_permission_snapshot(session_stamp: str | None, package: str) -> None:
    row = _fetch_latest_risk_surfaces(package)
    if row and row.get("session_stamp") == session_stamp:
        print(
            "  perm-audit (latest): "
            f"score={row.get('permission_audit_score_capped')}, "
            f"grade={row.get('permission_audit_grade') or '—'} "
            f"(dangerous={row.get('permission_audit_dangerous_count', 0)}, "
            f"signature={row.get('permission_audit_signature_count', 0)}, "
            f"oem={row.get('permission_audit_vendor_count', 0)})"
        )
        return

    if row:
        print("  perm-audit (latest): (not linked to this session)")
    else:
        print("  perm-audit (latest): (no snapshot)")


def _fetch_latest_finding_surfaces(package: str) -> dict[str, Any] | None:
    try:
        return run_sql(
            """
            SELECT
              package_name,
              session_stamp,
              canonical_high,
              canonical_med,
              canonical_low,
              canonical_info
            FROM vw_static_finding_surfaces_latest
            WHERE package_name = %s
            LIMIT 1
            """,
            (package,),
            fetch="one",
            dictionary=True,
        )
    except Exception:
        return None


def _fetch_latest_risk_surfaces(package: str) -> dict[str, Any] | None:
    try:
        return run_sql(
            """
            SELECT
              package_name,
              session_stamp,
              permission_audit_grade,
              permission_audit_score_capped,
              permission_audit_dangerous_count,
              permission_audit_signature_count,
              permission_audit_vendor_count
            FROM vw_static_risk_surfaces_latest
            WHERE package_name = %s
            LIMIT 1
            """,
            (package,),
            fetch="one",
            dictionary=True,
        )
    except Exception:
        return None


__all__ = ["show_recent_runs_dashboard"]
