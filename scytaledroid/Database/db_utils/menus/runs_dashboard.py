"""Recent runs dashboard for Database Utilities menu."""

from __future__ import annotations

from typing import Any, Dict, Optional

from scytaledroid.Database.db_core import run_sql
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from .sql_helpers import coerce_datetime, format_session_stamp


def show_recent_runs_dashboard(limit: int = 5) -> None:
    print()
    menu_utils.print_header("Recent Runs Dashboard")

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


def _fetch_recent_runs(limit: int) -> Optional[list[Dict[str, Any]]]:
    try:
        return run_sql(
            "SELECT run_id, package, version_name, version_code, target_sdk, ts, session_stamp FROM runs ORDER BY run_id DESC LIMIT %s",
            (limit,),
            fetch="all",
            dictionary=True,
        )
    except Exception as exc:  # pragma: no cover - relies on external DB
        print(status_messages.status(f"Unable to query runs: {exc}", level="error"))
        return None


def _render_run_entry(run: Dict[str, Any]) -> None:
    run_id = int(run.get("run_id") or 0)
    package = run.get("package") or "<unknown>"
    version_name = run.get("version_name") or "—"
    target_sdk = run.get("target_sdk")
    ts_value = run.get("ts")
    ts_dt = coerce_datetime(ts_value)
    session_stamp = run.get("session_stamp") or (format_session_stamp(ts_dt) if ts_dt else None)

    header = (
        f"Run #{run_id}  {package}  v{version_name}  "
        f"target={target_sdk or '—'}  {ts_dt or ts_value}"
    )
    print(header)

    total_points = run.get("total_points")
    total_cap = run.get("total_cap")
    if total_points is not None and total_cap is not None:
        print(f"  total points: {total_points}/{total_cap}")

    buckets = run_sql(
        "SELECT bucket, points, cap FROM buckets WHERE run_id = %s ORDER BY bucket",
        (run_id,),
        fetch="all",
        dictionary=True,
    ) or []
    if buckets:
        bucket_detail = ", ".join(
            f"{row['bucket']}:{row['points']}" for row in buckets
        )
        print(f"  buckets: {bucket_detail}")
    else:
        print("  buckets: (none)")

    if session_stamp:
        _render_findings_summary(session_stamp, package)
        _render_string_summary(session_stamp, package)
    else:
        print("  findings: (session stamp unavailable)")
        print("  strings : (session stamp unavailable)")

    _render_permission_snapshot(package)
    print()


def _render_findings_summary(session_stamp: str, package: str) -> None:
    findings = run_sql(
        """
        SELECT package_name, high, med, low, info
        FROM static_findings_summary
        WHERE session_stamp = %s AND package_name = %s
        ORDER BY created_at DESC
        LIMIT 1
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


def _render_permission_snapshot(package: str) -> None:
    row = run_sql(
        """
        SELECT score_capped, grade, dangerous_count, signature_count, vendor_count
        FROM permission_audit_apps
        WHERE package_name = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (package,),
        fetch="one",
        dictionary=True,
    )
    if row:
        print(
            "  perm-audit (latest): "
            f"score={row.get('score_capped')}, "
            f"grade={row.get('grade') or '—'} "
            f"(dangerous={row.get('dangerous_count', 0)}, "
            f"signature={row.get('signature_count', 0)}, "
            f"oem={row.get('vendor_count', 0)})"
        )
    else:
        print("  perm-audit (latest): (no snapshot)")


__all__ = ["show_recent_runs_dashboard"]
