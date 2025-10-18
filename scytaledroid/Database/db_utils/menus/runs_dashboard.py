"""Recent runs dashboard for Database Utilities menu."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from scytaledroid.Database.db_core import run_sql
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def show_recent_runs_dashboard(limit: int = 5) -> None:
    print()
    menu_utils.print_header("Recent Runs Dashboard")

    try:
        runs = run_sql(
            "SELECT run_id, package, version_name, target_sdk, ts FROM runs ORDER BY run_id DESC LIMIT %s",
            (limit,),
            fetch="all",
            dictionary=True,
        )
    except Exception as exc:
        print(status_messages.status(f"Unable to query runs: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    if not runs:
        print(status_messages.status("No runs available.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    for run in runs:
        _render_run_entry(run)

    prompt_utils.press_enter_to_continue()


def _render_run_entry(run: Dict[str, Any]) -> None:
    run_id = int(run.get("run_id") or 0)
    package = run.get("package") or "<unknown>"
    version_name = run.get("version_name") or "—"
    target_sdk = run.get("target_sdk")
    ts_value = run.get("ts")
    ts_dt = _coerce_datetime(ts_value)
    session_stamp = _format_session_stamp(ts_dt) if ts_dt else None

    header_line = f"Run #{run_id}  {package}  v{version_name}  target={target_sdk or '—'}  {ts_dt or ts_value}"
    print(header_line)

    bucket_rows = run_sql(
        "SELECT bucket, points FROM buckets WHERE run_id = %s ORDER BY bucket",
        (run_id,),
        fetch="all",
        dictionary=True,
    ) or []
    if bucket_rows:
        bucket_detail = ", ".join(f"{row['bucket']}:{row['points']}" for row in bucket_rows)
        print(f"  buckets: {bucket_detail}")
    else:
        print("  buckets: (none)")

    if session_stamp:
        _render_findings_summary(package, session_stamp)
        _render_string_summary(package, session_stamp)
    else:
        print("  findings: (session_stamp unavailable)")
        print("  strings : (session_stamp unavailable)")

    _render_permission_snapshot(package)
    print()


def _render_findings_summary(package: str, session_stamp: str) -> None:
    findings = run_sql(
        """
        SELECT high, med, low, info
        FROM static_findings_summary
        WHERE package_name = %s AND session_stamp = %s
        LIMIT 1
        """,
        (package, session_stamp),
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


def _render_string_summary(package: str, session_stamp: str) -> None:
    strings = run_sql(
        """
        SELECT endpoints, http_cleartext, high_entropy
        FROM static_string_summary
        WHERE package_name = %s AND session_stamp = %s
        LIMIT 1
        """,
        (package, session_stamp),
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
    permission_row = run_sql(
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
    if permission_row:
        print(
            "  perm-audit (latest): "
            f"score={permission_row.get('score_capped')}, "
            f"grade={permission_row.get('grade') or '—'} "
            f"(dangerous={permission_row.get('dangerous_count', 0)}, "
            f"signature={permission_row.get('signature_count', 0)}, "
            f"vendor={permission_row.get('vendor_count', 0)})"
        )
    else:
        print("  perm-audit (latest): (no snapshot)")


def _coerce_datetime(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return None
        try:
            return datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except Exception:
            try:
                return datetime.strptime(candidate, "%Y-%m-%d %H:%M:%S")
            except Exception:
                return None
    return None


def _format_session_stamp(ts: datetime) -> str:
    return ts.strftime("%Y%m%d-%H%M%S")


__all__ = ["show_recent_runs_dashboard"]
