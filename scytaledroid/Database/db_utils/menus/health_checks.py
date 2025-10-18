"""Data health checks for Database Utilities menu."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from scytaledroid.Database.db_core import run_sql
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def run_health_checks() -> None:
    print()
    menu_utils.print_header("Data Health Checks")

    latest_run = _fetch_latest_run()
    if latest_run is None:
        prompt_utils.press_enter_to_continue()
        return

    run_id = int(latest_run.get("run_id") or 0)
    package = str(latest_run.get("package") or "<unknown>")
    ts_value = latest_run.get("ts")
    ts_dt = _coerce_datetime(ts_value)
    session_stamp = _format_session_stamp(ts_dt) if ts_dt else None

    print(f"Ingestion — latest run (run_id={run_id}, pkg={package}, ts={ts_dt or ts_value})")
    _print_status_line("ok", "runs")

    buckets_count = _scalar("SELECT COUNT(*) FROM buckets WHERE run_id=%s", (run_id,))
    _print_status_line("ok" if buckets_count else "fail", "buckets", detail=str(buckets_count or 0))

    if session_stamp:
        findings_count = _scalar(
            "SELECT COUNT(*) FROM static_findings_summary WHERE session_stamp = %s AND package_name = %s",
            (session_stamp, package),
        )
        findings_detail = _fetch_findings_detail(session_stamp, package)
        _print_status_line(
            "ok" if findings_count else "fail",
            "static_findings_summary",
            detail=findings_detail or str(findings_count or 0),
        )

        strings_detail = _fetch_string_summary_detail(session_stamp, package)
        strings_count = 1 if strings_detail else _scalar(
            "SELECT COUNT(*) FROM static_string_summary WHERE session_stamp = %s AND package_name = %s",
            (session_stamp, package),
        )
        _print_status_line(
            "ok" if strings_detail or strings_count else "fail",
            "static_string_summary",
            detail=strings_detail or str(strings_count or 0),
        )

        provider_count = _scalar(
            "SELECT COUNT(*) FROM static_provider_acl WHERE session_stamp = %s AND package_name = %s",
            (session_stamp, package),
        )
        _print_status_line("ok" if provider_count else "warn", "static_provider_acl", detail=str(provider_count or 0))
    else:
        _print_status_line("warn", "session_stamp", detail="unable to derive from runs.ts")

    metrics_rows = _fetch_metrics_summary(run_id)
    if metrics_rows:
        detail = ", ".join(f"{row['feature_key']}={row['value_num']}" for row in metrics_rows)
        _print_status_line("ok", "metrics", detail=detail)
    else:
        _print_status_line("warn", "metrics", detail="expected keys not present")

    print()
    print("Scoring & coverage")
    _render_scoring_checks()

    print()
    print("Integrity")
    _render_integrity_checks()

    prompt_utils.press_enter_to_continue()


def _fetch_latest_run() -> Optional[Dict[str, Any]]:
    try:
        return run_sql(
            "SELECT run_id, package, version_name, target_sdk, ts FROM runs ORDER BY run_id DESC LIMIT 1",
            fetch="one",
            dictionary=True,
        )
    except Exception as exc:
        print(status_messages.status(f"Unable to query runs table: {exc}", level="error"))
        return None


def _render_scoring_checks() -> None:
    try:
        rows = run_sql(
            """
            SELECT s.snapshot_id, s.apps_total, COUNT(a.audit_id) AS actual
            FROM permission_audit_snapshots s
            LEFT JOIN permission_audit_apps a ON a.snapshot_id = s.snapshot_id
            GROUP BY s.snapshot_id, s.apps_total
            ORDER BY s.snapshot_id DESC
            LIMIT 3
            """,
            fetch="all",
            dictionary=True,
        )
    except Exception as exc:
        print(status_messages.status(f"Unable to query permission_audit tables: {exc}", level="error"))
        return

    if rows:
        snapshot = rows[0]
        snapshot_id = snapshot.get("snapshot_id")
        actual = int(snapshot.get("actual") or 0)
        expected = int(snapshot.get("apps_total") or 0)
        level = "ok" if expected == actual else "warn"
        detail = f"{snapshot_id}: expected {expected}, actual {actual}"
        _print_status_line(level, "permission_audit_snapshots ↔ permission_audit_apps", detail=detail)
    else:
        _print_status_line("warn", "permission audit", detail="no snapshots recorded yet")

    latest_snapshot_id = _scalar("SELECT MAX(snapshot_id) FROM permission_audit_snapshots")
    if latest_snapshot_id:
        grade_rows = run_sql(
            """
            SELECT grade, COUNT(*) AS cnt
            FROM permission_audit_apps
            WHERE snapshot_id = %s
            GROUP BY grade
            ORDER BY grade
            """,
            (latest_snapshot_id,),
            fetch="all",
            dictionary=True,
        ) or []
        if grade_rows:
            detail = ", ".join(f"{row.get('grade') or '∅'}:{row.get('cnt')}" for row in grade_rows)
            _print_status_line("ok", "grade distribution", detail=detail)
        else:
            _print_status_line("warn", "grade distribution", detail="no apps linked to latest snapshot")
    else:
        _print_status_line("warn", "grade distribution", detail="no snapshots available")

    optional_tables = {
        "contributors": "planned; wire scoring contributors",
        "correlations": "planned; wire correlation engine",
        "risk_scores": "optional per-run rollup",
        "static_permission_risk": "optional per-apk permission rollup",
    }
    for table, hint in optional_tables.items():
        count = _scalar(f"SELECT COUNT(*) FROM {table}")
        level = "ok" if count else "warn"
        detail = f"{count or 0} rows"
        if not count:
            detail += f" — {hint}"
        _print_status_line(level, table, detail=detail)


def _render_integrity_checks() -> None:
    try:
        rows = run_sql(
            """
            SELECT v.package_name, s.id AS summary_id
            FROM vw_latest_apk_per_package v
            LEFT JOIN static_findings_summary s ON s.package_name = v.package_name
            ORDER BY v.updated_at DESC
            LIMIT 10
            """,
            fetch="all",
            dictionary=True,
        )
        view_available = True
    except Exception:
        rows = []
        view_available = False

    if view_available:
        missing = [row["package_name"] for row in rows if not row.get("summary_id")]
        if missing:
            _print_status_line("warn", "latest APK ↔ summary", detail=f"missing summaries for {', '.join(missing)}")
        else:
            _print_status_line("ok", "latest APK ↔ summary", detail=f"{len(rows)} packages checked")
    else:
        _print_status_line("warn", "latest APK ↔ summary", detail="vw_latest_apk_per_package view unavailable")

    sample_rows = run_sql(
        """
        SELECT s.id AS summary_id, COUNT(x.id) AS samples
        FROM static_findings_summary s
        LEFT JOIN static_string_samples x ON x.summary_id = s.id
        GROUP BY s.id
        ORDER BY s.created_at DESC
        LIMIT 5
        """,
        fetch="all",
        dictionary=True,
    ) or []
    if sample_rows:
        zero_samples = [row["summary_id"] for row in sample_rows if not row.get("samples")]
        if zero_samples:
            _print_status_line("warn", "summary ↔ string samples", detail=f"missing samples for ids {', '.join(map(str, zero_samples))}")
        else:
            _print_status_line("ok", "summary ↔ string samples", detail=f"{len(sample_rows)} summaries inspected")
    else:
        _print_status_line("warn", "summary ↔ string samples", detail="no summaries found")


def _scalar(query: str, params: Sequence[Any] | None = None) -> Optional[int]:
    try:
        row = run_sql(query, params, fetch="one")
    except Exception:
        return None
    if not row:
        return None
    return int(row[0]) if row[0] is not None else None


def _fetch_findings_detail(session_stamp: str, package: str) -> Optional[str]:
    try:
        row = run_sql(
            """
            SELECT high, med, low, info
            FROM static_findings_summary
            WHERE session_stamp = %s AND package_name = %s
            LIMIT 1
            """,
            (session_stamp, package),
            fetch="one",
            dictionary=True,
        )
    except Exception:
        return None
    if not row:
        return None
    return f"H{row.get('high', 0)}/M{row.get('med', 0)}/L{row.get('low', 0)}/I{row.get('info', 0)}"


def _fetch_string_summary_detail(session_stamp: str, package: str) -> Optional[str]:
    try:
        row = run_sql(
            """
            SELECT endpoints, http_cleartext, high_entropy
            FROM static_string_summary
            WHERE session_stamp = %s AND package_name = %s
            LIMIT 1
            """,
            (session_stamp, package),
            fetch="one",
            dictionary=True,
        )
    except Exception:
        return None
    if not row:
        return None
    return (
        f"endpoints={row.get('endpoints', 0)}, "
        f"http={row.get('http_cleartext', 0)}, "
        f"entropy={row.get('high_entropy', 0)}"
    )


def _fetch_metrics_summary(run_id: int) -> Optional[List[Dict[str, Any]]]:
    try:
        rows = run_sql(
            """
            SELECT feature_key, value_num
            FROM metrics
            WHERE run_id = %s
              AND feature_key IN ('network.code_http_hosts', 'exports.total')
            ORDER BY feature_key
            """,
            (run_id,),
            fetch="all",
            dictionary=True,
        )
    except Exception:
        return None
    return rows or None


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


def _print_status_line(level: str, label: str, *, detail: Optional[str] = None) -> None:
    icons = {"ok": "✅", "warn": "⚠️", "fail": "❌"}
    prefix = icons.get(level, "•")
    line = f"  {prefix} {label}"
    if detail:
        line += f" ({detail})"
    print(line)


__all__ = ["run_health_checks"]

