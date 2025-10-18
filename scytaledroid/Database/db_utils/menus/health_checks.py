"""Data health checks for Database Utilities menu."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from scytaledroid.Database.db_core import run_sql
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from .sql_helpers import coerce_datetime, scalar, view_exists


def run_health_checks() -> None:
    print()
    menu_utils.print_header("Data Health Checks")

    latest_run = _fetch_latest_run()
    latest_session = _fetch_latest_session()

    if latest_run is None and latest_session is None:
        print(status_messages.status("No runs or summaries recorded yet.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    run_id = int(latest_run.get("run_id") or 0) if latest_run else 0
    package = str(
        (latest_run or {}).get("package")
        or (latest_session or {}).get("package_name")
        or "<unknown>"
    )
    ts_value = (latest_run or {}).get("ts")
    ts_dt = coerce_datetime(ts_value)
    session_from_run = (latest_run or {}).get("session_stamp")
    session_stamp = session_from_run or (latest_session or {}).get("session_stamp")

    print(
        "Ingestion — latest session "
        f"(session={session_stamp or 'unknown'})"
    )

    if session_stamp:
        findings_total = scalar(
            "SELECT COUNT(*) FROM static_findings_summary WHERE session_stamp = %s",
            (session_stamp,),
        )
        findings_detail = _fetch_findings_detail(session_stamp)
        _print_status_line(
            "ok" if findings_total else "fail",
            "static_findings_summary",
            detail=findings_detail or str(findings_total or 0),
        )

        strings_total = scalar(
            "SELECT COUNT(*) FROM static_string_summary WHERE session_stamp = %s",
            (session_stamp,),
        )
        strings_detail = _fetch_string_summary_detail(session_stamp)
        _print_status_line(
            "ok" if strings_total else "fail",
            "static_string_summary",
            detail=strings_detail or str(strings_total or 0),
        )

        findings_rows_total = scalar(
            """
            SELECT COUNT(*)
            FROM static_findings f
            JOIN static_findings_summary s ON s.id = f.summary_id
            WHERE s.session_stamp = %s
            """,
            (session_stamp,),
        )
        if findings_rows_total is not None:
            _print_status_line(
                "ok" if findings_rows_total else "warn",
                "static_findings",
                detail=str(findings_rows_total or 0),
            )

        provider_total = scalar(
            "SELECT COUNT(*) FROM static_provider_acl WHERE session_stamp = %s",
            (session_stamp,),
        )
        _print_status_line(
            "ok" if provider_total else "warn",
            "static_provider_acl",
            detail=str(provider_total or 0),
        )

        fileproviders_total = scalar(
            "SELECT COUNT(*) FROM static_fileproviders WHERE session_stamp = %s",
            (session_stamp,),
        )
        _print_status_line(
            "ok" if fileproviders_total else "warn",
            "static_fileproviders",
            detail=str(fileproviders_total or 0),
        )

        samples_total = scalar(
            """
            SELECT COUNT(*)
            FROM static_string_samples x
            JOIN static_findings_summary s ON s.id = x.summary_id
            WHERE s.session_stamp = %s
            """,
            (session_stamp,),
        )
        if samples_total is not None:
            _print_status_line(
                "ok" if samples_total else "warn",
                "static_string_samples",
                detail=str(samples_total or 0),
            )
    else:
        _print_status_line(
            "warn",
            "session_stamp",
            detail="no session stamp recorded; ensure static runs persist summaries",
        )

    print()
    print("Run linkage")
    if latest_run:
        run_label = f"run_id={run_id}, pkg={package}, ts={ts_dt or ts_value}"
        _print_status_line("ok", "runs", detail=run_label)

        buckets_count = scalar("SELECT COUNT(*) FROM buckets WHERE run_id=%s", (run_id,))
        _print_status_line(
            "ok" if buckets_count else "fail",
            "buckets",
            detail=str(buckets_count or 0),
        )

        metrics_rows = _fetch_metrics_summary(run_id)
        if metrics_rows:
            detail = ", ".join(
                f"{row['feature_key']}={row['value_num']}" for row in metrics_rows
            )
            _print_status_line("ok", "metrics", detail=detail)
        else:
            _print_status_line("warn", "metrics", detail="expected keys not present")
    else:
        _print_status_line(
            "warn",
            "runs",
            detail="no rows in runs table; run baseline/full analysis to populate",
        )

    print()
    print("Scoring & coverage")
    _render_scoring_checks()

    print()
    print("Integrity")
    _render_integrity_checks(session_stamp)

    prompt_utils.press_enter_to_continue()


def _fetch_latest_run() -> Optional[Dict[str, Any]]:
    try:
        return run_sql(
            "SELECT run_id, package, version_name, target_sdk, ts, session_stamp FROM runs ORDER BY run_id DESC LIMIT 1",
            fetch="one",
            dictionary=True,
        )
    except Exception as exc:
        # Fallback to legacy schema without session_stamp
        try:
            row = run_sql(
                "SELECT run_id, package, version_name, target_sdk, ts FROM runs ORDER BY run_id DESC LIMIT 1",
                fetch="one",
                dictionary=True,
            )
            if row is None:
                return None
            row.setdefault("session_stamp", None)
            return row
        except Exception:
            print(status_messages.status(f"Unable to query runs table: {exc}", level="error"))
            return None


def _fetch_latest_session() -> Optional[Dict[str, Any]]:
    try:
        return run_sql(
            """
            SELECT session_stamp, package_name
            FROM static_findings_summary
            ORDER BY created_at DESC
            LIMIT 1
            """,
            fetch="one",
            dictionary=True,
        )
    except Exception:
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

    latest_snapshot_id = scalar("SELECT MAX(snapshot_id) FROM permission_audit_snapshots")
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
        "contributors": "wire risk contributors emit",
        "correlations": "wire correlation detector persistence",
        "risk_scores": "optional rollup; populate after scoring contributors",
        "static_permission_risk": "optional per-apk rollup; populate after scoring contributors",
    }
    for table, hint in optional_tables.items():
        count = scalar(f"SELECT COUNT(*) FROM {table}")
        level = "ok" if count else "warn"
        detail = f"{count or 0} rows"
        if not count:
            detail += f" — {hint}"
        _print_status_line(level, table, detail=detail)


def _render_integrity_checks(session_stamp: Optional[str]) -> None:
    if view_exists("vw_latest_apk_per_package"):
        params: Sequence[Any]
        if session_stamp:
            params = (session_stamp, session_stamp)
        else:
            params = (None, None)
        try:
            rows = run_sql(
                """
                SELECT v.package_name, s.id AS summary_id
                FROM vw_latest_apk_per_package v
                LEFT JOIN static_findings_summary s
                  ON s.package_name = v.package_name
                 AND (%s IS NULL OR s.session_stamp = %s)
                ORDER BY v.updated_at DESC
                LIMIT 10
                """,
                params,
                fetch="all",
                dictionary=True,
            )
        except Exception:
            rows = []
        missing = [row["package_name"] for row in rows if not row.get("summary_id")]
        if rows and not missing:
            _print_status_line("ok", "latest APK ↔ summary", detail=f"{len(rows)} packages checked")
        elif missing:
            _print_status_line(
                "warn",
                "latest APK ↔ summary",
                detail=f"missing summaries for {', '.join(missing)}",
            )
        else:
            _print_status_line("warn", "latest APK ↔ summary", detail="no packages returned from view")
    else:
        _print_status_line(
            "warn",
            "latest APK ↔ summary",
            detail="vw_latest_apk_per_package view unavailable — create view to enable check",
        )

    sample_rows = run_sql(
        """
        SELECT s.id AS summary_id, COUNT(x.id) AS samples
        FROM static_findings_summary s
        LEFT JOIN static_string_samples x ON x.summary_id = s.id
        WHERE %s IS NULL OR s.session_stamp = %s
        GROUP BY s.id
        ORDER BY s.created_at DESC
        LIMIT 5
        """,
        (session_stamp, session_stamp),
        fetch="all",
        dictionary=True,
    ) or []
    if sample_rows:
        zero_samples = [row["summary_id"] for row in sample_rows if not row.get("samples")]
        if zero_samples:
            _print_status_line(
                "warn",
                "summary ↔ string samples",
                detail=f"missing samples for summary_id(s) {', '.join(map(str, zero_samples))}",
            )
        else:
            _print_status_line("ok", "summary ↔ string samples", detail=f"{len(sample_rows)} summaries inspected")
    else:
        _print_status_line(
            "warn",
            "summary ↔ string samples",
            detail="no summaries found for recent sessions",
        )


def _fetch_findings_detail(session_stamp: str) -> Optional[str]:
    try:
        row = run_sql(
            """
            SELECT SUM(high) AS high, SUM(med) AS med, SUM(low) AS low, SUM(info) AS info
            FROM static_findings_summary
            WHERE session_stamp = %s
            """,
            (session_stamp,),
            fetch="one",
            dictionary=True,
        )
    except Exception:
        return None
    if not row:
        return None
    return (
        f"H{row.get('high', 0)}/M{row.get('med', 0)}/"
        f"L{row.get('low', 0)}/I{row.get('info', 0)}"
    )


def _fetch_string_summary_detail(session_stamp: str) -> Optional[str]:
    try:
        row = run_sql(
            """
            SELECT SUM(endpoints) AS endpoints,
                   SUM(http_cleartext) AS http_cleartext,
                   SUM(high_entropy) AS high_entropy
            FROM static_string_summary
            WHERE session_stamp = %s
            """,
            (session_stamp,),
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


def _print_status_line(level: str, label: str, *, detail: Optional[str] = None) -> None:
    icons = {"ok": "✅", "warn": "⚠️", "fail": "❌"}
    prefix = icons.get(level, "•")
    line = f"  {prefix} {label}"
    if detail:
        line += f" ({detail})"
    print(line)


__all__ = ["run_health_checks"]
