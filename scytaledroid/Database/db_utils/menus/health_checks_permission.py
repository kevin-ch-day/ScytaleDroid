"""Permission/scoring health-check helpers for Database Utilities menu."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def render_scoring_checks(
    *,
    run_sql: Callable[..., Any],
    scalar: Callable[..., Any],
    print_status_line: Callable[..., None],
    status_messages: Any,
) -> None:
    """Render permission/scoring integrity checks for the health-check screen."""
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
        print_status_line(level, "permission_audit_snapshots ↔ permission_audit_apps", detail=detail)
    else:
        print_status_line("warn", "permission audit", detail="no snapshots recorded yet")

    mismatch_total = scalar(
        """
        SELECT COUNT(*)
        FROM (
          SELECT s.snapshot_id
          FROM permission_audit_snapshots s
          LEFT JOIN permission_audit_apps a ON a.snapshot_id = s.snapshot_id
          GROUP BY s.snapshot_id, s.apps_total
          HAVING COALESCE(s.apps_total, 0) <> COUNT(a.audit_id)
        ) x
        """
    )
    if mismatch_total is not None:
        level = "ok" if int(mismatch_total or 0) == 0 else "warn"
        print_status_line(level, "permission snapshot total drift", detail=f"{int(mismatch_total or 0)} snapshot(s)")

    partial_failed_runs = scalar(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs sar
        WHERE UPPER(COALESCE(sar.status, '')) = 'FAILED'
          AND EXISTS (SELECT 1 FROM static_permission_matrix spm WHERE spm.run_id = sar.id)
          AND NOT EXISTS (SELECT 1 FROM permission_audit_snapshots pas WHERE pas.static_run_id = sar.id)
        """
    )
    if partial_failed_runs is not None:
        level = "info" if int(partial_failed_runs or 0) else "ok"
        detail = (
            f"{int(partial_failed_runs or 0)} interrupted/failed run(s) with permission matrix but no snapshot refresh"
        )
        print_status_line(level, "permission audit partial runs", detail=detail)

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
            print_status_line("ok", "grade distribution", detail=detail)
        else:
            print_status_line("warn", "grade distribution", detail="no apps linked to latest snapshot")
    else:
        print_status_line("warn", "grade distribution", detail="no snapshots available")

    optional_tables = {
        "contributors": "wire risk contributors emit",
        "risk_scores": "run-level canonical risk source",
        "static_permission_risk_vnext": "run-aware permission-level risk rows",
    }
    for table, hint in optional_tables.items():
        count = scalar(f"SELECT COUNT(*) FROM {table}")
        if count:
            level = "ok"
        elif table in {"risk_scores", "static_permission_risk_vnext"}:
            level = "info"
        else:
            level = "warn"
        detail = f"{count or 0} rows"
        if not count:
            detail += f" — {hint}"
        print_status_line(level, table, detail=detail)

