"""Static integrity health-check helpers for Database Utilities menu."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def render_integrity_checks(
    *,
    run_sql: Callable[..., Any],
    print_status_line: Callable[..., None],
    session_stamp: str | None,
) -> None:
    print_status_line(
        "warn",
        "latest APK ↔ summary",
        detail="view checks disabled by policy (no DB views)",
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
    selected_rows = run_sql(
        """
        SELECT s.id AS summary_id, COUNT(x.id) AS samples
        FROM static_findings_summary s
        LEFT JOIN static_string_selected_samples x ON x.summary_id = s.id
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
            print_status_line(
                "warn",
                "summary ↔ string samples",
                detail=f"missing samples for summary_id(s) {', '.join(map(str, zero_samples))}",
            )
        else:
            print_status_line("ok", "summary ↔ string samples", detail=f"{len(sample_rows)} summaries inspected")
        if selected_rows:
            zero_selected = [row["summary_id"] for row in selected_rows if not row.get("samples")]
            if zero_selected:
                print_status_line(
                    "warn",
                    "summary ↔ selected samples",
                    detail=f"missing selected samples for summary_id(s) {', '.join(map(str, zero_selected))}",
                )
            else:
                print_status_line("ok", "summary ↔ selected samples", detail=f"{len(selected_rows)} summaries inspected")
    else:
        print_status_line(
            "warn",
            "summary ↔ string samples",
            detail="no summaries found for recent sessions",
        )


def fetch_findings_detail(*, run_sql: Callable[..., Any], session_stamp: str) -> str | None:
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


def fetch_string_summary_detail(*, run_sql: Callable[..., Any], session_stamp: str) -> str | None:
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

