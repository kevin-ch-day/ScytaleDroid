"""Lookup helpers linking ``static_analysis_runs`` rows to ``static_analysis_sessions``."""

from __future__ import annotations

from scytaledroid.Database.db_core import db_queries as core_q


def resolve_static_session_id_for_run(session_stamp: str | None, scope_label: str | None) -> int | None:
    """Return ``static_session_id`` when a matching session header row exists."""

    stamp = (session_stamp or "").strip()
    if not stamp:
        return None
    scope = ""
    if scope_label is not None:
        scope = str(scope_label).strip()

    try:
        row = core_q.run_sql(
            """
            SELECT static_session_id
            FROM static_analysis_sessions
            WHERE session_stamp=%s AND scope_label=%s
            LIMIT 1
            """,
            (stamp, scope),
            fetch="one",
        )
    except Exception:
        return None

    if not row:
        return None
    sid = row[0] if not isinstance(row, dict) else row.get("static_session_id")
    if sid is None:
        return None
    try:
        return int(sid)
    except (TypeError, ValueError):
        return None
