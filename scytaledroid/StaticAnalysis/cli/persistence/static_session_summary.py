"""``static_analysis_sessions`` shell upsert and aggregate refresh."""

from __future__ import annotations

from dataclasses import dataclass

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .session_header_linkage import resolve_static_session_id_for_run


def _norm_scope(scope_label: str | None) -> str:
    if scope_label is None:
        return ""
    return str(scope_label).strip()


def classify_static_session_status_and_disposition(
    *,
    session_stamp: str,
    scope_label: str,
    total_run_count: int,
    completed_run_count: int,
    failed_run_count: int,
    interrupted_run_count: int,
    persist_error_run_count: int,
    missing_artifacts_run_count: int,
) -> tuple[str, str]:
    """Derive ``session_status`` / ``session_disposition`` from run-level rollups.

    Ordering matches ``scripts/db/sql/session_summary_from_static_analysis_runs.sql``.
    """

    total = total_run_count
    if total <= 0:
        return ("UNKNOWN", "unknown_needs_review")

    stamp = session_stamp or ""
    scope = scope_label or ""

    # ---- session_status (coarse rollup) ----
    if completed_run_count == total:
        session_status = "COMPLETED"
    elif completed_run_count > 0 and failed_run_count > 0:
        session_status = "PARTIAL"
    elif interrupted_run_count > 0:
        session_status = "INTERRUPTED"
    elif failed_run_count == total:
        session_status = "FAILED"
    else:
        session_status = "UNKNOWN"

    # ---- session_disposition (cleanup/Web driver) ----
    if failed_run_count == total and interrupted_run_count > 0:
        disposition = "interrupted_partial_session"
    elif failed_run_count == total and persist_error_run_count > 0:
        disposition = "broken_persist_error_session"
    elif failed_run_count == total and missing_artifacts_run_count > 0:
        disposition = "broken_missing_artifacts_session"
    elif completed_run_count > 0 and failed_run_count > 0:
        disposition = "mixed_completed_failed_session"
    elif completed_run_count == total and (
        "all-full" in stamp.lower() or scope == "All harvested apps"
    ):
        disposition = "completed_full_session"
    elif completed_run_count == total:
        disposition = "completed_profile_session"
    else:
        disposition = "unknown_needs_review"

    return (session_status, disposition)


@dataclass(frozen=True)
class StaticSessionRunRollups:
    total_run_count: int
    completed_run_count: int
    failed_run_count: int
    interrupted_run_count: int
    persist_error_run_count: int
    missing_artifacts_run_count: int
    first_created_at: str | None
    last_ended_at: str | None


def fetch_static_session_run_rollups(session_stamp: str, scope_label: str) -> StaticSessionRunRollups | None:
    stamp = (session_stamp or "").strip()
    scope = _norm_scope(scope_label)
    if not stamp:
        return None

    row = core_q.run_sql(
        """
        SELECT
          COUNT(*) AS total_run_count,
          SUM(CASE WHEN sar.status = 'COMPLETED' THEN 1 ELSE 0 END) AS completed_run_count,
          SUM(CASE WHEN sar.status = 'FAILED' THEN 1 ELSE 0 END) AS failed_run_count,
          SUM(
            CASE
              WHEN sar.abort_reason IN ('user_abort', 'SIGINT') OR sar.abort_signal = 'SIGINT'
              THEN 1 ELSE 0
            END
          ) AS interrupted_run_count,
          SUM(CASE WHEN sar.abort_reason = 'persist_error' THEN 1 ELSE 0 END) AS persist_error_run_count,
          SUM(CASE WHEN sar.abort_reason = 'missing_required_artifacts' THEN 1 ELSE 0 END)
            AS missing_artifacts_run_count,
          MIN(sar.created_at) AS first_created_at,
          MAX(sar.ended_at_utc) AS last_ended_at
        FROM static_analysis_runs sar
        WHERE sar.session_stamp = %s
          AND COALESCE(TRIM(BOTH FROM sar.scope_label), '') = %s
        """,
        (stamp, scope),
        fetch="one",
    )
    if not row:
        return None

    def g(name: str, idx: int) -> object:
        if isinstance(row, dict):
            return row.get(name)
        if isinstance(row, (list, tuple)) and len(row) > idx:
            return row[idx]
        return None

    total = int(g("total_run_count", 0) or 0)
    if total == 0:
        return None

    return StaticSessionRunRollups(
        total_run_count=total,
        completed_run_count=int(g("completed_run_count", 1) or 0),
        failed_run_count=int(g("failed_run_count", 2) or 0),
        interrupted_run_count=int(g("interrupted_run_count", 3) or 0),
        persist_error_run_count=int(g("persist_error_run_count", 4) or 0),
        missing_artifacts_run_count=int(g("missing_artifacts_run_count", 5) or 0),
        first_created_at=_as_db_datetime(g("first_created_at", 6)),
        last_ended_at=_as_db_datetime(g("last_ended_at", 7)),
    )


def _as_db_datetime(value: object) -> str | None:
    if value is None:
        return None
    if hasattr(value, "strftime"):
        try:
            return value.strftime("%Y-%m-%d %H:%M:%S")  # type: ignore[no-any-return]
        except Exception:
            return str(value)
    text = str(value).strip()
    return text or None


def ensure_static_session_shell(
    *,
    session_stamp: str,
    scope_label: str | None,
    session_label: str | None = None,
    tool_semver: str | None = None,
    tool_git_commit: str | None = None,
    schema_version: str | None = None,
) -> int | None:
    """Create a minimal session header row if missing; preserve aggregates and operator knobs on conflict."""

    stamp = (session_stamp or "").strip()
    if not stamp:
        return None
    scope = _norm_scope(scope_label)
    label = None
    if session_label is not None and str(session_label).strip():
        label = str(session_label).strip()

    upsert_sql = """
    INSERT INTO static_analysis_sessions (
      session_stamp,
      scope_label,
      session_label,
      session_status,
      session_disposition,
      disposition_confidence,
      tool_semver,
      tool_git_commit,
      schema_version
    )
    VALUES (
      %s, %s, %s,
      'UNKNOWN',
      'unknown_needs_review',
      'medium',
      %s, %s, %s
    )
    ON DUPLICATE KEY UPDATE
      session_label = CASE
        WHEN VALUES(session_label) IS NOT NULL AND LENGTH(TRIM(VALUES(session_label))) > 0
          THEN VALUES(session_label)
        ELSE session_label
      END,
      tool_semver = COALESCE(VALUES(tool_semver), tool_semver),
      tool_git_commit = COALESCE(VALUES(tool_git_commit), tool_git_commit),
      schema_version = COALESCE(VALUES(schema_version), schema_version)
    """
    core_q.run_sql(
        upsert_sql,
        (stamp, scope, label, tool_semver, tool_git_commit, schema_version),
        fetch="none",
        query_name="static_session.ensure_shell",
    )
    return resolve_static_session_id_for_run(stamp, scope)


def _scalar_child_count(sql: str, params: tuple[object, ...]) -> int:
    row = core_q.run_sql(sql, params, fetch="one", query_name="static_session.child_count")
    if not row:
        return 0
    if isinstance(row, dict):
        v = row.get("child_cnt")
        if v is None and len(row) == 1:
            v = next(iter(row.values()))
    else:
        v = row[0]
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


_FETCH_FINDINGS_ROWS = """
SELECT COUNT(*) AS child_cnt
FROM static_analysis_findings f
JOIN static_analysis_runs r ON r.id = f.run_id
WHERE r.session_stamp = %s
  AND COALESCE(TRIM(BOTH FROM r.scope_label), '') = %s
"""

_FETCH_MATRIX_ROWS = """
SELECT COUNT(*) AS child_cnt
FROM static_permission_matrix pm
JOIN static_analysis_runs r ON r.id = pm.run_id
WHERE r.session_stamp = %s
  AND COALESCE(TRIM(BOTH FROM r.scope_label), '') = %s
"""

_FETCH_RISK_ROWS = """
SELECT COUNT(*) AS child_cnt
FROM static_permission_risk_vnext pr
JOIN static_analysis_runs r ON r.id = pr.run_id
WHERE r.session_stamp = %s
  AND COALESCE(TRIM(BOTH FROM r.scope_label), '') = %s
"""

_FETCH_STRING_SUMMARY_ROWS = """
SELECT COUNT(*) AS child_cnt
FROM static_string_summary ss
WHERE ss.session_stamp = %s
  AND COALESCE(TRIM(BOTH FROM ss.scope_label), '') = %s
"""

_FETCH_STRING_SAMPLE_ROWS = """
SELECT COUNT(*) AS child_cnt
FROM static_string_samples samp
JOIN static_string_summary ss ON ss.id = samp.summary_id
WHERE ss.session_stamp = %s
  AND COALESCE(TRIM(BOTH FROM ss.scope_label), '') = %s
"""

_FETCH_SESSION_LINK_ROWS = """
SELECT COUNT(*) AS child_cnt
FROM static_session_run_links l
WHERE l.session_stamp = %s
"""

_FETCH_ROLLUP_ROWS = """
SELECT COUNT(*) AS child_cnt
FROM static_session_rollups u
WHERE u.session_stamp = %s
  AND COALESCE(TRIM(BOTH FROM u.scope_label), '') = %s
"""

_FETCH_PERSISTENCE_FAILURE_ROWS = """
SELECT COUNT(*) AS child_cnt
FROM static_persistence_failures p
JOIN static_analysis_runs r ON r.id = p.static_run_id
WHERE r.session_stamp = %s
  AND COALESCE(TRIM(BOTH FROM r.scope_label), '') = %s
"""


def refresh_static_analysis_session_summary(
    *,
    session_stamp: str,
    scope_label: str | None,
) -> bool:
    """Recompute aggregate columns from child tables for one natural session key.

    Does **not** modify ``web_visibility_default``, ``cleanup_status``, or
    ``superseded_by_session_id``.
    """

    stamp = (session_stamp or "").strip()
    scope = _norm_scope(scope_label)
    if not stamp:
        return False

    rollups = fetch_static_session_run_rollups(stamp, scope)
    if rollups is None:
        return False

    sid_row = core_q.run_sql(
        """
        SELECT static_session_id FROM static_analysis_sessions
        WHERE session_stamp=%s AND scope_label=%s LIMIT 1
        """,
        (stamp, scope),
        fetch="one",
    )
    if not sid_row:
        return False
    sid = sid_row[0] if not isinstance(sid_row, dict) else sid_row.get("static_session_id")
    if sid is None:
        return False

    session_status, disposition = classify_static_session_status_and_disposition(
        session_stamp=stamp,
        scope_label=scope,
        total_run_count=rollups.total_run_count,
        completed_run_count=rollups.completed_run_count,
        failed_run_count=rollups.failed_run_count,
        interrupted_run_count=rollups.interrupted_run_count,
        persist_error_run_count=rollups.persist_error_run_count,
        missing_artifacts_run_count=rollups.missing_artifacts_run_count,
    )

    findings = _scalar_child_count(_FETCH_FINDINGS_ROWS, (stamp, scope))
    matrix = _scalar_child_count(_FETCH_MATRIX_ROWS, (stamp, scope))
    risk = _scalar_child_count(_FETCH_RISK_ROWS, (stamp, scope))
    str_sum = _scalar_child_count(_FETCH_STRING_SUMMARY_ROWS, (stamp, scope))
    str_samp = _scalar_child_count(_FETCH_STRING_SAMPLE_ROWS, (stamp, scope))
    links = _scalar_child_count(_FETCH_SESSION_LINK_ROWS, (stamp,))
    rollup_n = _scalar_child_count(_FETCH_ROLLUP_ROWS, (stamp, scope))
    persist_fail = _scalar_child_count(_FETCH_PERSISTENCE_FAILURE_ROWS, (stamp, scope))

    core_q.run_sql(
        """
        UPDATE static_analysis_sessions
        SET
          session_status = %s,
          session_disposition = %s,
          disposition_confidence = 'medium',
          total_run_count = %s,
          completed_run_count = %s,
          failed_run_count = %s,
          interrupted_run_count = %s,
          persist_error_run_count = %s,
          missing_artifacts_run_count = %s,
          total_findings_rows = %s,
          total_permission_matrix_rows = %s,
          total_permission_risk_rows = %s,
          total_string_summary_rows = %s,
          total_string_sample_rows = %s,
          session_link_rows = %s,
          rollup_rows = %s,
          persistence_failure_rows = %s,
          first_created_at = %s,
          last_ended_at = %s
        WHERE static_session_id = %s
        """,
        (
            session_status,
            disposition,
            rollups.total_run_count,
            rollups.completed_run_count,
            rollups.failed_run_count,
            rollups.interrupted_run_count,
            rollups.persist_error_run_count,
            rollups.missing_artifacts_run_count,
            findings,
            matrix,
            risk,
            str_sum,
            str_samp,
            links,
            rollup_n,
            persist_fail,
            rollups.first_created_at,
            rollups.last_ended_at,
            int(sid),
        ),
        fetch="none",
        query_name="static_session.refresh_summary",
    )
    return True


def list_distinct_session_keys_from_runs() -> list[tuple[str, str]]:
    rows = core_q.run_sql(
        """
        SELECT DISTINCT
          sar.session_stamp AS session_stamp,
          COALESCE(TRIM(BOTH FROM sar.scope_label), '') AS scope_label
        FROM static_analysis_runs sar
        WHERE sar.session_stamp IS NOT NULL
          AND LENGTH(TRIM(sar.session_stamp)) > 0
        ORDER BY session_stamp ASC, scope_label ASC
        """,
        (),
        fetch="all",
        query_name="static_session.list_keys",
    ) or []
    out: list[tuple[str, str]] = []
    for row in rows:
        if isinstance(row, dict):
            stamp = row.get("session_stamp")
            scope = row.get("scope_label")
        elif isinstance(row, (list, tuple)) and len(row) >= 2:
            stamp, scope = row[0], row[1]
        else:
            continue
        out.append((str(stamp), str(scope)))
    return out


def refresh_all_static_analysis_sessions_from_runs() -> int:
    """Refresh every (session_stamp, scope_label) observed in ``static_analysis_runs``."""

    n = 0
    for stamp, scope in list_distinct_session_keys_from_runs():
        if refresh_static_analysis_session_summary(session_stamp=stamp, scope_label=scope):
            n += 1
    return n


def maybe_refresh_static_analysis_session_summary(
    session_stamp: str | None,
    scope_label: str | None,
    *,
    reason: str = "session_refresh",
) -> None:
    """Call :func:`refresh_static_analysis_session_summary` and swallow DB errors."""

    stamp = (session_stamp or "").strip()
    if not stamp:
        return
    try:
        refresh_static_analysis_session_summary(session_stamp=stamp, scope_label=scope_label)
    except Exception as exc:
        log.warning(
            f"static_analysis_sessions refresh failed ({reason}): {exc}",
            category="static_analysis",
        )


def refresh_static_session_summaries_for_session_stamp(session_stamp: str | None) -> None:
    """Refresh session headers for every ``scope_label`` present under ``session_stamp``."""

    stamp = (session_stamp or "").strip()
    if not stamp:
        return
    try:
        rows = core_q.run_sql(
            """
            SELECT DISTINCT COALESCE(TRIM(BOTH FROM sar.scope_label), '') AS scope_label
            FROM static_analysis_runs sar
            WHERE sar.session_stamp = %s
            """,
            (stamp,),
            fetch="all",
            query_name="static_session.scopes_for_stamp",
        ) or []
    except Exception as exc:
        log.warning(
            f"static_analysis_sessions scope listing failed (session_stamp={stamp}): {exc}",
            category="static_analysis",
        )
        return

    for row in rows:
        if isinstance(row, dict):
            scope_val = row.get("scope_label")
        elif isinstance(row, (list, tuple)) and row:
            scope_val = row[0]
        else:
            continue
        scope = "" if scope_val is None else str(scope_val)
        maybe_refresh_static_analysis_session_summary(
            stamp,
            scope,
            reason="session_stamp_batch",
        )
