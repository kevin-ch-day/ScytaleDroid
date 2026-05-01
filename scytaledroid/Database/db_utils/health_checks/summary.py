"""Data builders for DB health summaries."""

from __future__ import annotations

from dataclasses import dataclass

from scytaledroid.Database.db_utils.menus.sql_helpers import scalar


@dataclass(frozen=True)
class HealthSummary:
    running_total: int | None
    running_recent: int | None
    ok_recent: int | None
    failed_recent: int | None
    aborted_recent: int | None
    stale_started_rows: int | None
    stale_started_sessions: int | None
    stale_started_rows_without_downstream: int | None
    stale_started_sessions_without_downstream: int | None
    orphan_findings: int | None
    orphan_samples: int | None
    orphan_selected_samples: int | None
    orphan_sample_sets: int | None
    orphan_audit_apps: int | None


STALE_STATIC_STARTED_THRESHOLD_HOURS = 2
STALE_STATIC_SESSION_MIN_ROWS = 5


def _started_at_expr(alias: str = "") -> str:
    prefix = f"{alias}." if alias else ""
    return (
        "COALESCE("
        f"STR_TO_DATE(REPLACE(REPLACE({prefix}run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f'), "
        f"STR_TO_DATE(REPLACE(REPLACE({prefix}run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s'), "
        f"{prefix}created_at"
        ")"
    )


def fetch_health_summary() -> HealthSummary:
    """Return aggregate health summary counts for the DB health screen."""
    running_total = scalar(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status='RUNNING' AND ended_at_utc IS NULL
        """
    )
    running_recent = scalar(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status='RUNNING' AND ended_at_utc IS NULL
          AND COALESCE(
            STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f'),
            STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s')
          ) >= (UTC_TIMESTAMP() - INTERVAL 1 DAY)
        """
    )
    ok_recent = scalar(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status IN ('COMPLETED','OK')
          AND ended_at_utc >= (UTC_TIMESTAMP() - INTERVAL 1 DAY)
        """
    )
    failed_recent = scalar(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status='FAILED'
          AND ended_at_utc >= (UTC_TIMESTAMP() - INTERVAL 1 DAY)
        """
    )
    aborted_recent = scalar(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status='ABORTED'
          AND ended_at_utc >= (UTC_TIMESTAMP() - INTERVAL 1 DAY)
        """
    )
    started_at_expr = _started_at_expr()
    stale_started_rows = scalar(
        f"""
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status='STARTED'
          AND ended_at_utc IS NULL
          AND {started_at_expr} < (UTC_TIMESTAMP() - INTERVAL {STALE_STATIC_STARTED_THRESHOLD_HOURS} HOUR)
        """
    )
    stale_started_sessions = scalar(
        f"""
        SELECT COUNT(*)
        FROM (
          SELECT session_label
          FROM static_analysis_runs
          WHERE status='STARTED'
            AND ended_at_utc IS NULL
            AND {started_at_expr} < (UTC_TIMESTAMP() - INTERVAL {STALE_STATIC_STARTED_THRESHOLD_HOURS} HOUR)
          GROUP BY session_label
        ) stale_sessions
        """
    )
    stale_started_rows_without_downstream = scalar(
        f"""
        SELECT COUNT(*)
        FROM static_analysis_runs sar
        LEFT JOIN static_analysis_findings saf ON saf.static_run_id = sar.id
        LEFT JOIN static_permission_matrix spm ON spm.run_id = sar.id
        WHERE sar.status='STARTED'
          AND sar.ended_at_utc IS NULL
          AND {_started_at_expr('sar')} < (UTC_TIMESTAMP() - INTERVAL {STALE_STATIC_STARTED_THRESHOLD_HOURS} HOUR)
          AND saf.static_run_id IS NULL
          AND spm.id IS NULL
        """
    )
    stale_started_sessions_without_downstream = scalar(
        f"""
        SELECT COUNT(*)
        FROM (
          SELECT sar.session_label
          FROM static_analysis_runs sar
          LEFT JOIN static_analysis_findings saf ON saf.static_run_id = sar.id
          LEFT JOIN static_permission_matrix spm ON spm.run_id = sar.id
          WHERE sar.status='STARTED'
            AND sar.ended_at_utc IS NULL
            AND {_started_at_expr('sar')} < (UTC_TIMESTAMP() - INTERVAL {STALE_STATIC_STARTED_THRESHOLD_HOURS} HOUR)
          GROUP BY sar.session_label
          HAVING COUNT(*) >= {STALE_STATIC_SESSION_MIN_ROWS}
             AND COUNT(saf.static_run_id) = 0
             AND COUNT(spm.id) = 0
        ) stale_sessions
        """
    )
    orphan_findings = scalar(
        """
        SELECT COUNT(*)
        FROM static_findings f
        LEFT JOIN static_findings_summary s ON s.id = f.summary_id
        WHERE s.id IS NULL
        """
    )
    orphan_samples = scalar(
        """
        SELECT COUNT(*)
        FROM static_string_samples x
        LEFT JOIN static_string_summary s ON s.id = x.summary_id
        WHERE s.id IS NULL
        """
    )
    orphan_selected_samples = scalar(
        """
        SELECT COUNT(*)
        FROM static_string_selected_samples x
        LEFT JOIN static_string_summary s ON s.id = x.summary_id
        WHERE s.id IS NULL
        """
    )
    orphan_sample_sets = scalar(
        """
        SELECT COUNT(*)
        FROM static_string_sample_sets x
        LEFT JOIN static_string_summary s ON s.id = x.summary_id
        WHERE s.id IS NULL
        """
    )
    orphan_audit_apps = scalar(
        """
        SELECT COUNT(*)
        FROM permission_audit_apps a
        LEFT JOIN permission_audit_snapshots s ON s.snapshot_id = a.snapshot_id
        WHERE s.snapshot_id IS NULL
        """
    )

    return HealthSummary(
        running_total=running_total,
        running_recent=running_recent,
        ok_recent=ok_recent,
        failed_recent=failed_recent,
        aborted_recent=aborted_recent,
        stale_started_rows=stale_started_rows,
        stale_started_sessions=stale_started_sessions,
        stale_started_rows_without_downstream=stale_started_rows_without_downstream,
        stale_started_sessions_without_downstream=stale_started_sessions_without_downstream,
        orphan_findings=orphan_findings,
        orphan_samples=orphan_samples,
        orphan_selected_samples=orphan_selected_samples,
        orphan_sample_sets=orphan_sample_sets,
        orphan_audit_apps=orphan_audit_apps,
    )


__all__ = ["HealthSummary", "fetch_health_summary"]
