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
    orphan_findings: int | None
    orphan_samples: int | None
    orphan_selected_samples: int | None
    orphan_sample_sets: int | None
    orphan_audit_apps: int | None


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
        orphan_findings=orphan_findings,
        orphan_samples=orphan_samples,
        orphan_selected_samples=orphan_selected_samples,
        orphan_sample_sets=orphan_sample_sets,
        orphan_audit_apps=orphan_audit_apps,
    )


__all__ = ["HealthSummary", "fetch_health_summary"]
