"""Recompute-oriented helpers for DB health checks."""

from __future__ import annotations

from scytaledroid.Database.db_core import run_sql


def fetch_dataset_tier_run_count() -> int:
    row = run_sql(
        """
        SELECT COUNT(*)
        FROM dynamic_sessions
        WHERE tier='dataset'
        """,
        fetch="one",
    )
    return int((row or [0])[0] or 0)


def recompute_network_signal_quality() -> None:
    run_sql(
        """
        UPDATE dynamic_sessions ds
        LEFT JOIN (
          SELECT dynamic_run_id,
                 SUM(COALESCE(bytes_in,0)) AS sum_in,
                 SUM(COALESCE(bytes_out,0)) AS sum_out,
                 COUNT(*) AS row_count
          FROM dynamic_telemetry_network
          WHERE source='netstats'
          GROUP BY dynamic_run_id
        ) t ON t.dynamic_run_id = ds.dynamic_run_id
        SET ds.network_signal_quality =
          CASE
            WHEN COALESCE(t.row_count,0) = 0 AND ds.netstats_missing_rows > 0 THEN 'netstats_missing'
            WHEN COALESCE(t.row_count,0) = 0 THEN 'none'
            WHEN (COALESCE(t.sum_in,0) + COALESCE(t.sum_out,0)) = 0 THEN 'netstats_zero_bytes'
            WHEN ds.netstats_missing_rows > 0 THEN 'netstats_partial'
            ELSE 'netstats_ok'
          END
        WHERE ds.tier='dataset'
        """,
        fetch=None,
    )
