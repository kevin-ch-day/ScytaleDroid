"""Dataset export helpers for Tier-1 and exploration runs."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Iterable, Mapping

from scytaledroid.Database.db_core import db_queries as core_q


DATASET_NAME = "ScytaleDroid-Dyn-v1"


def export_manifest_csv(output_path: Path) -> Path:
    """Export a manifest CSV with inclusion/exclusion flags."""

    rows = _fetch_manifest_rows()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else [])
        if rows:
            writer.writeheader()
            writer.writerows(rows)
    return output_path


def export_run_telemetry_csv(
    *,
    dynamic_run_id: str,
    output_dir: Path,
    include_network: bool = True,
) -> list[Path]:
    """Export per-run telemetry to CSV (process + network)."""

    output_dir.mkdir(parents=True, exist_ok=True)
    outputs: list[Path] = []

    process_rows = _fetch_process_rows(dynamic_run_id)
    if process_rows:
        process_path = output_dir / f"{dynamic_run_id}-process.csv"
        _write_csv(process_path, process_rows)
        outputs.append(process_path)

    if include_network:
        network_rows = _fetch_network_rows(dynamic_run_id)
        if network_rows:
            network_path = output_dir / f"{dynamic_run_id}-network.csv"
            _write_csv(network_path, network_rows)
            outputs.append(network_path)

    return outputs


def _fetch_manifest_rows() -> list[dict[str, Any]]:
    has_tier = _dynamic_sessions_has_column("tier")
    has_netstats = _dynamic_sessions_has_column("netstats_available")
    tier_select = "ds.tier" if has_tier else "NULL AS tier"
    netstats_select = "ds.netstats_available" if has_netstats else "NULL AS netstats_available"
    netstats_gate = "WHEN ds.netstats_available = 0 THEN 'exclude_netstats'" if has_netstats else ""
    sql = f"""
        SELECT
          ds.dynamic_run_id,
          ds.package_name,
          ds.version_name,
          ds.version_code,
          ds.base_apk_sha256,
          ds.artifact_set_hash,
          ds.scenario_id,
          ds.sampling_rate_s,
          {tier_select},
          ds.started_at_utc,
          ds.ended_at_utc,
          ds.duration_seconds,
          {netstats_select},
          ds.expected_samples,
          ds.captured_samples,
          ds.sample_max_gap_s,
          ds.status,
          CASE
            WHEN ds.duration_seconds IS NULL OR ds.duration_seconds < 90 THEN 'exclude_duration'
            WHEN ds.expected_samples IS NULL OR ds.captured_samples IS NULL THEN 'exclude_missing_stats'
            WHEN ds.captured_samples / NULLIF(ds.expected_samples,0) < 0.90 THEN 'exclude_low_capture'
            WHEN ds.sample_max_gap_s > (ds.sampling_rate_s * 2) THEN 'exclude_gap'
            {netstats_gate}
            ELSE 'include'
          END AS inclusion_status,
          %s AS dataset_name
        FROM dynamic_sessions ds
        ORDER BY ds.started_at_utc DESC
    """
    rows = core_q.run_sql(sql, (DATASET_NAME,), fetch="all", dictionary=True) or []
    return [dict(row) for row in rows]


def _fetch_process_rows(dynamic_run_id: str) -> list[dict[str, Any]]:
    sql = """
        SELECT
          dynamic_run_id,
          timestamp_utc,
          sample_index,
          uid,
          pid,
          cpu_pct,
          rss_kb,
          pss_kb,
          threads,
          proc_name
        FROM dynamic_telemetry_process
        WHERE dynamic_run_id = %s
        ORDER BY timestamp_utc ASC
    """
    rows = core_q.run_sql(sql, (dynamic_run_id,), fetch="all", dictionary=True) or []
    return [dict(row) for row in rows]


def _fetch_network_rows(dynamic_run_id: str) -> list[dict[str, Any]]:
    sql = """
        SELECT
          dynamic_run_id,
          timestamp_utc,
          sample_index,
          uid,
          bytes_in,
          bytes_out,
          conn_count,
          source
        FROM dynamic_telemetry_network
        WHERE dynamic_run_id = %s
          AND source = 'netstats'
        ORDER BY timestamp_utc ASC
    """
    rows = core_q.run_sql(sql, (dynamic_run_id,), fetch="all", dictionary=True) or []
    return [dict(row) for row in rows]


def _write_csv(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    rows = list(rows)
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


_DYN_SESSIONS_COLUMNS: set[str] | None = None


def _dynamic_sessions_has_column(column_name: str) -> bool:
    global _DYN_SESSIONS_COLUMNS
    if _DYN_SESSIONS_COLUMNS is None:
        try:
            rows = core_q.run_sql(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = DATABASE() AND table_name = 'dynamic_sessions'",
                fetch="all",
                dictionary=True,
            )
            _DYN_SESSIONS_COLUMNS = {
                str(row.get("column_name")).lower() for row in rows or [] if row.get("column_name")
            }
        except Exception:
            _DYN_SESSIONS_COLUMNS = set()
    return column_name.lower() in _DYN_SESSIONS_COLUMNS
