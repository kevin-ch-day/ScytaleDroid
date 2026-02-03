"""Dataset export helpers for Tier-1 and exploration runs."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.DynamicAnalysis.exports.feature_health import build_feature_health_report
from scytaledroid.DynamicAnalysis.analysis.privacy_manifest import write_privacy_manifest


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


def export_tier1_pack(output_dir: Path) -> dict[str, Path]:
    """Export manifest + summary + filtered telemetry for Tier-1 runs."""

    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "scytaledroid_dyn_v1_manifest.csv"
    summary_path = output_dir / "scytaledroid_dyn_v1_summary.csv"
    rollup_path = output_dir / "scytaledroid_dyn_v1_rollup.csv"

    manifest_rows = _fetch_manifest_rows()
    if manifest_rows:
        _write_csv(manifest_path, manifest_rows)
    else:
        _write_csv(manifest_path, [])

    summary_rows = _build_tier1_summary_rows(manifest_rows)
    if summary_rows:
        _write_csv(summary_path, summary_rows)
    else:
        _write_csv(summary_path, [])

    rollup_rows = _build_tier1_rollup_rows(manifest_rows)
    if rollup_rows:
        _write_csv(rollup_path, rollup_rows)
    else:
        _write_csv(rollup_path, [])

    included = [
        row
        for row in manifest_rows
        if row.get("inclusion_status") == "include"
    ]
    telemetry_dir = output_dir / "telemetry"
    _reset_telemetry_dir(telemetry_dir)
    for row in included:
        run_id = row["dynamic_run_id"]
        network_status = row.get("network_inclusion_status")
        include_network = network_status == "netstats_ok"
        export_run_telemetry_csv(
            dynamic_run_id=run_id,
            output_dir=telemetry_dir,
            include_network=include_network,
        )
        if not include_network:
            stale_network = telemetry_dir / f"{run_id}-network.csv"
            if stale_network.exists():
                stale_network.unlink()
            _write_network_skipped(
                telemetry_dir / f"{run_id}-network_skipped.json",
                reason=str(network_status or "network_unavailable"),
            )
    analysis_dir = output_dir / "analysis"
    feature_health = build_feature_health_report(
        telemetry_dir,
        analysis_dir,
        manifest_path=manifest_path,
    )
    privacy_manifest = write_privacy_manifest(analysis_dir)

    return {
        "manifest": manifest_path,
        "summary": summary_path,
        "rollup": rollup_path,
        "telemetry_dir": telemetry_dir,
        "analysis_dir": analysis_dir,
        "feature_health": feature_health,
        "privacy_manifest": privacy_manifest,
    }


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
    has_quality = _dynamic_sessions_has_column("network_signal_quality")
    has_netstats_rows = _dynamic_sessions_has_column("netstats_rows")
    has_netstats_missing = _dynamic_sessions_has_column("netstats_missing_rows")
    has_pcap_relpath = _dynamic_sessions_has_column("pcap_relpath")
    has_pcap_bytes = _dynamic_sessions_has_column("pcap_bytes")
    has_pcap_sha256 = _dynamic_sessions_has_column("pcap_sha256")
    has_pcap_valid = _dynamic_sessions_has_column("pcap_valid")
    has_pcap_validated = _dynamic_sessions_has_column("pcap_validated_at_utc")
    tier_select = "ds.tier" if has_tier else "NULL AS tier"
    netstats_select = "ds.netstats_available" if has_netstats else "NULL AS netstats_available"
    quality_select = "ds.network_signal_quality" if has_quality else "NULL AS network_signal_quality"
    netstats_rows_select = "ds.netstats_rows" if has_netstats_rows else "NULL AS netstats_rows"
    netstats_missing_select = (
        "ds.netstats_missing_rows" if has_netstats_missing else "NULL AS netstats_missing_rows"
    )
    pcap_relpath_select = "ds.pcap_relpath" if has_pcap_relpath else "NULL AS pcap_relpath"
    pcap_bytes_select = "ds.pcap_bytes" if has_pcap_bytes else "NULL AS pcap_bytes"
    pcap_sha256_select = "ds.pcap_sha256" if has_pcap_sha256 else "NULL AS pcap_sha256"
    pcap_valid_select = "ds.pcap_valid" if has_pcap_valid else "NULL AS pcap_valid"
    pcap_validated_select = (
        "ds.pcap_validated_at_utc" if has_pcap_validated else "NULL AS pcap_validated_at_utc"
    )
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
          {quality_select},
          ds.started_at_utc,
          ds.ended_at_utc,
          ds.duration_seconds,
          {netstats_select},
          ds.expected_samples,
          ds.captured_samples,
          ds.sample_max_gap_s,
          ds.status,
          {netstats_rows_select},
          {netstats_missing_select},
          {pcap_relpath_select},
          {pcap_bytes_select},
          {pcap_sha256_select},
          {pcap_valid_select},
          {pcap_validated_select},
          CASE
            WHEN ds.tier IS NULL THEN 'exclude_missing_tier'
            WHEN ds.tier <> 'dataset' THEN 'exclude_non_dataset'
            WHEN ds.duration_seconds IS NULL OR ds.duration_seconds < 90 THEN 'exclude_duration'
            WHEN ds.expected_samples IS NULL OR ds.captured_samples IS NULL THEN 'exclude_missing_stats'
            WHEN ds.captured_samples / NULLIF(ds.expected_samples,0) < 0.90 THEN 'exclude_low_capture'
            WHEN ds.sample_max_gap_s > (ds.sampling_rate_s * 2) THEN 'exclude_gap'
            ELSE 'include'
          END AS inclusion_status,
          %s AS dataset_name
        FROM dynamic_sessions ds
        ORDER BY ds.started_at_utc DESC
    """
    rows = core_q.run_sql(sql, (DATASET_NAME,), fetch="all", dictionary=True) or []
    totals = _fetch_netstats_totals([row.get("dynamic_run_id") for row in rows if row.get("dynamic_run_id")])
    enriched: list[dict[str, Any]] = []
    for row in rows:
        payload = dict(row)
        run_id = payload.get("dynamic_run_id")
        totals_row = totals.get(run_id, {}) if run_id else {}
        payload["netstats_bytes_in_total"] = totals_row.get("sum_in")
        payload["netstats_bytes_out_total"] = totals_row.get("sum_out")
        payload["network_inclusion_status"] = _derive_network_inclusion(payload)
        enriched.append(payload)
    return enriched


def _build_tier1_summary_rows(manifest_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not manifest_rows:
        return []
    summary: list[dict[str, Any]] = []
    for row in manifest_rows:
        summary.append(
            {
                "dynamic_run_id": row.get("dynamic_run_id"),
                "package_name": row.get("package_name"),
                "tier": row.get("tier"),
                "status": row.get("status"),
                "inclusion_status": row.get("inclusion_status"),
                "capture_ratio": _safe_ratio(row.get("captured_samples"), row.get("expected_samples")),
                "sample_max_gap_s": row.get("sample_max_gap_s"),
                "netstats_available": row.get("netstats_available"),
                "network_signal_quality": row.get("network_signal_quality"),
                "network_inclusion_status": row.get("network_inclusion_status"),
                "netstats_rows": row.get("netstats_rows"),
                "netstats_missing_rows": row.get("netstats_missing_rows"),
            }
        )
    return summary


def _build_tier1_rollup_rows(manifest_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not manifest_rows:
        return []
    rollup: dict[str, dict[str, Any]] = {}
    for row in manifest_rows:
        pkg = row.get("package_name") or "<unknown>"
        bucket = rollup.setdefault(
            pkg,
            {
                "package_name": pkg,
                "runs_total": 0,
                "runs_included": 0,
                "runs_excluded": 0,
                "avg_capture_ratio": [],
                "netstats_missing_pct": [],
            },
        )
        bucket["runs_total"] += 1
        if row.get("inclusion_status") == "include":
            bucket["runs_included"] += 1
        else:
            bucket["runs_excluded"] += 1
        ratio = _safe_ratio(row.get("captured_samples"), row.get("expected_samples"))
        if ratio is not None:
            bucket["avg_capture_ratio"].append(ratio)
        missing_rows = row.get("netstats_missing_rows")
        total_rows = row.get("netstats_rows")
        try:
            missing = float(missing_rows)
            total = float(total_rows)
        except (TypeError, ValueError):
            missing = None
            total = None
        if missing is not None and total and total > 0:
            bucket["netstats_missing_pct"].append(missing / total)

    output: list[dict[str, Any]] = []
    for pkg, bucket in rollup.items():
        ratios = bucket.pop("avg_capture_ratio")
        miss_pct = bucket.pop("netstats_missing_pct")
        output.append(
            {
                "package_name": pkg,
                "runs_total": bucket["runs_total"],
                "runs_included": bucket["runs_included"],
                "runs_excluded": bucket["runs_excluded"],
                "avg_capture_ratio": round(sum(ratios) / len(ratios), 3) if ratios else None,
                "avg_netstats_missing_pct": round(sum(miss_pct) / len(miss_pct), 3) if miss_pct else None,
            }
        )
    return output


def _derive_network_inclusion(row: Mapping[str, Any]) -> str:
    quality = row.get("network_signal_quality")
    if isinstance(quality, str) and quality:
        if quality == "netstats_ok":
            return "netstats_ok"
        if quality == "netstats_partial":
            return "netstats_partial"
        if quality == "netstats_missing":
            return "netstats_missing"
        if quality == "none":
            return "none"
        if quality == "netstats_zero_bytes":
            return "netstats_zero_bytes"
        if quality == "pcap_only":
            return "pcap_only"
    try:
        netstats_rows = int(row.get("netstats_rows") or 0)
        netstats_missing = int(row.get("netstats_missing_rows") or 0)
    except (TypeError, ValueError):
        netstats_rows = 0
        netstats_missing = 0
    try:
        sum_in = int(row.get("netstats_bytes_in_total") or 0)
        sum_out = int(row.get("netstats_bytes_out_total") or 0)
    except (TypeError, ValueError):
        sum_in = 0
        sum_out = 0
    if netstats_rows and (sum_in + sum_out) == 0:
        return "netstats_zero_bytes"
    if netstats_rows and netstats_missing:
        return "netstats_partial"
    if netstats_rows:
        return "netstats_ok"
    if netstats_missing:
        return "netstats_missing"
    return "none"


def _write_network_skipped(path: Path, *, reason: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"reason": reason}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _reset_telemetry_dir(telemetry_dir: Path) -> None:
    if not telemetry_dir.exists():
        return
    for path in telemetry_dir.iterdir():
        if path.is_file() and (path.suffix == ".csv" or path.name.endswith("_skipped.json")):
            path.unlink()


def _safe_ratio(captured: object, expected: object) -> float | None:
    try:
        cap = float(captured)
        exp = float(expected)
    except (TypeError, ValueError):
        return None
    if exp == 0:
        return None
    return round(cap / exp, 3)


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
    with path.open("w", newline="", encoding="utf-8") as handle:
        if not rows:
            return
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


def _fetch_netstats_totals(run_ids: list[str]) -> dict[str, dict[str, int]]:
    if not run_ids:
        return {}
    placeholders = ", ".join(["%s"] * len(run_ids))
    sql = f"""
        SELECT dynamic_run_id,
               SUM(COALESCE(bytes_in,0)) AS sum_in,
               SUM(COALESCE(bytes_out,0)) AS sum_out
        FROM dynamic_telemetry_network
        WHERE dynamic_run_id IN ({placeholders})
          AND source = 'netstats'
        GROUP BY dynamic_run_id
    """
    rows = core_q.run_sql(sql, tuple(run_ids), fetch="all", dictionary=True) or []
    totals: dict[str, dict[str, int]] = {}
    for row in rows:
        run_id = row.get("dynamic_run_id")
        if run_id:
            totals[str(run_id)] = {
                "sum_in": int(row.get("sum_in") or 0),
                "sum_out": int(row.get("sum_out") or 0),
            }
    return totals
