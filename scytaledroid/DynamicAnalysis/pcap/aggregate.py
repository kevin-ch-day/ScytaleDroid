"""Aggregate PCAP features into a single CSV dataset."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config


def export_pcap_features_csv() -> Path | None:
    output_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not output_root.exists():
        return None
    rows: list[dict[str, Any]] = []
    for run_dir in output_root.iterdir():
        if not run_dir.is_dir():
            continue
        features_path = run_dir / "analysis" / "pcap_features.json"
        manifest_path = run_dir / "run_manifest.json"
        if not features_path.exists() or not manifest_path.exists():
            continue
        try:
            features = json.loads(features_path.read_text(encoding="utf-8"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        row = _flatten_features(features)
        row.update(
            {
                "dynamic_run_id": manifest.get("dynamic_run_id"),
                "package_name": (manifest.get("target") or {}).get("package_name"),
                "scenario": (manifest.get("scenario") or {}).get("id"),
                "started_at": manifest.get("started_at"),
                "ended_at": manifest.get("ended_at"),
                "tier": (manifest.get("operator") or {}).get("tier"),
            }
        )
        rows.append(row)
    if not rows:
        return None
    dest = Path(app_config.DATA_DIR) / "archive" / "pcap_features.csv"
    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_csv(dest, rows)
    return dest


def export_dynamic_run_summary_csv() -> Path | None:
    output_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not output_root.exists():
        return None
    rows: list[dict[str, Any]] = []
    for run_dir in output_root.iterdir():
        if not run_dir.is_dir():
            continue
        manifest = _load_json(run_dir / "run_manifest.json")
        summary = _load_json(run_dir / "analysis" / "summary.json")
        overlap = _load_json(run_dir / "analysis" / "static_dynamic_overlap.json")
        report = _load_json(run_dir / "analysis" / "pcap_report.json")
        features = _load_json(run_dir / "analysis" / "pcap_features.json")
        if not manifest or not summary or not report or not features:
            continue
        row = _build_run_summary_row(manifest, summary, report, overlap, features)
        if row:
            rows.append(row)
    if not rows:
        return None
    dest = Path(app_config.DATA_DIR) / "archive" / "dynamic_run_summary.csv"
    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_csv(dest, rows)
    return dest


def _flatten_features(features: dict[str, Any]) -> dict[str, Any]:
    row = {}
    for group in ("metrics", "proxies", "quality"):
        values = features.get(group) or {}
        if not isinstance(values, dict):
            continue
        for key, value in values.items():
            if isinstance(value, (list, dict)):
                row[f"{group}_{key}"] = json.dumps(value, sort_keys=True)
            else:
                row[f"{group}_{key}"] = value
    return row


def _build_run_summary_row(
    manifest: dict[str, Any],
    summary: dict[str, Any],
    report: dict[str, Any],
    overlap: dict[str, Any] | None,
    features: dict[str, Any],
) -> dict[str, Any] | None:
    target = manifest.get("target") or {}
    telemetry = summary.get("telemetry") or {}
    stats = telemetry.get("stats") or {}
    capture = summary.get("capture") or {}
    metrics = (features.get("metrics") or {}) if isinstance(features.get("metrics"), dict) else {}
    overlap_sources = (overlap or {}).get("overlap_by_source") or {}
    overlap_nsc = _overlap_ratio_for_source(overlap_sources, "nsc")
    overlap_strings = _overlap_ratio_for_source(overlap_sources, "strings")
    proto = report.get("protocol_hierarchy") or []
    quic_ratio = _protocol_ratio(proto, "quic")
    tls_ratio = _protocol_ratio(proto, "tls")
    unique_domains = _unique_domains(report)
    return {
        "app": target.get("package_name"),
        "run_id": manifest.get("dynamic_run_id"),
        "sampling_duration_seconds": stats.get("sampling_duration_seconds"),
        "pcap_valid": capture.get("pcap_valid"),
        "overlap_ratio": (overlap or {}).get("overlap_ratio"),
        "overlap_ratio_nsc": overlap_nsc,
        "overlap_ratio_strings": overlap_strings,
        "dynamic_only_ratio": (overlap or {}).get("dynamic_only_ratio"),
        "bytes_per_sec": metrics.get("data_byte_rate_bps"),
        "packets_per_sec": metrics.get("avg_packet_rate_pps"),
        "quic_ratio": quic_ratio,
        "tls_ratio": tls_ratio,
        "unique_domains": unique_domains,
    }


def _protocol_ratio(rows: list[dict[str, Any]], protocol: str) -> float | None:
    if not rows:
        return None
    total = 0
    matched = 0
    for row in rows:
        try:
            bytes_count = int(row.get("bytes") or 0)
        except (TypeError, ValueError):
            bytes_count = 0
        total += bytes_count
        if str(row.get("protocol") or "").lower() == protocol:
            matched += bytes_count
    if total <= 0:
        return None
    return matched / float(total)


def _unique_domains(report: dict[str, Any]) -> int | None:
    domains = set()
    for item in report.get("top_sni") or []:
        value = item.get("value")
        if value:
            domains.add(str(value).strip())
    for item in report.get("top_dns") or []:
        value = item.get("value")
        if value:
            domains.add(str(value).strip())
    return len(domains) if domains else None


def _overlap_ratio_for_source(sources: dict[str, Any], source: str) -> float | None:
    payload = sources.get(source)
    if not isinstance(payload, dict):
        return None
    ratio = payload.get("overlap_ratio")
    if isinstance(ratio, (int, float)):
        return float(ratio)
    return None


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = sorted({key for row in rows for key in row.keys()})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


__all__ = ["export_pcap_features_csv", "export_dynamic_run_summary_csv"]
