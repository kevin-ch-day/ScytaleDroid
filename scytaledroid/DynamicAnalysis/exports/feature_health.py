"""Feature health reporting for exported telemetry."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ColumnStats:
    total: int = 0
    numeric: int = 0
    missing: int = 0
    zeros: int = 0
    sum_value: float = 0.0
    sum_sq: float = 0.0

    def add(self, value: str | None) -> None:
        self.total += 1
        if value is None or value == "":
            self.missing += 1
            return
        try:
            numeric_value = float(value)
        except ValueError:
            self.missing += 1
            return
        self.numeric += 1
        self.sum_value += numeric_value
        self.sum_sq += numeric_value * numeric_value
        if numeric_value == 0:
            self.zeros += 1

    def variance(self) -> float | None:
        if self.numeric == 0:
            return None
        mean = self.sum_value / self.numeric
        return max((self.sum_sq / self.numeric) - (mean * mean), 0.0)

    def missing_pct(self) -> float | None:
        if self.total == 0:
            return None
        return round(self.missing / self.total, 4)

    def zero_pct(self) -> float | None:
        if self.total == 0:
            return None
        return round(self.zeros / self.total, 4)


def build_feature_health_report(
    telemetry_dir: Path,
    output_dir: Path,
    *,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    column_stats: dict[str, ColumnStats] = {}
    csv_files = sorted(telemetry_dir.glob("*.csv"))
    for csv_path in csv_files:
        with csv_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                for key, value in row.items():
                    stats = column_stats.setdefault(key, ColumnStats())
                    stats.add(value)

    metrics: dict[str, dict[str, Any]] = {}
    degenerate: dict[str, dict[str, Any]] = {}
    for column, stats in column_stats.items():
        variance = stats.variance()
        missing_pct = stats.missing_pct()
        zero_pct = stats.zero_pct()
        if stats.numeric == 0:
            continue
        metrics[column] = {
            "missing_pct": missing_pct,
            "zero_pct": zero_pct,
            "variance": variance,
            "numeric_samples": stats.numeric,
            "total_samples": stats.total,
        }
        if variance == 0 or (zero_pct is not None and zero_pct >= 0.99):
            degenerate[column] = metrics[column]

    core_columns = {"bytes_in", "bytes_out"}
    core_degenerate = {name: info for name, info in degenerate.items() if name in core_columns}
    status = "PASS"
    if core_degenerate:
        status = "FAIL"
    elif degenerate:
        status = "WARN"

    report = {
        "status": status,
        "core_degenerate": core_degenerate,
        "degenerate": degenerate,
        "metrics": metrics,
        "telemetry_files": [path.name for path in csv_files],
    }
    if manifest_path and manifest_path.exists():
        report["pcap_bytes"] = _summarize_pcap_bytes(manifest_path)

    gate = _gate_core_features(metrics, core_columns)
    report["gating"] = gate

    json_path = output_dir / "feature_health.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    md_path = output_dir / "feature_health.md"
    md_path.write_text(_render_markdown(report), encoding="utf-8")

    return {"status": status, "json_path": json_path, "md_path": md_path, "gating": gate}


def _render_markdown(report: dict[str, Any]) -> str:
    lines = ["# Feature Health Report", "", f"Status: **{report.get('status')}**", ""]
    core = report.get("core_degenerate") or {}
    if core:
        lines.append("## Core feature issues")
        for name, info in core.items():
            lines.append(f"- **{name}**: zero_pct={info.get('zero_pct')}, variance={info.get('variance')}")
        lines.append("")
    degenerate = report.get("degenerate") or {}
    if degenerate:
        lines.append("## Degenerate features")
        for name, info in degenerate.items():
            lines.append(f"- {name}: zero_pct={info.get('zero_pct')}, variance={info.get('variance')}")
        lines.append("")
    gating = report.get("gating") or {}
    if gating:
        lines.append("## Gating")
        lines.append(f"- status={gating.get('status')}")
        failed = gating.get("failed_features") or []
        if failed:
            lines.append(f"- failed_features={', '.join(failed)}")
        lines.append("")
    pcap_summary = report.get("pcap_bytes")
    if isinstance(pcap_summary, dict) and pcap_summary.get("count"):
        lines.append("## PCAP bytes (manifest cross-check)")
        lines.append(
            f"- count={pcap_summary.get('count')}, "
            f"total_bytes={pcap_summary.get('total_bytes')}, "
            f"avg_bytes={pcap_summary.get('avg_bytes')}"
        )
        lines.append("")
    lines.append("## Metrics (numeric columns)")
    for name, info in sorted((report.get("metrics") or {}).items()):
        lines.append(
            f"- {name}: missing_pct={info.get('missing_pct')}, zero_pct={info.get('zero_pct')}, "
            f"variance={info.get('variance')}"
        )
    lines.append("")
    return "\n".join(lines)


def _summarize_pcap_bytes(manifest_path: Path) -> dict[str, Any]:
    total_bytes = 0
    count = 0
    with manifest_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            value = row.get("pcap_bytes")
            if value in (None, ""):
                continue
            try:
                total_bytes += int(float(value))
                count += 1
            except ValueError:
                continue
    if count == 0:
        return {"count": 0, "total_bytes": 0, "avg_bytes": None}
    return {"count": count, "total_bytes": total_bytes, "avg_bytes": int(total_bytes / count)}


def _gate_core_features(
    metrics: dict[str, dict[str, Any]],
    core_columns: set[str],
    *,
    zero_threshold: float = 0.99,
    variance_threshold: float = 0.0,
) -> dict[str, Any]:
    failed: list[str] = []
    for column in sorted(core_columns):
        info = metrics.get(column)
        if not info:
            failed.append(column)
            continue
        zero_pct = info.get("zero_pct")
        variance = info.get("variance")
        if zero_pct is not None and zero_pct >= zero_threshold:
            failed.append(column)
        elif variance is not None and variance <= variance_threshold:
            failed.append(column)
    return {
        "status": "FAIL" if failed else "PASS",
        "failed_features": failed,
        "zero_threshold": zero_threshold,
        "variance_threshold": variance_threshold,
    }


__all__ = ["build_feature_health_report"]
