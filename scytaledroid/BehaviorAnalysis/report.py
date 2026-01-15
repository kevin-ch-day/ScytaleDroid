"""Report generation for behavior sessions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Sequence

import matplotlib.pyplot as plt


def write_anomaly_plot(windows: List[Dict[str, object]], scores: List[Dict[str, object]], plot_path: Path) -> None:
    times = [row.get("window_end_utc") for row in windows]
    score_map = {}
    for score in scores:
        key = score.get("window_end_utc")
        score_map.setdefault(key, []).append(float(score.get("score", 0.0)))
    values = [max(score_map.get(t, [0.0])) for t in times]
    plt.figure(figsize=(10, 4))
    plt.plot(times, values, marker="o")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plot_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(plot_path)
    plt.close()


def build_behavior_report(
    metadata: Dict[str, object],
    markers: Sequence[Dict[str, object]],
    windows: Sequence[Dict[str, object]],
    scores: Sequence[Dict[str, object]],
    plot_path: Path,
    report_path: Path,
) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    lines: List[str] = []
    lines.append("# Behavior Analysis Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("- Behavior session completed.")
    if metadata.get("best_effort_network"):
        lines.append("- Network telemetry: best effort (aggregate characteristics only).")
    lines.append("")
    lines.append("## Reproducibility")
    lines.append(f"- Session: {metadata.get('session_id')}")
    lines.append(f"- Package: {metadata.get('package')}")
    lines.append(f"- Scenario: {metadata.get('scenario')}")
    lines.append(f"- Device: {metadata.get('device')}")
    lines.append(f"- UID: {metadata.get('uid')}")
    lines.append(f"- Sampling: {metadata.get('sample_rate_s')}s; window {metadata.get('window_length_s')}s / step {metadata.get('window_step_s')}s")
    lines.append(f"- Feature schema: {metadata.get('feature_schema_version')}")
    lines.append(f"- Model backend: {metadata.get('model_backend')}")
    lines.append(f"- Training mode: {metadata.get('training_mode')} ({metadata.get('threshold_policy')})")
    lines.append(f"- Git: {metadata.get('git_commit')}")
    lines.append(f"- Start UTC: {metadata.get('start_utc')}")
    lines.append(f"- End UTC: {metadata.get('end_utc')}")
    ns = metadata.get("network_source_summary", {})
    lines.append(f"- Network source summary: {ns}")
    lines.append(f"- Missed samples: {metadata.get('missed_sample_count')}")
    hashes = metadata.get("device", {}).get("apk_hashes") if isinstance(metadata.get("device"), dict) else metadata.get("apk_hashes")
    if hashes:
        lines.append(f"- APK hashes: md5={hashes.get('md5')}, sha1={hashes.get('sha1')}, sha256={hashes.get('sha256')}")
    lines.append("")
    lines.append("## Data Quality")
    lines.append(f"- Process available: {metadata.get('collector_capabilities', {}).get('process_available')}")
    lines.append(f"- Network available: {metadata.get('collector_capabilities', {}).get('network_available')} (best_effort={metadata.get('best_effort_network')})")
    lines.append(f"- Events available: {metadata.get('collector_capabilities', {}).get('events_available')}")
    lines.append(f"- Network source summary: {ns}")
    lines.append(f"- Missed samples: {metadata.get('missed_sample_count')}")
    ns = metadata.get("network_source_summary", {})
    lines.append(f"- Network source summary: {ns}")
    lines.append(f"- Missed samples: {metadata.get('missed_sample_count')}")
    lines.append("")
    lines.append("## Data Quality")
    lines.append(f"- Process available: {metadata.get('collector_capabilities', {}).get('process_available')}")
    lines.append(f"- Network available: {metadata.get('collector_capabilities', {}).get('network_available')} (best_effort={metadata.get('best_effort_network')})")
    lines.append(f"- Events available: {metadata.get('collector_capabilities', {}).get('events_available')}")
    lines.append(f"- Network source summary: {ns}")
    lines.append(f"- Missed samples: {metadata.get('missed_sample_count')}")
    lines.append("")
    lines.append("## Top Anomalous Windows")
    lines.append("| Start | End | Score | Model | Marker | Δs |")
    lines.append("|---|---|---|---|---|---|")
    top = sorted(scores, key=lambda s: float(s.get("score", 0.0)), reverse=True)[:5]
    for row in top:
        lines.append(
            f"| {row.get('window_start_utc','')} | {row.get('window_end_utc','')} | {row.get('score','')} | {row.get('model_name','')} | {row.get('marker_nearest','')} | {row.get('marker_delta_s','')} |"
        )
    lines.append("")
    lines.append("## Plots")
    lines.append(f"- Anomaly timeline: {plot_path}")
    lines.append("")
    lines.append("## Interpretation Notes")
    lines.append("- Higher scores indicate behavioral deviation; anomalies are not proof of malware.")
    lines.append("- Network metrics are aggregate and best-effort; payload/destination not inspected.")
    lines.append("- Use scenario context and markers when interpreting anomalies.")
    if metadata.get("model_backend") == "fallback":
        lines.append("- Fallback model used (heuristic z-score over CPU/network).")

    report_path.write_text("\n".join(lines), encoding="utf-8")
