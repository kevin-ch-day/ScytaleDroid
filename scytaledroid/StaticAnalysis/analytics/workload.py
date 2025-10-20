"""Workload profiling helpers for detector pipelines."""

from __future__ import annotations

import math
from collections import defaultdict
from statistics import mean, median
from typing import Mapping, MutableMapping, Sequence

from ..core.findings import DetectorResult


def build_workload_profile(
    results: Sequence[DetectorResult],
) -> Mapping[str, object]:
    """Return detector load classifications and throughput indicators."""

    durations = [float(result.duration_sec or 0.0) for result in results if result.duration_sec]
    findings_per_detector = {result.detector_id: len(result.findings) for result in results}
    total_findings = sum(findings_per_detector.values())
    total_duration = sum(durations)

    section_totals: MutableMapping[str, MutableMapping[str, float]] = defaultdict(lambda: defaultdict(float))
    for result in results:
        section = result.section_key or result.detector_id
        section_totals[section]["duration_sec"] += float(result.duration_sec or 0.0)
        section_totals[section]["findings"] += len(result.findings)

    sorted_durations = sorted(durations)
    p50 = _percentile(sorted_durations, 50)
    p90 = _percentile(sorted_durations, 90)

    detector_load: dict[str, Mapping[str, object]] = {}
    for result in results:
        duration = float(result.duration_sec or 0.0)
        bucket = _classify_duration(duration, p50, p90)
        detector_load[result.detector_id or "unknown"] = {
            "duration_sec": round(duration, 3),
            "finding_count": len(result.findings),
            "status": bucket,
        }

    summary: dict[str, object] = {
        "total_duration_sec": round(total_duration, 3),
        "total_findings": int(total_findings),
        "detector_count": len(results),
    }
    if durations:
        summary["mean_duration_sec"] = round(mean(durations), 3)
        summary["median_duration_sec"] = round(median(durations), 3)
        summary["p90_duration_sec"] = round(p90, 3)
        throughput = (total_findings / total_duration) if total_duration else 0.0
        summary["findings_per_second"] = round(throughput, 3)

    sections_serialised = {
        key: {
            "duration_sec": round(values["duration_sec"], 3),
            "finding_count": int(values["findings"]),
        }
        for key, values in section_totals.items()
        if values["duration_sec"] or values["findings"]
    }

    return {
        "summary": summary,
        "detector_load": detector_load,
        "section_totals": sections_serialised,
    }


def _classify_duration(duration: float, p50: float, p90: float) -> str:
    if duration <= 0:
        return "idle"
    if p90 and duration >= p90:
        return "critical"
    if p50 and duration >= p50:
        return "elevated"
    return "baseline"


def _percentile(data: Sequence[float], percentile: float) -> float:
    if not data:
        return 0.0
    if percentile <= 0:
        return float(data[0])
    if percentile >= 100:
        return float(data[-1])
    k = (len(data) - 1) * (percentile / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(data[int(k)])
    d0 = data[f] * (c - k)
    d1 = data[c] * (k - f)
    return float(d0 + d1)


__all__ = ["build_workload_profile"]
