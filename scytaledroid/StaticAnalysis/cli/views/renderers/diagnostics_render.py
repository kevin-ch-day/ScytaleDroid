"""Diagnostics rendering helpers (inline MASVS summaries)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping

from scytaledroid.StaticAnalysis.analytics.masvs_quality import compute_quality_metrics

from ....core import StaticAnalysisReport
from ...core.cvss_v4 import score_vector, severity_band


def _extract_cvss_from_metrics(metrics: Mapping[str, object]) -> tuple[str | None, float | None]:
    """Return (vector, score) pair extracted from a finding's metrics mapping."""

    if not isinstance(metrics, Mapping):
        return None, None

    vector: str | None = None
    score: float | None = None

    vector_candidates = (
        metrics.get("cvss_v40_b_vector"),
        metrics.get("cvss_vector"),
        metrics.get("cvss"),
    )
    for candidate in vector_candidates:
        if isinstance(candidate, str) and candidate.startswith("CVSS:4.0/"):
            vector = candidate
            break

    score_candidates = (
        metrics.get("cvss_v40_b_score"),
        metrics.get("cvss_score"),
        metrics.get("cvss"),
    )
    for candidate in score_candidates:
        if isinstance(candidate, (int, float)):
            score = float(candidate)
            break
        if isinstance(candidate, str):
            try:
                score = float(candidate)
                break
            except ValueError:
                continue

    if score is None and vector:
        computed = score_vector(vector)
        if computed is not None:
            score = computed

    return vector, score


def summarise_masvs_inline(report: StaticAnalysisReport) -> Mapping[str, Mapping[str, object]]:
    areas = ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")
    summary: dict[str, dict[str, object]] = {}
    severity_map = {
        "P0": "High",
        "P1": "Medium",
        "P2": "Low",
        "NOTE": "Info",
    }

    for area in areas:
        summary[area] = {
            "counts": Counter({"High": 0, "Medium": 0, "Low": 0, "Info": 0}),
            "scores": [],
            "score_sum": 0.0,
            "bands": Counter(),
            "missing": 0,
        }

    for result in getattr(report, "detector_results", ()):  # type: ignore[attr-defined]
        findings = getattr(result, "findings", ())
        for finding in findings:
            area = getattr(finding, "category_masvs", None)
            area_name = area.value if hasattr(area, "value") else str(area or "")
            if area_name not in summary:
                continue
            severity = getattr(finding, "severity_gate", None)
            severity_name = severity.value if hasattr(severity, "value") else str(severity or "")
            sev_bucket = severity_map.get(severity_name, "Info")
            summary[area_name]["counts"][sev_bucket] += 1

            metrics = getattr(finding, "metrics", {})
            vector, score = _extract_cvss_from_metrics(metrics if isinstance(metrics, Mapping) else {})
            identifier = getattr(finding, "finding_id", None) or getattr(finding, "title", "")
            if score is not None:
                summary[area_name]["scores"].append((score, vector, identifier))
                summary[area_name]["score_sum"] += score
                band = severity_band(score) or "Unknown"
                summary[area_name]["bands"][band] += 1
            elif isinstance(metrics, Mapping) and any(
                key in metrics for key in ("cvss", "cvss_v40_b_vector", "cvss_v40_b_score")
            ):
                summary[area_name]["missing"] += 1

    for area in areas:
        data = summary[area]
        scores = data["scores"]
        if scores:
            worst_score, worst_vector, worst_identifier = max(scores, key=lambda item: item[0])
            data["worst"] = {
                "score": worst_score,
                "vector": worst_vector,
                "identifier": worst_identifier,
                "band": severity_band(worst_score),
            }
            count = len(scores)
            data["average"] = round(data["score_sum"] / count, 2)
        else:
            data["worst"] = None
            data["average"] = None
        data["total"] = len(scores) + data["missing"]

        counts = data["counts"]
        high = int(counts.get("High", 0))
        medium = int(counts.get("Medium", 0))
        low = int(counts.get("Low", 0))
        info = int(counts.get("Info", 0))
        control_count = high + medium + low + info
        worst_meta = data["worst"] or {}
        cvss_meta = {
            "worst_score": worst_meta.get("score"),
            "worst_vector": worst_meta.get("vector"),
            "worst_identifier": worst_meta.get("identifier"),
            "worst_severity": worst_meta.get("band"),
            "average_score": data.get("average"),
            "band_counts": dict(data.get("bands", {})),
            "scored_count": len(scores),
            "missing": data.get("missing", 0),
            "total": data.get("total", 0),
        }
        data["high"] = high
        data["medium"] = medium
        data["low"] = low
        data["info"] = info
        data["control_count"] = control_count
        data["cvss"] = cvss_meta
        data["quality"] = compute_quality_metrics(data)

    return summary


__all__ = ["summarise_masvs_inline"]
