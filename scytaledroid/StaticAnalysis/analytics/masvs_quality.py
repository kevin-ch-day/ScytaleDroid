"""Derive qualitative MASVS metrics from severity and CVSS aggregates."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping

__all__ = [
    "compute_quality_metrics",
    "SEVERITY_WEIGHTS",
    "BAND_WEIGHTS",
    "RISK_COMPONENT_WEIGHTS",
]

SEVERITY_WEIGHTS: Mapping[str, float] = {
    "high": 5.0,
    "medium": 3.0,
    "low": 1.0,
    "info": 0.0,
}

BAND_WEIGHTS: Mapping[str, float] = {
    "Critical": 1.0,
    "High": 0.75,
    "Medium": 0.5,
    "Low": 0.2,
    "None": 0.0,
    "Unknown": 0.0,
}


RISK_COMPONENT_WEIGHTS: Mapping[str, float] = {
    "severity": 0.5,
    "band": 0.3,
    "intensity": 0.2,
}


def _coerce_int(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return 0


def _coerce_float(value: object) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return 0.0


def compute_quality_metrics(entry: Mapping[str, object]) -> MutableMapping[str, float | int | None]:
    """Return derived quality indicators for a MASVS area summary."""

    high = _coerce_int(entry.get("high"))
    medium = _coerce_int(entry.get("medium"))
    low = _coerce_int(entry.get("low"))
    info = _coerce_int(entry.get("info"))
    total_findings = high + medium + low + info
    control_count = _coerce_int(entry.get("control_count"))
    if control_count <= 0 and total_findings:
        control_count = high + medium + low + info
    elif control_count <= 0:
        return {
            "severity_pressure": 0.0,
            "severity_density": 0.0,
            "severity_density_norm": 0.0,
            "cvss_coverage": None,
            "cvss_band_score": 0.0,
            "cvss_intensity": 0.0,
            "risk_index": None,
            "cvss_gap": None,
            "scored_count": 0,
            "control_count": 0,
            "coverage_status": "no_data",
            "risk_components": {
                "inputs": {
                    "severity_density_norm": 0.0,
                    "cvss_band_score": 0.0,
                    "cvss_intensity": 0.0,
                },
                "weights": dict(RISK_COMPONENT_WEIGHTS),
                "contributions": {
                    "severity": 0.0,
                    "band": 0.0,
                    "intensity": 0.0,
                },
            },
        }

    severity_pressure = (
        high * SEVERITY_WEIGHTS["high"]
        + medium * SEVERITY_WEIGHTS["medium"]
        + low * SEVERITY_WEIGHTS["low"]
    )
    severity_density = severity_pressure / control_count if control_count else 0.0
    severity_density_norm = min(severity_density / SEVERITY_WEIGHTS["high"], 1.0)

    cvss_meta = entry.get("cvss") if isinstance(entry.get("cvss"), Mapping) else {}
    worst_score = _coerce_float(cvss_meta.get("worst_score")) if cvss_meta else 0.0
    avg_score = (
        _coerce_float(cvss_meta.get("average_score")) if cvss_meta else 0.0
    )
    scored_count = _coerce_int(cvss_meta.get("scored_count")) if cvss_meta else 0
    missing = _coerce_int(cvss_meta.get("missing")) if cvss_meta else 0
    total_vectorised = _coerce_int(cvss_meta.get("total")) if cvss_meta else 0
    if total_vectorised <= 0:
        total_vectorised = scored_count + missing
    if total_vectorised <= 0:
        total_vectorised = control_count
    if total_vectorised <= 0:
        total_vectorised = 1

    cvss_coverage = scored_count / total_vectorised

    band_counts = cvss_meta.get("band_counts") if isinstance(cvss_meta, Mapping) else {}
    band_score_total = 0.0
    if isinstance(band_counts, Mapping):
        for band, weight in BAND_WEIGHTS.items():
            band_score_total += weight * _coerce_int(band_counts.get(band))
    cvss_band_score = band_score_total / scored_count if scored_count else 0.0
    cvss_band_score = min(cvss_band_score, 1.0)

    cvss_intensity = worst_score / 10.0 if worst_score else 0.0

    severity_weight = RISK_COMPONENT_WEIGHTS["severity"]
    band_weight = RISK_COMPONENT_WEIGHTS["band"]
    intensity_weight = RISK_COMPONENT_WEIGHTS["intensity"]

    severity_component = severity_density_norm * severity_weight
    band_component = cvss_band_score * band_weight
    intensity_component = cvss_intensity * intensity_weight

    raw_risk = severity_component + band_component + intensity_component
    risk_index = round(min(max(raw_risk, 0.0), 1.0) * 100, 1)

    cvss_gap = None
    if scored_count:
        cvss_gap = round(worst_score - avg_score, 2)

    risk_components = {
        "inputs": {
            "severity_density_norm": round(severity_density_norm, 3),
            "cvss_band_score": round(cvss_band_score, 3),
            "cvss_intensity": round(cvss_intensity, 3),
        },
        "weights": {
            "severity": severity_weight,
            "band": band_weight,
            "intensity": intensity_weight,
        },
        "contributions": {
            "severity": round(severity_component * 100, 1),
            "band": round(band_component * 100, 1),
            "intensity": round(intensity_component * 100, 1),
        },
    }

    return {
        "severity_pressure": round(severity_pressure, 2),
        "severity_density": round(severity_density, 2),
        "severity_density_norm": round(severity_density_norm, 3),
        "cvss_coverage": round(cvss_coverage, 2),
        "cvss_band_score": round(cvss_band_score, 2),
        "cvss_intensity": round(cvss_intensity, 2),
        "risk_index": risk_index,
        "cvss_gap": cvss_gap,
        "scored_count": scored_count,
        "control_count": control_count,
        "coverage_status": "findings_based",
        "risk_components": risk_components,
    }