import pytest

from scytaledroid.StaticAnalysis.analytics.masvs_quality import compute_quality_metrics


def test_compute_quality_metrics_with_scores():
    entry = {
        "high": 2,
        "medium": 1,
        "low": 0,
        "info": 0,
        "control_count": 3,
        "cvss": {
            "worst_score": 9.0,
            "average_score": 8.0,
            "band_counts": {"Critical": 1, "High": 2},
            "scored_count": 3,
            "missing": 0,
            "total": 3,
        },
    }
    quality = compute_quality_metrics(entry)
    assert quality["severity_pressure"] == 13.0
    assert quality["cvss_coverage"] == 1.0
    assert quality["cvss_band_score"] == 0.83
    assert quality["cvss_intensity"] == 0.9
    assert quality["risk_index"] == 86.3
    assert quality["cvss_gap"] == 1.0
    assert quality["severity_density_norm"] == 0.867
    components = quality["risk_components"]
    assert components["inputs"]["severity_density_norm"] == 0.867
    assert components["contributions"]["severity"] + components["contributions"]["band"] + components["contributions"]["intensity"] == pytest.approx(quality["risk_index"], abs=0.2)


def test_compute_quality_metrics_handles_missing_cvss():
    entry = {
        "high": 0,
        "medium": 0,
        "low": 2,
        "info": 0,
        "control_count": 2,
        "cvss": {
            "scored_count": 0,
            "missing": 2,
            "total": 2,
        },
    }
    quality = compute_quality_metrics(entry)
    assert quality["cvss_coverage"] == 0.0
    assert quality["cvss_band_score"] == 0.0
    assert quality["cvss_intensity"] == 0.0
    assert quality["risk_index"] == 10.0
    assert quality["cvss_gap"] is None
    assert quality["severity_density_norm"] == 0.2
    components = quality["risk_components"]
    assert components["inputs"]["cvss_band_score"] == 0.0
    for value in components["contributions"].values():
        assert 0.0 <= value <= 100.0


def test_compute_quality_metrics_risk_index_is_bounded():
    entry = {
        "high": 50,
        "medium": 10,
        "low": 0,
        "info": 0,
        "control_count": 60,
        "cvss": {
            "worst_score": 10.0,
            "average_score": 10.0,
            "band_counts": {"Critical": 60},
            "scored_count": 60,
            "missing": 0,
            "total": 60,
        },
    }

    quality = compute_quality_metrics(entry)
    assert 0.0 <= quality["risk_index"] <= 100.0
