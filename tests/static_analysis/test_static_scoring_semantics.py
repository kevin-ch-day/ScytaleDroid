from __future__ import annotations

import inspect
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.execution import analytics
from scytaledroid.StaticAnalysis.cli.execution.analytics import static_exposure_grade
from scytaledroid.StaticAnalysis.detectors.correlation.scoring import risk_finding
from scytaledroid.StaticAnalysis.reporting.html import render_html_report
from scytaledroid.StaticAnalysis.risk import compute_risk_assessment


def test_static_exposure_grade_is_named_separately_from_permission_grades() -> None:
    assert static_exposure_grade(1.0) == "Minimal"
    assert static_exposure_grade(3.0) == "Low"
    assert static_exposure_grade(5.5) == "Moderate"
    assert static_exposure_grade(7.5) == "Elevated"
    assert static_exposure_grade(9.0) == "High"


def test_broader_static_composite_no_longer_uses_permission_grade_helper() -> None:
    source = inspect.getsource(analytics._build_static_risk_row)  # noqa: SLF001 - contract test
    assert "permission_risk_grade(score_0_10)" not in source
    assert "static_exposure_grade(score_0_10)" in source


def test_html_report_labels_risk_as_heuristic_indicator_surface() -> None:
    html = render_html_report(
        {
            "app": {"name": "Example", "package": "com.example.app", "version_name": "1.0", "version_code": "1", "main_activity": "Main"},
            "identity": {"size_human": "1 B", "size_bytes": 1, "hashes": {"md5": "m", "sha1": "s", "sha256": "z"}},
            "result": {"badge": "OK", "badge_class": "ok", "p0": 0, "p1": 0, "p2": 0},
            "topology": {"modules": {"base": True, "config": []}, "dex_count": 1, "resource_asset_count": 0},
            "permissions": [],
            "indicators": {"hosts": [], "ips": [], "ws": [], "interesting": []},
            "network": {"host_hashes_csv": "—", "http_count": 0, "https_count": 0, "ws_count": 0, "uses_cleartext": False, "nsc": "—", "pinning": "—"},
            "secrets": [],
            "risk": {
                "title": "Selected static risk indicators",
                "score": 25,
                "band": "Low",
                "top_factors": ["cleartext traffic"],
                "surface_kind": "heuristic_static_indicator_summary",
                "is_canonical_app_risk": False,
            },
            "run": {"timestamp_utc": "2026-06-12 12:00", "profile": "full", "verbosity": "summary", "evidence_limit": 2, "toolchain": {}, "seed": "abc", "version": "test"},
        }
    )

    assert "Selected static risk indicators" in html
    assert "Heuristic surface: heuristic_static_indicator_summary" in html
    assert "Permission band" in html
    assert "<th>Risk</th>" not in html
    assert "<h2>Risk</h2>" not in html


def test_correlation_priority_finding_is_marked_synthetic_not_canonical() -> None:
    finding = risk_finding({"score": 180, "grade": "High"})

    assert finding.title == "Correlation priority — High"
    assert "synthetic prioritization signal" in finding.because
    assert finding.metrics["surface_kind"] == "correlation_priority"
    assert finding.metrics["finding_kind"] == "synthetic_prioritization"
    assert finding.metrics["is_canonical_app_risk"] is False


def test_composite_risk_scoring_prefers_permission_band_field() -> None:
    report = SimpleNamespace(
        manifest_flags=SimpleNamespace(uses_cleartext_traffic=False),
        permissions=SimpleNamespace(declared=set()),
    )

    assessment = compute_risk_assessment(
        permissions=[
            {"name": "android.permission.CAMERA", "band": "High"},
            {"name": "android.permission.INTERNET", "risk": "Low"},
        ],
        secrets=[],
        network={},
        report=report,
    )

    assert assessment.score == 5
    assert assessment.band == "Low"
    assert assessment.factors[0].label == "high-risk permissions"
