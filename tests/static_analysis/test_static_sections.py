from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.persistence import static_sections


def test_baseline_severity_counts_prefers_baseline_findings_over_external_totals():
    counts = static_sections._baseline_severity_counts(
        {"High": 33, "Medium": 451, "Low": 34, "Info": 1},
        [
            {"severity": "Medium"},
            {"severity": "Medium"},
            {"severity": "Low"},
            {"severity": "Info"},
        ],
    )

    assert counts == {
        "High": 0,
        "Medium": 2,
        "Low": 1,
        "Info": 1,
    }


def test_baseline_severity_counts_falls_back_when_no_findings_present():
    counts = static_sections._baseline_severity_counts(
        {"High": 1, "Medium": 2, "Low": 3, "Info": 4},
        None,
    )

    assert counts == {
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Info": 4,
    }
