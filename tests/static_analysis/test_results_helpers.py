from __future__ import annotations

from collections import Counter

import pytest
from scytaledroid.StaticAnalysis.cli.execution import analytics, results, results_formatters


@pytest.mark.unit
def test_dedupe_profile_entries_removes_duplicate_packages():
    entries = [
        {"package": "pkg.alpha", "value": 1},
        {"package": "pkg.alpha", "value": 2},
        {"label": "Alias"},
        {"label": "Alias", "value": 3},
        {"package_name": "pkg.beta"},
        {"value": 5},
    ]

    deduped = results._dedupe_profile_entries(entries)

    assert len(deduped) == 4  # pkg.alpha, Alias, pkg.beta, anonymous entry
    assert deduped[0]["value"] == 1
    assert {
        entry.get("package") or entry.get("label") or entry.get("package_name")
        for entry in deduped[:-1]
    } == {
        "pkg.alpha",
        "Alias",
        "pkg.beta",
    }


@pytest.mark.unit
def test_format_highlight_tokens_prefers_provider_count():
    stats = {"providers": 37, "nsc_guard": 9, "secrets_suppressed": 0}
    totals = {"high": 0, "critical": 0}

    tokens = results_formatters._format_highlight_tokens(stats, totals, app_count=8)

    assert tokens[0].startswith("37 exported provider")


@pytest.mark.unit
def test_format_highlight_tokens_falls_back_to_high_findings():
    stats = {"providers": 0, "nsc_guard": 0, "secrets_suppressed": 0}
    totals = {"high": 2, "critical": 0}

    tokens = results_formatters._format_highlight_tokens(stats, totals, app_count=5)

    assert "high-severity" in tokens[0]


@pytest.mark.unit
def test_collect_component_stats_counts_exports():
    class FakeExports:
        activities = [1, 2]
        services = [1]
        receivers = []
        providers = [1]

    class FakeManifest:
        app_label = "Discord"
        package_name = "pkg.alpha"

    class FakeReport:
        manifest = FakeManifest()
        exported_components = FakeExports()

    stats = analytics._collect_component_stats(FakeReport())

    assert stats == {
        "package": "pkg.alpha",
        "label": "Discord",
        "activities": 2,
        "services": 1,
        "receivers": 0,
        "providers": 1,
    }


@pytest.mark.unit
def test_collect_secret_stats_aggregates_samples():
    payload = {
        "counts": {"api_keys": 2, "high_entropy": 3},
        "samples": {
            "api_keys": [
                {"risk_tag": "token_candidate", "provider": "aws"},
                {"risk_tag": "token_candidate", "provider": "aws"},
            ],
            "high_entropy": [
                {"risk_tag": "entropy_hit", "provider": "custom"}
            ],
        },
    }

    class FakeManifest:
        app_label = "Label"
        package_name = "pkg.alpha"

    class FakeReport:
        manifest = FakeManifest()

    stats = analytics._collect_secret_stats(payload, FakeReport())

    assert stats["package"] == "pkg.alpha"
    assert stats["api_keys"] == 2
    assert stats["high_entropy"] == 3
    assert stats["risk_tags"]["token_candidate"] == 2


@pytest.mark.unit
def test_compute_trend_delta_returns_differences(monkeypatch):
    previous = {"session_stamp": "20251020-000000", "high": 1, "med": 2, "low": 3}

    monkeypatch.setattr(analytics.core_q, "run_sql", lambda *args, **kwargs: previous)

    totals = Counter({"High": 3, "Medium": 5, "Low": 7})

    delta = analytics._compute_trend_delta("pkg.alpha", "20251026-202635", totals)

    assert delta == {
        "package": "pkg.alpha",
        "previous_session": "20251020-000000",
        "delta_high": 2,
        "delta_medium": 3,
        "delta_low": 4,
    }


@pytest.mark.unit
def test_compute_trend_delta_handles_missing_previous(monkeypatch):
    monkeypatch.setattr(analytics.core_q, "run_sql", lambda *args, **kwargs: None)
    totals = Counter({"High": 1})

    assert analytics._compute_trend_delta("pkg.alpha", "20251026-202635", totals) is None
