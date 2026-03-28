from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from scytaledroid.StaticAnalysis.cli.execution import analytics, results, results_formatters
from scytaledroid.StaticAnalysis.cli.core.models import (
    AppRunResult,
    ArtifactOutcome,
    RunOutcome,
    RunParameters,
    ScopeSelection,
)
from scytaledroid.StaticAnalysis.cli.core.run_context import StaticRunContext


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


@pytest.mark.unit
def test_format_masvs_cell_renders_na_for_missing_area():
    assert results_formatters._format_masvs_cell(None) == "N/A"


@pytest.mark.unit
def test_collect_masvs_profile_keeps_missing_areas_absent():
    class FakeCategory:
        value = "PLATFORM"

    class FakeGate:
        value = "P1"

    class FakeFinding:
        category_masvs = FakeCategory()
        severity_gate = FakeGate()
        title = "Exported activity without permission"
        finding_id = "platform_exported_activity"

    class FakeResult:
        findings = [FakeFinding()]
        detector_id = "ipc_components"

    class FakeReport:
        detector_results = [FakeResult()]

    profile = analytics._collect_masvs_profile(FakeReport())
    counts = profile.get("counts")
    assert isinstance(counts, dict)
    assert "PLATFORM" in counts
    assert "NETWORK" not in counts
    assert "PRIVACY" not in counts
    assert "STORAGE" not in counts


@pytest.mark.unit
def test_build_static_risk_row_uses_composite_grade_not_permission_grade():
    class FakeExports:
        def total(self):
            return 4

    class FakeFlags:
        uses_cleartext_traffic = False
        request_legacy_external_storage = False

    class FakePermissions:
        declared = ("android.permission.INTERNET",)

    class FakeManifest:
        package_name = "pkg.alpha"
        app_label = "Alpha"

    class FakeReport:
        exported_components = FakeExports()
        manifest_flags = FakeFlags()
        permissions = FakePermissions()
        manifest = FakeManifest()

    class FakeApp:
        package_name = "pkg.alpha"

    row = analytics._build_static_risk_row(
        FakeReport(),
        {
            "counts": {"endpoints": 3, "http_cleartext": 0, "high_entropy": 0},
            "aggregates": {"endpoint_roots": ["example.com"], "api_keys_high": []},
        },
        {"grade": "F", "risk": 0.8, "label": "Alpha"},
        FakeApp(),
    )

    assert row["grade"] != "F"
    assert row["network"] == 4.0


@pytest.mark.unit
def test_build_static_risk_row_component_points_do_not_saturate_immediately():
    class FakeExports:
        def __init__(self, n: int) -> None:
            self._n = n

        def total(self):
            return self._n

    class FakeFlags:
        uses_cleartext_traffic = False
        request_legacy_external_storage = False

    class FakePermissions:
        declared = ()

    class FakeManifest:
        package_name = "pkg.alpha"
        app_label = "Alpha"

    class FakeReport:
        def __init__(self, n: int) -> None:
            self.exported_components = FakeExports(n)
            self.manifest_flags = FakeFlags()
            self.permissions = FakePermissions()
            self.manifest = FakeManifest()

    class FakeApp:
        package_name = "pkg.alpha"

    low = analytics._build_static_risk_row(FakeReport(8), {"counts": {}, "aggregates": {}}, {"risk": 5.0, "label": "Alpha"}, FakeApp())
    high = analytics._build_static_risk_row(FakeReport(289), {"counts": {}, "aggregates": {}}, {"risk": 5.0, "label": "Alpha"}, FakeApp())

    assert float(low["components"]) < 12.0
    assert float(high["components"]) <= 12.0
    assert float(high["components"]) > float(low["components"])


@pytest.mark.unit
def test_analyse_strings_for_results_degrades_to_empty_payload_on_error(monkeypatch):
    class _SilentLogger:
        def exception(self, *_args, **_kwargs):
            return None

    def _raise(*_args, **_kwargs):
        raise ValueError("Invalid IPv6 URL")

    monkeypatch.setattr(results, "analyse_strings", _raise)
    monkeypatch.setattr(results.logging_engine, "get_error_logger", lambda: _SilentLogger())

    warnings: list[str] = []
    payload = results._analyse_strings_for_results(
        "/tmp/example.apk",
        params=RunParameters(profile="full", scope="all", scope_label="All apps"),
        package_name="com.example.app",
        warning_sink=warnings,
    )

    assert payload["counts"] == {}
    assert payload["samples"] == {}
    assert payload["selected_samples"] == {}
    assert payload["warnings"] == ["ValueError: Invalid IPv6 URL"]
    assert len(warnings) == 1
    assert "com.example.app" in warnings[0]


@pytest.mark.unit
def test_render_results_reuses_cached_base_string_payload(tmp_path, monkeypatch):
    now = datetime.now(UTC)
    manifest = SimpleNamespace(app_label="Example", package_name="com.example.app")
    report = SimpleNamespace(
        manifest=manifest,
        exported_components=SimpleNamespace(providers=[]),
        detector_results=[],
        file_path="/tmp/example.apk",
        metadata={"duration_seconds": 0.1},
    )
    artifact = ArtifactOutcome(
        label="base.apk",
        report=report,
        severity=Counter(),
        duration_seconds=0.1,
        saved_path=None,
        started_at=now,
        finished_at=now,
        metadata={},
    )
    cached_string_payload = {
        "counts": {"endpoints": 2},
        "samples": {},
        "selected_samples": {},
        "aggregates": {"endpoint_roots": ["example.com"]},
    }
    app = AppRunResult(
        package_name="com.example.app",
        category="Test",
        artifacts=[artifact],
        base_string_data=cached_string_payload,
    )
    outcome = RunOutcome(
        results=[app],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        base_dir=tmp_path,
    )
    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        dry_run=True,
        verbose_output=False,
    )
    run_ctx = StaticRunContext(
        run_mode="batch",
        quiet=True,
        batch=True,
        noninteractive=True,
        show_splits=False,
        session_stamp=params.session_stamp,
        persistence_ready=False,
        paper_grade_requested=False,
    )

    def _unexpected_analyse(*_args, **_kwargs):
        raise AssertionError("analyse_strings should not be called")

    monkeypatch.setattr(results, "analyse_strings", _unexpected_analyse)
    monkeypatch.setattr(results, "_derive_highlight_stats", lambda *_a, **_k: {"providers": 0, "nsc_guard": 0, "secrets_suppressed": 0})
    monkeypatch.setattr(results, "_build_permission_profile", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_collect_component_stats", lambda *_a, **_k: {})
    monkeypatch.setattr(results, "_build_static_risk_row", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_collect_secret_stats", lambda *_a, **_k: {})
    monkeypatch.setattr(results, "_collect_masvs_profile", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_collect_finding_signatures", lambda *_a, **_k: {})
    monkeypatch.setattr(results, "_bulk_trend_deltas", lambda *_a, **_k: [])
    monkeypatch.setattr(results, "_apply_display_names", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_persist_cohort_rollup", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "app_detail_loop", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_render_post_run_views", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_render_cross_app_insights", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_render_db_masvs_summary", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_render_db_severity_table", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_render_persistence_footer", lambda *_a, **_k: None)

    captured: dict[str, object] = {}

    def _render_app_result(_report, *, string_data=None, **_kwargs):
        captured["string_data"] = string_data
        return ["line"], {"baseline": {"findings": []}}, {"High": 0, "Medium": 0, "Low": 0, "Info": 0}

    monkeypatch.setattr(results, "render_app_result", _render_app_result)

    results.render_run_results(outcome, params, run_ctx=run_ctx)

    assert captured["string_data"] is cached_string_payload
