from __future__ import annotations

import pytest
from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
from scytaledroid.StaticAnalysis.cli.execution import results, results_dedupe, results_formatters


pytestmark = [pytest.mark.contract, pytest.mark.report_contract, pytest.mark.unit]


def test_dedupe_profile_entries_removes_duplicate_packages():
    entries = [
        {"package": "pkg.alpha", "value": 1},
        {"package": "pkg.alpha", "value": 2},
        {"label": "Alias"},
        {"label": "Alias", "value": 3},
        {"package_name": "pkg.beta"},
        {"value": 5},
    ]

    deduped = results_dedupe.dedupe_profile_entries(entries)

    assert len(deduped) == 4
    assert deduped[0]["value"] == 1
    assert {
        entry.get("package") or entry.get("label") or entry.get("package_name")
        for entry in deduped[:-1]
    } == {
        "pkg.alpha",
        "Alias",
        "pkg.beta",
    }


def test_format_highlight_tokens_prefers_provider_count():
    stats = {"providers": 37, "nsc_guard": 9, "secrets_suppressed": 0}
    totals = {"high": 0, "critical": 0}

    tokens = results_formatters._format_highlight_tokens(stats, totals, app_count=8)

    assert tokens[0].startswith("37 exported provider")


def test_format_highlight_tokens_falls_back_to_high_findings():
    stats = {"providers": 0, "nsc_guard": 0, "secrets_suppressed": 0}
    totals = {"high": 2, "critical": 0}

    tokens = results_formatters._format_highlight_tokens(stats, totals, app_count=5)

    assert "high-severity" in tokens[0]


def test_format_persistence_progress_text_is_operator_focused() -> None:
    text = results._format_persistence_progress_text(
        index=31,
        total_results=120,
        package_name="com.google.android.accessibility.switchaccess",
        app_label="Switch Access",
        elapsed_text="24m 18s",
        eta_text="1h 12m",
        persistence_error_count=0,
        include_phase_banner=True,
    )

    assert "DB persistence phase" in text
    assert "Writing now: Switch Access" in text
    assert "Package: com.google.android.accessibility.switchaccess" in text
    assert "Package write progress: 31 / 120" in text
    assert "Elapsed: 24m 18s" in text
    assert "ETA: ~1h 12m" in text
    assert "Persistence errors: 0 (none - DB write phase healthy so far)" in text


def test_format_persistence_progress_text_checkpoint_omits_repeated_banner() -> None:
    text = results._format_persistence_progress_text(
        index=11,
        total_results=120,
        package_name="com.example.pkg",
        app_label=None,
        elapsed_text="1 min 2 secs",
        eta_text="5 secs",
        persistence_error_count=0,
        include_phase_banner=False,
    )

    assert "DB persistence phase" not in text
    assert "Writing now: com.example.pkg" in text
    assert "Package write progress: 11 / 120" in text
    assert "Elapsed: 1 min 2 secs" in text
    assert "ETA: ~5 secs" in text
    assert "Persistence errors: 0 (none - DB write phase healthy so far)" in text


def test_render_compact_persistence_summary_stays_concise(capsys) -> None:
    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="sess-big-batch",
        verbose_output=False,
    )

    results._render_compact_persistence_summary(
        params=params,
        total_results=120,
        normalized_findings_total=14628,
        string_samples_persisted_total=512,
        baseline_written_count=120,
        plan_written_count=120,
        report_reference_count=120,
        persistence_errors=[],
        compat_export_errors=[],
        canonical_failures=[],
        run_status="COMPLETED",
    )

    out = capsys.readouterr().out
    assert "Persistence summary" in out
    assert "Session : sess-big-batch" in out
    assert "Apps    : 120" in out
    assert "Findings: 14628" in out
    assert "Strings : 512" in out
    assert "Artifacts: baseline=120 plan=120 report=120" in out
    assert "Status  : COMPLETED" in out
    assert "Database tools / Web view" in out


def test_format_masvs_cell_renders_na_for_missing_area():
    assert results_formatters._format_masvs_cell(None) == "N/A"
