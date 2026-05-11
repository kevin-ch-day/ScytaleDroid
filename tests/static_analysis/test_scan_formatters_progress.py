from __future__ import annotations

from collections import Counter

from scytaledroid.StaticAnalysis.cli.execution.scan_formatters import (
    _format_compact_progress_text,
    format_scan_progress_single_line,
)


def test_compact_progress_shows_first_app_as_one_of_total() -> None:
    text = _format_compact_progress_text(
        apps_completed=0,
        total_apps=12,
        artifacts_done=0,
        total_artifacts=98,
        agg_checks=Counter({"warn": 0, "fail": 0, "error": 0}),
        elapsed_text="0 ms",
        eta_text="--",
        current_app_label="Facebook",
        current_package_name="com.facebook.katana",
    )
    assert "Run context" in text
    assert "Packages in run: 12" in text
    assert "APKs in run: 98" in text
    assert "App progress: 1 / 12 packages" in text
    assert "com.facebook.katana" in text
    assert "App: Facebook" in text
    assert "Current package: com.facebook.katana" in text
    assert "Legend:" in text


def test_compact_progress_omits_run_context_when_disabled() -> None:
    text = _format_compact_progress_text(
        apps_completed=5,
        total_apps=12,
        artifacts_done=40,
        total_artifacts=98,
        agg_checks=Counter({"warn": 1, "fail": 0, "error": 0}),
        elapsed_text="5 mins 0 secs",
        eta_text="20m",
        current_app_label="X",
        current_package_name="com.example.x",
        include_run_context=False,
        include_legend=True,
    )
    assert "Run context" not in text
    assert "Session:" not in text
    assert "Current app" in text
    assert "Findings so far" in text


def test_single_line_progress_matches_operator_shape() -> None:
    line = format_scan_progress_single_line(
        apps_completed=31,
        total_apps=144,
        artifacts_done=115,
        total_artifacts=531,
        current_app_label="Facebook",
        current_package_name="com.facebook.katana",
        agg_checks=Counter({"warn": 351, "fail": 57, "error": 0}),
        last_report_seconds_ago=3,
        last_report_package="com.expedia.bookings",
        eta_text="52m",
        archive_reports_written=115,
    )
    assert "[31/144 apps | 115/531 APKs]" in line
    assert "Facebook" in line
    assert "detector_warnings=351" in line
    assert "policy_failures=57" in line
    assert "execution_errors=0" in line
    assert "com.expedia.bookings" in line


def test_compact_progress_after_one_app_completed_shows_second_ordinal() -> None:
    text = _format_compact_progress_text(
        apps_completed=1,
        total_apps=12,
        artifacts_done=12,
        total_artifacts=98,
        agg_checks=Counter({"warn": 1, "fail": 0, "error": 0}),
        elapsed_text="3 mins 0 secs",
        eta_text="30m",
        current_app_label="Messenger",
        current_package_name="com.facebook.orca",
    )
    assert "App progress: 2 / 12 packages" in text
    assert "Legend:" in text
