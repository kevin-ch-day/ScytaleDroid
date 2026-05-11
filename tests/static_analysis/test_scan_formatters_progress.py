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
        elapsed_text="starting",
        eta_text="--",
        current_app_label="Facebook",
        current_package_name="com.facebook.katana",
    )
    assert "Run context" in text
    assert "Preset:" in text
    assert "Packages in run: 12" in text
    assert "APKs in run: 98" in text
    assert "Package progress: 1 / 12 selected" in text
    assert "com.facebook.katana" in text
    assert "Display name: Facebook" in text
    assert "Package: com.facebook.katana" in text
    assert "APK artifact progress: 0 / 98 completed" in text
    assert "Elapsed: starting" in text
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
    assert "Current package" in text
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
        last_report_package="com.facebook.katana",
        last_report_app_label="Facebook",
        eta_text="52m",
        archive_reports_written=115,
    )
    assert "Progress: packages 31/144 · APKs 115/531 · ETA ~52m" in line
    assert "Current: Facebook (com.facebook.katana)" in line
    assert "Last artifact save: 3s ago" in line
    assert "Reports 115/531" in line
    assert "Findings: Warnings=351 · Policy/finding failures=57 · Execution errors=0" in line


def test_single_line_progress_labels_last_save_when_cursor_advanced() -> None:
    line = format_scan_progress_single_line(
        apps_completed=2,
        total_apps=144,
        artifacts_done=5,
        total_artifacts=531,
        current_app_label="Adobe Acrobat",
        current_package_name="com.adobe.reader",
        agg_checks=Counter({"warn": 13, "fail": 2, "error": 0}),
        last_report_seconds_ago=7,
        last_report_package="bbc.mobile.news.ww",
        last_report_app_label="BBC News",
        eta_text="1h 3m",
        archive_reports_written=5,
    )
    assert "Current: Adobe Acrobat (com.adobe.reader)" in line
    assert "Last save: BBC News (bbc.mobile.news.ww) · 7s ago" in line
    assert "Progress: packages 2/144 · APKs 5/531" in line


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
    assert "Package progress: 2 / 12 selected" in text
    assert "Legend:" in text
