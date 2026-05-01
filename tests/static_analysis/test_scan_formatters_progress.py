from __future__ import annotations

from collections import Counter

from scytaledroid.StaticAnalysis.cli.execution.scan_formatters import _format_compact_progress_text


def test_compact_progress_shows_first_app_as_one_of_total() -> None:
    text = _format_compact_progress_text(
        apps_completed=0,
        total_apps=12,
        artifacts_done=0,
        total_artifacts=98,
        agg_checks=Counter({"warn": 0, "fail": 0, "error": 0}),
        elapsed_text="00:00",
        eta_text="--",
        current_app_label="Facebook",
        current_package_name="com.facebook.katana",
    )
    assert "app 1/12" in text
    assert "com.facebook.katana" in text
    assert "Working on:" in text


def test_compact_progress_after_one_app_completed_shows_second_ordinal() -> None:
    text = _format_compact_progress_text(
        apps_completed=1,
        total_apps=12,
        artifacts_done=12,
        total_artifacts=98,
        agg_checks=Counter({"warn": 1, "fail": 0, "error": 0}),
        elapsed_text="03:00",
        eta_text="30m",
        current_app_label="Messenger",
        current_package_name="com.facebook.orca",
    )
    assert "app 2/12" in text
