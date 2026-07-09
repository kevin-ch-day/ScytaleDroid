from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunOutcome, ScopeSelection
from scytaledroid.StaticAnalysis.cli.execution.scan_formatters import (
    _format_compact_progress_text,
    format_scan_progress_checkpoint_card,
    format_scan_progress_heartbeat,
    format_scan_progress_heartbeat_lines,
    format_scan_progress_single_line,
    format_static_run_final_summary_block,
)


def test_checkpoint_pipeline_metric_table_uses_full_width_rules() -> None:
    card = format_scan_progress_checkpoint_card(
        apps_completed=1,
        total_apps=10,
        artifacts_done=1,
        total_artifacts=5,
        current_app_label="Example",
        current_package_name="com.example.app",
        agg_checks=Counter(
            {
                "ok": 120,
                "warn": 0,
                "fail": 0,
                "policy_fail": 0,
                "finding_fail": 0,
                "error": 0,
                "skipped_stages": 40,
                "parse_signals_est": 0,
            }
        ),
        eta_text="5m",
        archive_reports_written=1,
        elapsed_text="10s",
        verbose_metrics=True,
    )
    lines = card.split("\n")
    title_i = lines.index("Detector-stage events so far")
    rule_above = lines[title_i + 1]
    header = lines[title_i + 2]
    rule_below = lines[title_i + 3]
    assert rule_above == rule_below
    assert len(rule_above) == len(header)
    assert set(rule_above) == {"-"}


def test_compact_progress_shows_first_app_as_one_of_total() -> None:
    text = _format_compact_progress_text(
        apps_completed=0,
        total_apps=12,
        artifacts_done=0,
        total_artifacts=98,
        agg_checks=Counter({"ok": 0, "warn": 0, "fail": 0, "policy_fail": 0, "finding_fail": 0, "error": 0}),
        elapsed_text="starting",
        eta_text="--",
        current_app_label="Facebook",
        current_package_name="com.facebook.katana",
        concise=False,
        include_recent_apps=True,
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
    assert "APK reports saved: 0 / 98" in text
    assert "Detector-stage events so far" in text
    assert "Legend" in text


def test_compact_progress_concise_defaults_short_lines() -> None:
    text = _format_compact_progress_text(
        apps_completed=0,
        total_apps=12,
        artifacts_done=0,
        total_artifacts=98,
        agg_checks=Counter({"ok": 0, "warn": 0, "fail": 0, "policy_fail": 0, "finding_fail": 0, "error": 0}),
        elapsed_text="starting",
        eta_text="--",
        current_app_label="Facebook",
        current_package_name="com.facebook.katana",
        include_run_context=False,
    )
    assert "Run context" not in text
    assert "Run progress: 1 / 12 selected · APKs 0 / 98 · reports 0 / 98" in text
    assert "Timing: elapsed starting · pending (needs a few completed APKs)" in text
    assert "No detector-stage events yet · execution OK" in text
    assert "APK reports saved:" not in text
    assert "Live table = detector-stage roll-ups" in text
    assert "Use --verbose for full OK + skipped-stage columns" in text


def test_compact_progress_omits_run_context_when_disabled() -> None:
    text = _format_compact_progress_text(
        apps_completed=5,
        total_apps=12,
        artifacts_done=40,
        total_artifacts=98,
        agg_checks=Counter({"ok": 0, "warn": 1, "fail": 0, "policy_fail": 0, "finding_fail": 0, "error": 0}),
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
    assert "Run progress:" in text
    assert "Timing:" in text
    assert "Detector-stage events so far" in text


def test_compact_progress_shows_persist_lag_when_stale() -> None:
    text = _format_compact_progress_text(
        apps_completed=5,
        total_apps=12,
        artifacts_done=40,
        total_artifacts=98,
        agg_checks=Counter({"ok": 0, "warn": 0, "fail": 0, "policy_fail": 0, "finding_fail": 0, "error": 0}),
        elapsed_text="10m",
        eta_text="20m",
        current_app_label="X",
        current_package_name="com.example.x",
        last_report_seconds_ago=240,
        last_report_package="com.stale.pkg",
        archive_reports_written=40,
        include_run_context=False,
        stale_persist_seconds=180,
    )
    assert "Run progress: 6 / 12 selected · APKs 40 / 98 · reports 40 / 98" in text
    assert "Last report persist: com.stale.pkg" in text


def test_heartbeat_line1_is_progress_only() -> None:
    line1, _line2 = format_scan_progress_heartbeat_lines(
        apps_completed=31,
        total_apps=144,
        artifacts_done=115,
        total_artifacts=531,
        current_app_label="Facebook",
        current_package_name="com.facebook.katana",
        agg_checks=Counter(
            {"ok": 0, "warn": 351, "fail": 57, "policy_fail": 57, "finding_fail": 0, "error": 0}
        ),
        eta_text="52m",
        archive_reports_written=115,
        eta_preliminary=False,
    )
    assert line1 == "115/531 APKs · 31/144 pkgs · Facebook"
    assert "ETA" not in line1
    assert "warn" not in line1.lower()


def test_heartbeat_line2_eta_reports_errors() -> None:
    _line1, line2 = format_scan_progress_heartbeat_lines(
        apps_completed=31,
        total_apps=144,
        artifacts_done=115,
        total_artifacts=531,
        current_app_label="Facebook",
        current_package_name="com.facebook.katana",
        agg_checks=Counter(
            {"ok": 0, "warn": 351, "fail": 57, "policy_fail": 57, "finding_fail": 0, "error": 0}
        ),
        eta_text="52m",
        archive_reports_written=115,
        eta_preliminary=False,
    )
    assert "ETA ~52m" in line2
    assert "APK reports 115/531" in line2
    assert "execution errors 0" in line2


def test_heartbeat_eta_preliminary_suffix() -> None:
    _l1, l2 = format_scan_progress_heartbeat_lines(
        apps_completed=2,
        total_apps=50,
        artifacts_done=5,
        total_artifacts=100,
        current_app_label="X",
        current_package_name="com.example.x",
        agg_checks=Counter({"ok": 1, "warn": 0, "fail": 0, "policy_fail": 0, "finding_fail": 0, "error": 0}),
        eta_text="40m",
        archive_reports_written=5,
        eta_preliminary=True,
    )
    assert "preliminary" in l2


def test_heartbeat_line1_only_backward_compat() -> None:
    line = format_scan_progress_heartbeat(
        apps_completed=1,
        total_apps=3,
        artifacts_done=2,
        total_artifacts=5,
        current_app_label="X",
        current_package_name="com.example.x",
        agg_checks=Counter({"ok": 0, "warn": 0, "fail": 0, "policy_fail": 0, "finding_fail": 0, "error": 0}),
        eta_text="5m",
    )
    assert line == "2/5 APKs · 1/3 pkgs · X"
    assert "ETA" not in line


def test_single_line_joins_heartbeat_parts() -> None:
    line = format_scan_progress_single_line(
        apps_completed=2,
        total_apps=144,
        artifacts_done=5,
        total_artifacts=531,
        current_app_label="Adobe Acrobat",
        current_package_name="com.adobe.reader",
        agg_checks=Counter(
            {"ok": 0, "warn": 13, "fail": 2, "policy_fail": 2, "finding_fail": 0, "error": 0}
        ),
        last_report_seconds_ago=7,
        last_report_package="bbc.mobile.news.ww",
        last_report_app_label="BBC News",
        eta_text="1h 3m",
        archive_reports_written=5,
    )
    assert "5/531 APKs · 2/144 pkgs · Adobe Acrobat" in line
    assert "ETA ~1h3m" in line or "ETA ~1h 3m" in line
    assert "execution errors 0" in line
    assert "BBC" not in line


def test_checkpoint_card_multiline_shape_default_table() -> None:
    card = format_scan_progress_checkpoint_card(
        apps_completed=10,
        total_apps=144,
        artifacts_done=120,
        total_artifacts=531,
        current_app_label="Next App",
        current_package_name="com.example.next",
        agg_checks=Counter(
            {"ok": 0, "warn": 3, "fail": 1, "policy_fail": 1, "finding_fail": 0, "error": 0}
        ),
        eta_text="40m",
        archive_reports_written=118,
        elapsed_text="18m 0s",
        split_heavy_note="TikTok has 45 APK artifacts; split scan is on.",
        verbose_metrics=False,
        eta_preliminary=False,
    )
    assert "Static progress" in card
    assert "Detector-stage events so far" in card
    assert "Current package : Next App · com.example.next" in card
    assert "Packages 10 / 144" in card
    assert "APK artifacts 120 / 531" in card
    assert "Reports 118 / 531" in card
    assert "Elapsed 18m 0s · ETA ~40m" in card
    assert "Warnings 3" in card
    assert "Policy gate failures 1" in card
    assert "Finding signals 0" in card
    assert "Execution errors 0" in card
    assert "Skipped stages" not in card or "Skipped stages 0" not in card
    assert "OK detector stages" not in card
    assert "Skipped detector stages" not in card
    assert "Split note" in card
    assert "TikTok has 45 APK artifacts" in card


def test_checkpoint_card_concise_pipeline_block_collapses_to_dense_lines() -> None:
    card = format_scan_progress_checkpoint_card(
        apps_completed=80,
        total_apps=152,
        artifacts_done=286,
        total_artifacts=576,
        current_app_label="Android Auto",
        current_package_name="com.google.android.projection.gearhead",
        agg_checks=Counter(
            {
                "warn": 475,
                "policy_fail": 0,
                "finding_fail": 94,
                "error": 0,
                "skipped_stages": 1424,
                "parse_signals_est": 35,
            }
        ),
        eta_text="15 mins 50 secs",
        archive_reports_written=286,
        elapsed_text="15 mins 37 secs",
        verbose_metrics=False,
    )

    assert "Warnings 475 · Policy gate failures 0 · Finding signals 94 · Execution errors 0" in card
    assert "Skipped stages 1424 · Parse est. 35" in card
    assert "Current package : Android Auto · com.google.android.projection.gearhead" in card
    assert "Packages 80 / 152 · APK artifacts 286 / 576 · Reports 286 / 576" in card
    assert "Elapsed 15 mins 37 secs · ETA ~15 mins 50 secs" in card
    assert "(execution OK — no analyzer/pipeline errors)" in card
    assert "(skipped = profile/applicability skips; normal)" in card
    assert "Metric" not in card


def test_checkpoint_card_falls_back_to_separate_package_id_for_very_long_lines() -> None:
    card = format_scan_progress_checkpoint_card(
        apps_completed=1,
        total_apps=10,
        artifacts_done=3,
        total_artifacts=10,
        current_app_label="A Very Long Human Display Label That Should Force The Progress Card To Wrap Back",
        current_package_name="com.example.this.package.name.is.long.enough.to.trigger.the.fallback.layout",
        agg_checks=Counter({"warn": 1, "policy_fail": 0, "finding_fail": 0, "error": 0}),
        eta_text="9m",
        archive_reports_written=3,
        elapsed_text="1m",
        verbose_metrics=False,
    )

    assert "Current package : A Very Long Human Display Label That Should Force The Progress Card To Wrap Back" in card
    assert "Package id      : com.example.this.package.name.is.long.enough.to.trigger.the.fallback.layout" in card


def test_checkpoint_card_verbose_shows_full_table() -> None:
    card = format_scan_progress_checkpoint_card(
        apps_completed=1,
        total_apps=10,
        artifacts_done=3,
        total_artifacts=10,
        current_app_label="Y",
        current_package_name="com.example.y",
        agg_checks=Counter(
            {
                "ok": 5,
                "warn": 1,
                "fail": 0,
                "policy_fail": 0,
                "finding_fail": 0,
                "error": 0,
                "skipped_stages": 9,
                "parse_signals_est": 2,
            }
        ),
        eta_text="9m",
        archive_reports_written=3,
        elapsed_text="1m",
        verbose_metrics=True,
    )
    assert "OK detector stages" in card
    assert "Skipped detector stages" in card


def test_compact_progress_after_one_app_completed_shows_second_ordinal() -> None:
    text = _format_compact_progress_text(
        apps_completed=1,
        total_apps=12,
        artifacts_done=12,
        total_artifacts=98,
        agg_checks=Counter({"ok": 0, "warn": 1, "fail": 0, "policy_fail": 0, "finding_fail": 0, "error": 0}),
        elapsed_text="3 mins 0 secs",
        eta_text="30m",
        current_app_label="Messenger",
        current_package_name="com.facebook.orca",
        concise=False,
    )
    assert "Package progress: 2 / 12 selected" in text
    assert "Legend" in text


def test_format_static_run_final_summary_block_with_pipeline_digest() -> None:
    t0 = datetime.now(UTC)
    r1 = AppRunResult("com.a", "Cat")
    r1.final_status = "complete"
    r2 = AppRunResult("com.b", "Cat")
    r2.final_status = "partial"
    outcome = RunOutcome(
        [r1, r2],
        t0,
        t0,
        ScopeSelection(scope="all", label="All apps", groups=()),
        Path("/tmp"),
        persistence_failed=False,
    )
    outcome.run_aggregate_status = "partial"
    outcome.total_artifacts = 10
    outcome.completed_artifacts = 10
    block = format_static_run_final_summary_block(
        outcome,
        session_display="sess-1",
        archive_reports_written=9,
        persistence_ready=True,
        dry_run=False,
        agg_checks=Counter(
            {
                "ok": 12,
                "warn": 3,
                "policy_fail": 1,
                "finding_fail": 0,
                "error": 0,
                "skipped_stages": 40,
                "parse_signals_est": 2,
            }
        ),
    )
    assert "Static run summary" in block
    assert "Session" in block and "sess-1" in block
    assert "1 complete" in block and "1 partial" in block
    assert "Evidence (reports)" in block and "9 / 10" in block
    assert "DB persistence" in block and "OK" in block
    assert "Run completion" in block and "COMPLETE" in block
    assert "Detector posture" in block and "PARTIAL" in block
    assert "Execution errors" in block and "0" in block
    assert "audit_static_session.py --session 'sess-1'" in block
    assert "report_static_session_grain_integrity.py" in block
    assert "--session-stamp 'sess-1'" in block
    assert "--count-archive-json" in block
    assert "DB check menus" in block
    assert "Post-run diagnostics" in block
    assert "Session pipeline totals" in block
    assert "Full detector-stage counts (session)" in block
    assert "OK detector stages" in block
    assert "Skipped detector stages" in block


def test_format_static_run_final_summary_block_omits_digest_without_agg_checks() -> None:
    t0 = datetime.now(UTC)
    r1 = AppRunResult("com.a", "Cat")
    r1.final_status = "complete"
    outcome = RunOutcome(
        [r1],
        t0,
        t0,
        ScopeSelection(scope="all", label="All apps", groups=()),
        Path("/tmp"),
    )
    outcome.run_aggregate_status = "complete"
    outcome.total_artifacts = 1
    block = format_static_run_final_summary_block(
        outcome,
        session_display="s",
        archive_reports_written=1,
        persistence_ready=True,
        dry_run=False,
    )
    assert "Session pipeline totals" not in block
