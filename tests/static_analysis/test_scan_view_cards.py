from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
from scytaledroid.StaticAnalysis.cli.core.run_context import StaticRunContext
from scytaledroid.StaticAnalysis.cli.execution import scan_view


def _ctx() -> StaticRunContext:
    return StaticRunContext(
        run_mode="interactive",
        quiet=False,
        batch=False,
        noninteractive=False,
        show_splits=False,
        session_stamp="sess-1",
        persistence_ready=True,
        paper_grade_requested=False,
    )


def test_render_app_completion_card_mode_dedupes_slowest_detectors(capsys) -> None:
    params = RunParameters(profile="full", scope="all", scope_label="All apps")
    summary = {
        "detector_total": 20,
        "detector_executed": 15,
        "detector_skipped": 5,
        "status_counts": {"OK": 10, "WARN": 3, "INFO": 2},
        "policy_fail_count": 1,
        "finding_fail_count": 2,
        "error_count": 0,
        "severity_counts": {"P0": 1, "P1": 2, "P2": 3, "NOTE": 0},
        "slowest_detectors": [
            {"detector": "correlation_engine", "duration_sec": 10.8},
            {"detector": "correlation_engine", "duration_sec": 10.3},
            {"detector": "integrity_identity", "duration_sec": 1.1},
        ],
        "finding_fail_detectors": [{"detector": "network_surface"}],
    }

    scan_view.render_app_completion(
        artifact_count=4,
        elapsed_seconds=37.0,
        report_metadata={"pipeline_summary": summary},
        params=params,
        run_ctx=_ctx(),
        app_index=2,
        app_total=99,
        app_title="BBC News",
        package_name="bbc.mobile.news.ww",
        app_summary=summary,
    )

    out = capsys.readouterr().out
    assert "[2/99] BBC News\n" in out
    assert "Package: bbc.mobile.news.ww" in out
    assert "[2/111] BBC News  (bbc.mobile.news.ww)" not in out
    assert "4 APKs | 00:37 | warn=3 | fail=3 | high=2 | med=3" in out
    assert "Slow:" in out
    assert out.count("correlation_engine") == 1
    assert "integrity_identity" in out
    assert "Policy/finding fails:" not in out


def test_render_app_completion_large_batch_suppresses_extra_detail_for_low_signal_app(capsys) -> None:
    params = RunParameters(profile="full", scope="all", scope_label="All apps")
    summary = {
        "detector_total": 20,
        "detector_executed": 18,
        "detector_skipped": 2,
        "status_counts": {"OK": 12, "WARN": 2, "INFO": 1},
        "policy_fail_count": 0,
        "finding_fail_count": 1,
        "error_count": 0,
        "severity_counts": {"P0": 0, "P1": 1, "P2": 2, "NOTE": 0},
        "slowest_detectors": [{"detector": "correlation_engine", "duration_sec": 4.2}],
        "finding_fail_detectors": [{"detector": "network_surface"}],
    }

    scan_view.render_app_completion(
        artifact_count=3,
        elapsed_seconds=21.0,
        report_metadata={"pipeline_summary": summary},
        params=params,
        run_ctx=_ctx(),
        app_index=7,
        app_total=120,
        app_title="Dropbox",
        package_name="com.dropbox.android",
        app_summary=summary,
    )

    out = capsys.readouterr().out
    assert out == ""
    assert "Slow:" not in out
    assert "Policy/finding fails:" not in out


def test_render_app_completion_large_batch_hides_policy_fail_list_without_verbose(capsys) -> None:
    params = RunParameters(profile="full", scope="all", scope_label="All apps")
    summary = {
        "detector_total": 20,
        "detector_executed": 18,
        "detector_skipped": 2,
        "status_counts": {"OK": 12, "WARN": 2, "INFO": 1},
        "policy_fail_count": 2,
        "finding_fail_count": 1,
        "error_count": 0,
        "severity_counts": {"P0": 0, "P1": 1, "P2": 2, "NOTE": 0},
        "slowest_detectors": [{"detector": "correlation_engine", "duration_sec": 4.2}],
        "policy_fail_detectors": [
            {"detector": "ipc_components"},
            {"detector": "provider_acl"},
        ],
        "finding_fail_detectors": [{"detector": "crypto_hygiene"}],
    }

    scan_view.render_app_completion(
        artifact_count=3,
        elapsed_seconds=21.0,
        report_metadata={"pipeline_summary": summary},
        params=params,
        run_ctx=_ctx(),
        app_index=7,
        app_total=120,
        app_title="Dropbox",
        package_name="com.dropbox.android",
        app_summary=summary,
    )

    out = capsys.readouterr().out
    assert out == ""
    assert "Policy/finding fails:" not in out


def test_format_compact_completion_line_is_dashboard_friendly() -> None:
    line = scan_view.format_compact_completion_line(
        app_index=7,
        app_total=120,
        app_title="Dropbox",
        package_name="com.dropbox.android",
        artifact_count=3,
        elapsed_seconds=21.0,
        app_summary={"warn_count": 2, "fail_count": 1, "high_count": 1, "medium_count": 2},
    )

    assert line == "[7/120] Dropbox | 3 APKs | 00:21 | warn=2 fail=1 | high=1 med=2"


def test_format_recent_completion_line_is_compact() -> None:
    line = scan_view.format_recent_completion_line(
        app_index=7,
        app_title="Dropbox",
        package_name="com.dropbox.android",
        elapsed_seconds=21.0,
        app_summary={"warn_count": 2, "fail_count": 1, "severity_counts": {"P1": 1, "P2": 2}},
    )

    assert line == "#7 Dropbox 00:21 w2 f1 h1 m2"


def test_render_app_completion_card_mode_for_profile_scope(capsys) -> None:
    params = RunParameters(profile="full", scope="profile", scope_label="Messaging")
    summary = {
        "detector_total": 20,
        "detector_executed": 15,
        "detector_skipped": 5,
        "status_counts": {"OK": 9, "WARN": 1, "INFO": 0},
        "policy_fail_count": 0,
        "finding_fail_count": 0,
        "error_count": 0,
        "severity_counts": {"P0": 0, "P1": 0, "P2": 1, "NOTE": 1},
        "slowest_detectors": [{"detector": "correlation_engine", "duration_sec": 3.9}],
    }

    scan_view.render_app_completion(
        artifact_count=1,
        elapsed_seconds=3.0,
        report_metadata={"pipeline_summary": summary},
        params=params,
        run_ctx=_ctx(),
        app_index=1,
        app_total=12,
        app_title="Signal",
        package_name="org.thoughtcrime.securesms",
        app_summary=summary,
    )

    out = capsys.readouterr().out
    assert "[1/12] Signal" in out
    assert "Package: org.thoughtcrime.securesms" in out
    assert "1 APK | 00:03 | warn=1 | fail=0 | high=0 | med=1" in out
    assert "Artifacts: 1   Time: 00:03" not in out
    assert "Pipeline stages:" not in out
    assert "Skipped detectors:" not in out


def test_render_app_completion_uses_dense_mode_for_persistence_test_batch(capsys) -> None:
    params = RunParameters(profile="full", scope="all", scope_label="Persistence test (10 apps)")
    summary = {
        "detector_total": 20,
        "detector_executed": 18,
        "detector_skipped": 2,
        "status_counts": {"OK": 12, "WARN": 4, "INFO": 1},
        "policy_fail_count": 1,
        "finding_fail_count": 1,
        "error_count": 0,
        "severity_counts": {"P0": 0, "P1": 12, "P2": 4, "NOTE": 1},
        "slowest_detectors": [{"detector": "correlation_engine", "duration_sec": 4.2}],
        "policy_fail_detectors": [{"detector": "ipc_components"}],
        "finding_fail_detectors": [{"detector": "crypto_hygiene"}],
    }

    scan_view.render_app_completion(
        artifact_count=4,
        elapsed_seconds=26.0,
        report_metadata={"pipeline_summary": summary},
        params=params,
        run_ctx=_ctx(),
        app_index=2,
        app_total=10,
        app_title="BBC News",
        package_name="bbc.mobile.news.ww",
        app_summary=summary,
    )

    out = capsys.readouterr().out
    assert "[2/10] BBC News" in out
    assert "Package: bbc.mobile.news.ww" in out
    assert "4 APKs | 00:26 | warn=4 | fail=2 | high=12 | med=4" in out
    assert "Artifacts: 4   Time: 00:26" not in out
