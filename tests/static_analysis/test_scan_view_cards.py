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
        "policy_fail_count": 0,
        "finding_fail_count": 1,
        "error_count": 0,
        "severity_counts": {"P0": 1, "P1": 2, "P2": 3, "NOTE": 0},
        "slowest_detectors": [
            {"detector": "correlation_engine", "duration_sec": 7.8},
            {"detector": "correlation_engine", "duration_sec": 7.3},
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
        app_total=111,
        app_title="BBC News",
        package_name="bbc.mobile.news.ww",
        app_summary=summary,
    )

    out = capsys.readouterr().out
    assert "[2/111] BBC News" in out
    assert "Package: bbc.mobile.news.ww" in out
    assert "Artifacts: 4   Time: 00:37" in out
    assert "Checks: ok=10 warn=3 fail=1 error=0 skipped=5" in out
    assert "Findings: C:1 H:2 M:3 L:0 I:0 Note:0" in out
    assert "Slow:" in out
    assert out.count("correlation_engine") == 1
    assert "integrity_identity" in out


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
    assert "Artifacts: 1   Time: 00:03" in out
