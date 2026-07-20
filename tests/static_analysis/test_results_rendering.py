from __future__ import annotations

from types import SimpleNamespace

import pytest
from scytaledroid.StaticAnalysis.cli.execution import results
from tests.static_analysis._results_support import (
    make_app_result,
    make_outcome,
    make_params,
    make_report,
    make_run_ctx,
    patch_results_render_baseline,
)

pytestmark = [pytest.mark.contract, pytest.mark.report_contract, pytest.mark.unit]


def test_render_run_results_prints_context_sections_and_hides_runtime_wall(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("SCYTALEDROID_VERBOSE_RESULTS", "1")

    apps = [
        make_app_result(
            tmp_path=tmp_path,
            package_name=f"pkg.example.{i}",
            app_label=f"Example {i}",
            report=make_report(
                package_name=f"pkg.example.{i}",
                app_label=f"Example {i}",
                file_path=f"/tmp/example-{i}.apk",
                providers=["com.example.Provider"],
                detector_results=[
                    SimpleNamespace(
                        findings=[SimpleNamespace(severity_gate=SimpleNamespace(value="P0"))]
                    )
                ],
            ),
        )
        for i in range(6)
    ]
    outcome = make_outcome(tmp_path=tmp_path, app_results=apps)
    params = make_params(dry_run=True, verbose_output=False)

    patch_results_render_baseline(
        monkeypatch,
        highlight_stats={"providers": 5, "nsc_guard": 0, "secrets_suppressed": 0},
        output_context={
            "session_id": "sess-ctx",
            "device_serial": "ZY22JK89DR",
            "snapshot_id": 26,
            "scope_analyzed": "Harvested APK artifacts only",
            "mode_label": "Canonical / non-root",
            "analyzed_apps": 6,
            "planned_artifacts": 6,
            "observed_artifacts": 6,
            "acquisition": {
                "inventoried": 546,
                "in_scope": 546,
                "policy_eligible": 117,
                "scheduled": 117,
                "harvested": 117,
                "persisted": 117,
                "blocked_policy": 411,
                "blocked_scope": 18,
            },
        },
        render_app_result=lambda *_a, **_k: (
            ["line"],
            {"baseline": {"findings": []}},
            {"High": 1, "Medium": 2, "Low": 3, "Info": 0},
        ),
    )

    results.render_run_results(outcome, params)
    out = capsys.readouterr().out

    assert "Stage Context" in out
    assert "Acquisition Counters" in out
    assert "Blocked policy  : 411" in out
    assert "Example 0 (runtime" not in out


def test_render_run_results_large_compact_batch_suppresses_post_run_views(monkeypatch, capsys, tmp_path):
    apps = [
        make_app_result(
            tmp_path=tmp_path,
            package_name=f"pkg.example.{i}",
            app_label=f"Example {i}",
            static_run_id=i + 1000,
            report=make_report(
                package_name=f"pkg.example.{i}",
                app_label=f"Example {i}",
                file_path=f"/tmp/example-{i}.apk",
            ),
        )
        for i in range(25)
    ]
    outcome = make_outcome(tmp_path=tmp_path, app_results=apps)
    params = make_params(
        dry_run=False,
        verbose_output=False,
        persistence_ready=False,
        paper_grade_requested=False,
        session_stamp="sess-large-compact",
    )

    patch_results_render_baseline(
        monkeypatch,
        output_context={
            "session_id": "sess-large-compact",
            "device_serial": "ZY22JK89DR",
            "snapshot_id": 31,
            "scope_analyzed": "Harvested APK artifacts only",
            "mode_label": "Canonical / non-root",
            "analyzed_apps": 25,
            "planned_artifacts": 25,
            "observed_artifacts": 25,
            "acquisition": {},
        },
        render_app_result=lambda *_a, **_k: (
            ["line"],
            {"baseline": {"findings": []}},
            {"High": 0, "Medium": 1, "Low": 2, "Info": 0},
        ),
    )
    called = {"post_views": 0, "cross_app": 0}
    monkeypatch.setattr(results, "_render_post_run_views", lambda *_a, **_k: called.__setitem__("post_views", called["post_views"] + 1))
    monkeypatch.setattr(results, "_render_cross_app_insights", lambda *_a, **_k: called.__setitem__("cross_app", called["cross_app"] + 1))
    monkeypatch.setattr(results.prompt_utils, "prompt_text", lambda *_a, **_k: "2")

    results.render_run_results(outcome, params)

    out = capsys.readouterr().out
    assert called["post_views"] == 0
    assert called["cross_app"] == 0
    assert "Post-run diagnostics" in out
    assert "Open diagnostics menu" in out
    assert "Batch Context" in out
    assert "Acquisition Counters" not in out
    assert "Use the prompts below to drill into per-app findings." not in out
    assert "Use Review, Database tools, or the Web view for deeper drilldown." in out
    assert "Run Identity" not in out


def test_render_results_reuses_cached_base_string_payload(tmp_path, monkeypatch):
    cached_string_payload = {
        "counts": {"endpoints": 2},
        "samples": {},
        "selected_samples": {},
        "aggregates": {"endpoint_roots": ["example.com"]},
    }
    app = make_app_result(
        tmp_path=tmp_path,
        package_name="com.example.app",
        app_label="Example",
        base_string_data=cached_string_payload,
        saved_path=None,
        report=make_report(package_name="com.example.app", app_label="Example", duration_seconds=0.1),
    )
    outcome = make_outcome(tmp_path=tmp_path, app_results=[app])
    params = make_params(dry_run=True, verbose_output=False)
    run_ctx = make_run_ctx(params=params)

    def _unexpected_analyse(*_args, **_kwargs):
        raise AssertionError("analyse_strings should not be called")

    monkeypatch.setattr(results, "analyse_strings", _unexpected_analyse)
    patch_results_render_baseline(monkeypatch)

    captured: dict[str, object] = {}

    def _render_app_result(_report, *, string_data=None, **_kwargs):
        captured["string_data"] = string_data
        return ["line"], {"baseline": {"findings": []}}, {"High": 0, "Medium": 0, "Low": 0, "Info": 0}

    monkeypatch.setattr(results, "render_app_result", _render_app_result)

    results.render_run_results(outcome, params, run_ctx=run_ctx)

    assert captured["string_data"] is cached_string_payload


def test_render_run_results_hides_diagnostics_prompt_after_persistence_exception(
    monkeypatch, capsys, tmp_path
):
    app_result = make_app_result(
        tmp_path=tmp_path,
        package_name="com.example.app",
        app_label="Example",
        static_run_id=123,
        report=make_report(
            package_name="com.example.app",
            app_label="Example",
            providers=["com.example.Provider"],
            detector_results=[
                SimpleNamespace(
                    findings=[SimpleNamespace(severity_gate=SimpleNamespace(value="P0"))]
                )
            ],
        ),
    )
    outcome = make_outcome(tmp_path=tmp_path, app_results=[app_result], scope="app", scope_label="Example")
    params = make_params(
        scope="app",
        scope_label="Example",
        dry_run=False,
        verbose_output=False,
        persistence_ready=True,
        session_stamp="sess-failfast",
    )

    patch_results_render_baseline(
        monkeypatch,
        highlight_stats={"providers": 1, "nsc_guard": 0, "secrets_suppressed": 0},
        output_context={
            "session_id": "sess-failfast",
            "device_serial": "n/a",
            "snapshot_id": None,
            "scope_analyzed": "Harvested APK artifacts only",
            "mode_label": "Canonical",
            "analyzed_apps": 1,
            "planned_artifacts": 1,
            "observed_artifacts": 1,
            "acquisition": {},
        },
        render_app_result=lambda *_a, **_k: (
            ["line"],
            {"baseline": {"findings": []}},
            {"High": 1, "Medium": 1, "Low": 0, "Info": 0},
        ),
    )
    monkeypatch.setattr(
        results,
        "persist_run_summary",
        lambda *_a, **_k: (_ for _ in ()).throw(AttributeError("boom")),
    )
    monkeypatch.setattr(results, "finalize_static_run", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "publish_persisted_artifacts", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "ingest_baseline_payload", lambda *_a, **_k: True)
    monkeypatch.setattr(results.prompt_utils, "prompt_text", lambda *_a, **_k: "1")

    results.render_run_results(outcome, params)

    out = capsys.readouterr().out
    assert "Aborting post-processing: persistence exception" in out
    assert "Post-run diagnostics" not in out
    assert getattr(outcome, "return_to_main_menu", False) is True


def test_render_run_results_refreshes_base_report_after_persistence_even_without_saved_artifact_paths(
    monkeypatch, tmp_path
):
    base_report = make_report(package_name="com.example.app", app_label="Example")
    app_result = make_app_result(
        tmp_path=tmp_path,
        package_name="com.example.app",
        app_label="Example",
        report=base_report,
        saved_path=None,
    )
    outcome = make_outcome(tmp_path=tmp_path, app_results=[app_result], scope="app", scope_label="Example")
    params = make_params(
        scope="app",
        scope_label="Example",
        dry_run=False,
        verbose_output=False,
        persistence_ready=True,
        session_stamp="sess-refresh-base",
    )

    patch_results_render_baseline(
        monkeypatch,
        output_context={
            "session_id": "sess-refresh-base",
            "device_serial": "n/a",
            "snapshot_id": None,
            "scope_analyzed": "Harvested APK artifacts only",
            "mode_label": "Canonical",
            "analyzed_apps": 1,
            "planned_artifacts": 1,
            "observed_artifacts": 1,
            "acquisition": {},
        },
        render_app_result=lambda *_a, **_k: (
            ["line"],
            {"baseline": {"findings": []}},
            {"High": 1, "Medium": 0, "Low": 0, "Info": 0},
        ),
    )
    monkeypatch.setattr(
        results,
        "persist_run_summary",
        lambda *_a, **_k: SimpleNamespace(
            success=True,
            runtime_findings=4,
            persisted_findings=4,
            findings_capped_total=0,
            runtime_p0_findings=1,
            persisted_p0_findings=1,
            capped_p0_findings=0,
            findings_capped_by_detector={},
            string_samples_persisted=0,
            persistence_warnings=[],
            static_run_id=321,
        ),
    )
    monkeypatch.setattr(results, "finalize_static_run", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "publish_persisted_artifacts", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "ingest_baseline_payload", lambda *_a, **_k: True)

    refreshed_reports: list[object] = []
    monkeypatch.setattr(results, "refresh_saved_report_json", lambda report: refreshed_reports.append(report))

    results.render_run_results(outcome, params)

    assert refreshed_reports
    assert refreshed_reports[0] is base_report
