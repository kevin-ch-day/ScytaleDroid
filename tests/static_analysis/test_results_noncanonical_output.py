from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.core.models import (
    AppRunResult,
    ArtifactOutcome,
    RunOutcome,
    RunParameters,
    ScopeSelection,
)
from scytaledroid.StaticAnalysis.cli.core.run_context import StaticRunContext
from scytaledroid.StaticAnalysis.cli.execution import results


class _DummyPersistOutcome:
    static_run_id = None
    persisted_findings = 0
    string_samples_persisted = 0
    success = False
    errors = ["db_write_failed:run.create:returned_null"]




def test_render_results_writes_noncanonical_baseline_when_run_id_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
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
        saved_path=str(tmp_path / "report.json"),
        started_at=now,
        finished_at=now,
        metadata={},
    )
    app = AppRunResult(package_name="com.example.app", category="Test", artifacts=[artifact], static_run_id=None)
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
        session_stamp="sess-1",
        persistence_ready=True,
        dry_run=False,
        paper_grade_requested=False,
        verbose_output=False,
    )
    run_ctx = StaticRunContext(
        run_mode="batch",
        quiet=True,
        batch=True,
        noninteractive=True,
        show_splits=False,
        session_stamp="sess-1",
        persistence_ready=True,
        paper_grade_requested=False,
    )

    monkeypatch.setattr(results, "analyse_strings", lambda *_a, **_k: {})
    monkeypatch.setattr(results, "_derive_highlight_stats", lambda *_a, **_k: {"providers": 0, "nsc_guard": 0, "secrets_suppressed": 0})
    monkeypatch.setattr(results, "_build_permission_profile", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_collect_component_stats", lambda *_a, **_k: {})
    monkeypatch.setattr(results, "_build_static_risk_row", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_collect_secret_stats", lambda *_a, **_k: {})
    monkeypatch.setattr(results, "_collect_masvs_profile", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_collect_finding_signatures", lambda *_a, **_k: {})
    monkeypatch.setattr(
        results,
        "render_app_result",
        lambda *_a, **_k: (["line"], {"baseline": {"findings": []}}, {"High": 0, "Medium": 0, "Low": 0, "Info": 0}),
    )
    monkeypatch.setattr(results, "persist_run_summary", lambda *_a, **_k: _DummyPersistOutcome())
    monkeypatch.setattr(results, "ingest_baseline_payload", lambda *_a, **_k: True)
    monkeypatch.setattr(results, "governance_ready", lambda: (True, "ok"))
    monkeypatch.setattr(results, "refresh_static_run_manifest", lambda *_a, **_k: True)
    monkeypatch.setattr(results, "record_artifacts", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "build_artifact_registry_entries", lambda *_a, **_k: [])
    monkeypatch.setattr(results, "write_manifest_evidence", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "write_dynamic_plan_json", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_bulk_trend_deltas", lambda *_a, **_k: [])
    monkeypatch.setattr(results, "_apply_display_names", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_persist_cohort_rollup", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "app_detail_loop", lambda *_a, **_k: None)

    out_file = tmp_path / "noncanonical.json"

    def _write_baseline_json(*_a, **_k):
        out_file.write_text("{}", encoding="utf-8")
        return out_file

    monkeypatch.setattr(results, "write_baseline_json", _write_baseline_json)

    results.render_run_results(outcome, params, run_ctx=run_ctx)

    assert out_file.exists()


def test_render_results_skips_db_masvs_summary_when_no_results(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=[],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        base_dir=tmp_path,
    )
    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="sess-empty",
        persistence_ready=True,
        dry_run=False,
        paper_grade_requested=False,
        verbose_output=False,
    )
    run_ctx = StaticRunContext(
        run_mode="batch",
        quiet=True,
        batch=True,
        noninteractive=True,
        show_splits=False,
        session_stamp="sess-empty",
        persistence_ready=True,
        paper_grade_requested=False,
    )

    called = {"db_masvs": 0}
    monkeypatch.setattr(results, "analyse_strings", lambda *_a, **_k: {})
    monkeypatch.setattr(results, "_derive_highlight_stats", lambda *_a, **_k: {"providers": 0, "nsc_guard": 0, "secrets_suppressed": 0})
    monkeypatch.setattr(results, "_bulk_trend_deltas", lambda *_a, **_k: [])
    monkeypatch.setattr(results, "_apply_display_names", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_persist_cohort_rollup", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_render_post_run_views", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_render_cross_app_insights", lambda *_a, **_k: None)
    monkeypatch.setattr(
        results,
        "render_app_result",
        lambda *_a, **_k: (["line"], {"baseline": {"findings": []}}, {"High": 0, "Medium": 0, "Low": 0, "Info": 0}),
    )
    monkeypatch.setattr(results, "_render_db_masvs_summary", lambda *_a, **_k: called.__setitem__("db_masvs", called["db_masvs"] + 1))
    monkeypatch.setattr(results, "persist_run_summary", lambda *_a, **_k: _DummyPersistOutcome())
    monkeypatch.setattr(results, "refresh_static_run_manifest", lambda *_a, **_k: True)
    monkeypatch.setattr(results, "record_artifacts", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "build_artifact_registry_entries", lambda *_a, **_k: [])
    monkeypatch.setattr(results, "write_manifest_evidence", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "write_dynamic_plan_json", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_render_persistence_footer", lambda *_a, **_k: None)
    results.render_run_results(outcome, params, run_ctx=run_ctx)

    assert called["db_masvs"] == 0


def test_render_results_skips_db_masvs_summary_when_no_static_run_id(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime.now(UTC)
    manifest = SimpleNamespace(app_label="Tmp", package_name="tmp")
    report = SimpleNamespace(
        manifest=manifest,
        exported_components=SimpleNamespace(providers=[]),
        detector_results=[],
        file_path="/tmp/tmp.apk",
        metadata={"duration_seconds": 0.0},
    )
    artifact = ArtifactOutcome(
        label="tmp.apk",
        report=report,
        severity=Counter(),
        duration_seconds=0.0,
        saved_path=str(tmp_path / "tmp.json"),
        started_at=now,
        finished_at=now,
        metadata={},
    )
    app = AppRunResult(package_name="tmp", category="Test", artifacts=[artifact], static_run_id=None)
    outcome = RunOutcome(
        results=[app],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="app", label="tmp", groups=tuple()),
        base_dir=tmp_path,
    )
    params = RunParameters(
        profile="full",
        scope="app",
        scope_label="tmp",
        session_stamp="sess-no-run-id",
        persistence_ready=True,
        dry_run=False,
        paper_grade_requested=False,
        verbose_output=False,
    )
    run_ctx = StaticRunContext(
        run_mode="batch",
        quiet=True,
        batch=True,
        noninteractive=True,
        show_splits=False,
        session_stamp="sess-no-run-id",
        persistence_ready=True,
        paper_grade_requested=False,
    )

    called = {"db_masvs": 0}
    monkeypatch.setattr(results, "analyse_strings", lambda *_a, **_k: {})
    monkeypatch.setattr(results, "_derive_highlight_stats", lambda *_a, **_k: {"providers": 0, "nsc_guard": 0, "secrets_suppressed": 0})
    monkeypatch.setattr(results, "_bulk_trend_deltas", lambda *_a, **_k: [])
    monkeypatch.setattr(results, "_apply_display_names", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_persist_cohort_rollup", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_render_post_run_views", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_render_cross_app_insights", lambda *_a, **_k: None)
    monkeypatch.setattr(
        results,
        "render_app_result",
        lambda *_a, **_k: (["line"], {"baseline": {"findings": []}}, {"High": 0, "Medium": 0, "Low": 0, "Info": 0}),
    )
    monkeypatch.setattr(results, "_render_db_masvs_summary", lambda *_a, **_k: called.__setitem__("db_masvs", called["db_masvs"] + 1))
    monkeypatch.setattr(results, "persist_run_summary", lambda *_a, **_k: _DummyPersistOutcome())
    monkeypatch.setattr(results, "refresh_static_run_manifest", lambda *_a, **_k: True)
    monkeypatch.setattr(results, "record_artifacts", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "build_artifact_registry_entries", lambda *_a, **_k: [])
    monkeypatch.setattr(results, "write_manifest_evidence", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "write_dynamic_plan_json", lambda *_a, **_k: None)
    monkeypatch.setattr(results, "_render_persistence_footer", lambda *_a, **_k: None)

    results.render_run_results(outcome, params, run_ctx=run_ctx)

    assert called["db_masvs"] == 0
