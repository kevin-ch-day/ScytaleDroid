from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scytaledroid.StaticAnalysis.cli.core.models import (
    AppRunResult,
    ArtifactOutcome,
    RunOutcome,
    RunParameters,
    ScopeSelection,
)
from scytaledroid.StaticAnalysis.cli.execution import results
from scytaledroid.StaticAnalysis.cli.persistence.run_summary import PersistenceOutcome
from scytaledroid.StaticAnalysis.core.models import ManifestSummary, StaticAnalysisReport


def _make_report(tmp_path: Path, *, package: str) -> StaticAnalysisReport:
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"fake")
    manifest = ManifestSummary(
        package_name=package,
        app_label="Example",
        version_name="1.0",
        version_code="1",
        min_sdk="23",
        target_sdk="35",
    )
    return StaticAnalysisReport(
        file_path=str(apk_path),
        relative_path=None,
        file_name=apk_path.name,
        file_size=apk_path.stat().st_size,
        hashes={"sha256": "deadbeef"},
        manifest=manifest,
        metadata={
            "repro_bundle": {
                "manifest_evidence": {
                    "components": [
                        {"type": "provider", "name": "com.example.Provider"}
                    ]
                }
            }
        },
    )


def _make_outcome(tmp_path: Path, *, static_run_id: int) -> RunOutcome:
    report = _make_report(tmp_path, package="com.example.app")
    report_path = tmp_path / "report.json"
    report_path.write_text("{}", encoding="utf-8")
    artifact = ArtifactOutcome(
        label="base",
        report=report,
        severity=Counter({"High": 1}),
        duration_seconds=1.0,
        saved_path=str(report_path),
        started_at=datetime.now(UTC) - timedelta(seconds=1),
        finished_at=datetime.now(UTC),
        metadata={},
    )
    app_result = AppRunResult(
        package_name="com.example.app",
        category="App",
        artifacts=[artifact],
        static_run_id=static_run_id,
        app_label="Example",
        version_name="1.0",
        version_code=1,
        min_sdk=23,
        target_sdk=35,
    )
    scope = ScopeSelection(scope="app", label="Example", groups=tuple())
    now = datetime.now(UTC)
    return RunOutcome(
        results=[app_result],
        started_at=now - timedelta(seconds=2),
        finished_at=now,
        scope=scope,
        base_dir=tmp_path,
    )


def _patch_common(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SCYTALEDROID_PERSISTENCE_READY", "1")
    monkeypatch.setenv("SCYTALEDROID_PAPER_GRADE", "1")
    monkeypatch.setattr(results, "analyse_strings", lambda *args, **kwargs: {"selected_samples": {}})
    monkeypatch.setattr(
        results,
        "render_app_result",
        lambda *args, **kwargs: ([], {"baseline": {"findings": []}}, Counter()),
    )
    monkeypatch.setattr(
        results,
        "persist_run_summary",
        lambda *args, **kwargs: PersistenceOutcome(persisted_findings=0, string_samples_persisted=0),
    )
    monkeypatch.setattr(results, "_apply_display_names", lambda *args, **kwargs: None)
    monkeypatch.setattr(results, "_render_db_masvs_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(results, "_render_persistence_footer", lambda *args, **kwargs: None)
    monkeypatch.setattr(results, "_render_post_run_views", lambda *args, **kwargs: None)
    monkeypatch.setattr(results, "_render_cross_app_insights", lambda *args, **kwargs: None)
    monkeypatch.setattr(results, "_render_db_severity_table", lambda *args, **kwargs: False)
    monkeypatch.setattr(results.prompt_utils, "prompt_text", lambda *args, **kwargs: "2")


def test_governance_missing_blocks_publish(monkeypatch, tmp_path, capsys):
    _patch_common(monkeypatch, tmp_path)

    baseline_path = tmp_path / "baseline.json"
    plan_path = tmp_path / "plan.json"
    baseline_path.write_text("{}", encoding="utf-8")
    plan_path.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(results, "write_baseline_json", lambda *args, **kwargs: baseline_path)
    monkeypatch.setattr(results, "write_dynamic_plan_json", lambda *args, **kwargs: plan_path)
    monkeypatch.setattr(results, "record_artifacts", lambda *args, **kwargs: None)

    manifest_calls: list[tuple[int, str, tuple[str, ...]]] = []

    def _refresh(static_run_id: int, *, grade: str, grade_reasons=None):
        manifest_calls.append((static_run_id, grade, tuple(grade_reasons or ())))
        return True

    monkeypatch.setattr(results, "refresh_static_run_manifest", _refresh)

    def _run_sql(query: str, *args, **kwargs):
        if "permission_governance_snapshots" in query:
            return (0,)
        if "permission_governance_snapshot_rows" in query:
            return (0,)
        if "FROM artifact_registry" in query:
            return []
        return (0,)

    monkeypatch.setattr(results.core_q, "run_sql", _run_sql)

    outcome = _make_outcome(tmp_path, static_run_id=100)
    params = RunParameters(profile="full", scope="app", scope_label="Example")
    results.render_run_results(outcome, params)

    out = capsys.readouterr().out
    assert "Run grade: EXPERIMENTAL (MISSING_GOVERNANCE)" in out
    assert manifest_calls == []


def test_governance_present_allows_publish(monkeypatch, tmp_path, capsys):
    _patch_common(monkeypatch, tmp_path)

    baseline_path = tmp_path / "baseline.json"
    plan_path = tmp_path / "plan.json"
    baseline_path.write_text("{}", encoding="utf-8")
    plan_path.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(results, "write_baseline_json", lambda *args, **kwargs: baseline_path)
    monkeypatch.setattr(results, "write_dynamic_plan_json", lambda *args, **kwargs: plan_path)
    monkeypatch.setattr(results, "record_artifacts", lambda *args, **kwargs: None)

    manifest_calls: list[tuple[int, str, tuple[str, ...]]] = []

    def _refresh(static_run_id: int, *, grade: str, grade_reasons=None):
        manifest_calls.append((static_run_id, grade, tuple(grade_reasons or ())))
        return True

    monkeypatch.setattr(results, "refresh_static_run_manifest", _refresh)

    def _run_sql(query: str, *args, **kwargs):
        if "permission_governance_snapshots" in query:
            return (1,)
        if "permission_governance_snapshot_rows" in query:
            return (1,)
        if "FROM artifact_registry" in query:
            return [(artifact,) for artifact in results._REQUIRED_PAPER_ARTIFACTS]
        return (0,)

    monkeypatch.setattr(results.core_q, "run_sql", _run_sql)

    outcome = _make_outcome(tmp_path, static_run_id=200)
    params = RunParameters(profile="full", scope="app", scope_label="Example")
    results.render_run_results(outcome, params)

    out = capsys.readouterr().out
    assert "MISSING_GOVERNANCE" not in out
    assert manifest_calls
    static_run_id, grade, reasons = manifest_calls[0]
    assert static_run_id == 200
    assert grade == "PAPER_GRADE"
    assert reasons == ()
