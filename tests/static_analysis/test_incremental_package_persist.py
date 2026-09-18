from __future__ import annotations

from collections import Counter
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.execution import scan_flow
from scytaledroid.StaticAnalysis.cli.execution import scan_report as scan_report_mod
from scytaledroid.StaticAnalysis.cli.execution.results_persist import persist_analyzed_package
from scytaledroid.StaticAnalysis.cli.persistence import run_summary as rs
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, RepositoryArtifact


class _DummyOutcome:
    success = True
    persistence_failed = False
    static_run_id = 101
    persisted_findings = 2
    errors: list[str] = []


def _group(tmp_path: Path, package_name: str) -> ArtifactGroup:
    apk_path = tmp_path / f"{package_name}.apk"
    apk_path.write_bytes(b"apk")
    artifact = RepositoryArtifact(
        path=apk_path,
        display_path=apk_path.name,
        metadata={
            "package_name": package_name,
            "version_code": "1",
            "version_name": "1.0",
            "artifact": "base",
            "split_name": "base",
            "is_split_member": False,
        },
    )
    return ArtifactGroup(
        group_key=f"{package_name}:1",
        package_name=package_name,
        version_display="1.0",
        session_stamp="20260918",
        capture_id="20260918",
        artifacts=(artifact,),
        harvest_manifest_path=None,
        harvest_manifest=None,
    )


def test_persist_analyzed_package_skips_dry_run_and_uncommitted(monkeypatch) -> None:
    called = {"persist": 0}
    monkeypatch.setattr(rs, "persist_run_summary", lambda *_a, **_k: called.__setitem__("persist", 1))
    app = AppRunResult("com.example.app", "Uncategorized")
    app.static_run_id = 9
    params = RunParameters(profile="full", scope="app", scope_label="Example", dry_run=True)
    assert persist_analyzed_package(app_result=app, params=params) is None
    assert called["persist"] == 0

    params = RunParameters(profile="full", scope="app", scope_label="Example", dry_run=False)
    app.static_run_id = None
    assert persist_analyzed_package(app_result=app, params=params) is None
    assert called["persist"] == 0


def test_persist_analyzed_package_marks_committed_and_rollup_failure_is_nonfatal(monkeypatch) -> None:
    app = AppRunResult("com.example.app", "Uncategorized")
    app.static_run_id = 44
    report = SimpleNamespace(
        metadata={},
        manifest=SimpleNamespace(package_name="com.example.app"),
        detector_results=[],
        hashes={},
        analysis_version="test",
        exported_components=None,
        file_path="/tmp/base.apk",
        signatures=(),
        permissions=SimpleNamespace(declared=(), custom=()),
        components=SimpleNamespace(activities=(), services=(), receivers=(), providers=()),
        manifest_flags=SimpleNamespace(),
    )
    monkeypatch.setattr(app, "base_report", lambda: report)
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.results_persist.render_app_result",
        lambda *_a, **_k: ([], {"baseline": {}}, Counter()),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.results_persist.persist_run_summary",
        lambda *_a, **_k: _DummyOutcome(),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.results_persist.apply_persistence_outcome",
        lambda **_k: (0, 0),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.results_persist.merge_persistence_metadata",
        lambda **_k: None,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.results_persist._persist_cohort_rollup",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("rollup boom")),
    )
    params = RunParameters(
        profile="full",
        scope="app",
        scope_label="Example",
        session_stamp="sess-inc-1",
        dry_run=False,
        persistence_ready=True,
    )
    outcome = persist_analyzed_package(app_result=app, params=params)
    assert outcome is not None
    assert app.canonical_persist_committed is True
    assert app.canonical_persist_committed_at_monotonic is not None


def test_scan_flow_persists_package_one_before_package_two_starts(monkeypatch, tmp_path: Path) -> None:
    order: list[str] = []

    def _generate_report(_artifact, _base_dir, _params, **_kwargs):
        package = Path(str(_artifact.path)).stem
        order.append(f"analyze:{package}")
        return (
            SimpleNamespace(
                metadata=dict(_kwargs.get("extra_metadata") or {}),
                detector_results=[],
                file_path=str(_artifact.path),
            ),
            None,
            None,
            False,
        )

    def _persist(*, app_result, params, **_kwargs):
        order.append(f"persist:{app_result.package_name}")
        app_result.canonical_persist_committed = True
        return _DummyOutcome()

    monkeypatch.setattr(scan_flow, "load_display_name_map", lambda _groups: {})
    monkeypatch.setattr(scan_flow, "inspect_open_static_runs", lambda: SimpleNamespace(count=0))
    monkeypatch.setattr(scan_flow, "create_static_run_ledger", lambda **_kwargs: 7)
    monkeypatch.setattr(scan_flow, "render_app_start", lambda **_kwargs: None)
    monkeypatch.setattr(scan_flow, "render_app_completion", lambda **_kwargs: None)
    monkeypatch.setattr(scan_flow, "render_resource_warnings", lambda *_a, **_k: None)
    monkeypatch.setattr(scan_flow, "is_compact_card_mode", lambda *_a, **_k: False)
    monkeypatch.setattr(scan_flow, "ensure_static_session_shell", lambda **_kwargs: 1)
    monkeypatch.setattr(scan_flow, "persist_analyzed_package", _persist)
    monkeypatch.setattr(scan_report_mod, "generate_report", _generate_report)
    monkeypatch.setattr(scan_flow, "analyse_string_payload", lambda *_a, **_k: {})
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.scan_identity_helpers.lookup_stored_install_set_identity",
        lambda **_k: None,
    )

    groups = (_group(tmp_path, "com.example.one"), _group(tmp_path, "com.example.two"))
    params = RunParameters(
        profile="full",
        scope="profile",
        scope_label="Example",
        session_stamp="sess-inc-order",
        dry_run=False,
        persistence_ready=True,
        paper_grade_requested=False,
    )
    scan_flow.execute_scan(ScopeSelection(scope="profile", label="Example", groups=groups), params, tmp_path)
    assert order == [
        "analyze:com.example.one",
        "persist:com.example.one",
        "analyze:com.example.two",
        "persist:com.example.two",
    ]


def test_persist_run_summary_refuses_completed_replace(monkeypatch) -> None:
    monkeypatch.setattr(rs, "require_canonical_schema", lambda: None)
    monkeypatch.setattr(
        rs,
        "prepare_run_envelope",
        lambda **_kwargs: (SimpleNamespace(run_id=None, threat_profile=None, env_profile=None), []),
    )
    monkeypatch.setattr(
        rs,
        "_build_persistence_run_context",
        lambda **_kwargs: SimpleNamespace(),
    )
    monkeypatch.setattr(
        rs.core_q,
        "run_sql",
        lambda *_a, **_k: ("COMPLETED",),
    )
    report = SimpleNamespace(
        metadata={},
        manifest=SimpleNamespace(
            package_name="com.example.app",
            app_label="Example",
            version_name="1.0",
            version_code=1,
            min_sdk=24,
            target_sdk=34,
        ),
        detector_results=[],
        hashes={},
        analysis_version="test",
        exported_components=None,
    )
    outcome = rs.persist_run_summary(
        report,
        {},
        "com.example.app",
        session_stamp="sess-immut-1",
        scope_label="all",
        finding_totals={"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        baseline_payload={},
        static_run_id=101,
        paper_grade_requested=False,
        dry_run=False,
    )
    assert outcome.success is False
    assert any("immutable_completed_run" in err for err in outcome.errors)
