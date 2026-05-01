from __future__ import annotations

from dataclasses import dataclass, field
from collections import Counter
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.execution import scan_flow
from scytaledroid.StaticAnalysis.cli.persistence import run_summary
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, RepositoryArtifact


@dataclass
class _FakeReport:
    file_path: str = "/tmp/example.apk"
    metadata: dict[str, object] = field(default_factory=dict)
    detector_results: list[object] = field(default_factory=list)


def _make_group(tmp_path: Path, *, package_name: str, harvest_manifest: dict[str, object] | None) -> ArtifactGroup:
    apk_path = tmp_path / f"{package_name}__base.apk"
    apk_path.write_bytes(b"apk")
    artifact = RepositoryArtifact(
        path=apk_path,
        display_path=apk_path.name,
        metadata={
            "package_name": package_name,
            "version_code": "101",
            "version_name": "1.0.1",
            "artifact": "base",
            "is_split_member": False,
        },
    )
    return ArtifactGroup(
        group_key=f"{package_name}:101",
        package_name=package_name,
        version_display="1.0.1",
        session_stamp="20260328",
        capture_id="20260328",
        artifacts=(artifact,),
        harvest_manifest_path=(
            str(tmp_path / package_name / "harvest_package_manifest.json") if harvest_manifest else None
        ),
        harvest_manifest=harvest_manifest,
    )


def _configure_scan_flow(monkeypatch, *, calls: list[str]) -> None:
    monkeypatch.setattr(scan_flow, "load_display_name_map", lambda _groups: {})
    monkeypatch.setattr(scan_flow, "finalize_open_static_runs", lambda *_a, **_k: 0)
    monkeypatch.setattr(scan_flow, "create_static_run_ledger", lambda **_kwargs: None)
    monkeypatch.setattr(scan_flow, "render_app_start", lambda **_kwargs: None)
    monkeypatch.setattr(scan_flow, "render_app_completion", lambda **_kwargs: None)
    monkeypatch.setattr(scan_flow, "render_resource_warnings", lambda *_a, **_k: None)
    monkeypatch.setattr(scan_flow, "is_compact_card_mode", lambda *_a, **_k: False)

    def _fake_generate_report(_artifact, _base_dir, _params, *, extra_metadata=None):
        calls.append("generate_report")
        return _FakeReport(metadata=dict(extra_metadata or {})), None, None, False

    monkeypatch.setattr(scan_flow, "generate_report", _fake_generate_report)
    monkeypatch.setattr(
        scan_flow,
        "analyse_string_payload",
        lambda *_a, **_k: calls.append("string_payload") or {"counts": {}, "samples": {}, "selected_samples": {}, "aggregates": {}},
    )


def test_execute_scan_marks_harvest_ineligible_group_exploratory(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []
    _configure_scan_flow(monkeypatch, calls=calls)
    group = _make_group(
        tmp_path,
        package_name="com.example.partial",
        harvest_manifest={
            "execution_state": "completed",
            "status": {
                "capture_status": "partial",
                "persistence_status": "mirrored",
                "research_status": "ineligible",
            },
            "comparison": {
                "matches_planned_artifacts": False,
                "observed_hashes_complete": True,
            },
        },
    )
    params = RunParameters(
        profile="full",
        scope="app",
        scope_label="Example",
        paper_grade_requested=False,
        dry_run=False,
    )

    outcome = scan_flow.execute_scan(
        ScopeSelection(scope="app", label="Example", groups=(group,)),
        params,
        tmp_path,
    )

    assert calls == ["generate_report", "string_payload"]
    assert outcome.failures == []
    assert len(outcome.results) == 1
    result = outcome.results[0]
    assert result.exploratory_only is True
    assert result.research_usable is False
    assert "HARVEST_CAPTURE_PARTIAL" in result.research_block_reasons
    assert result.executed_artifacts == 1
    assert result.identity_valid is True
    assert result.base_string_data is not None


def test_execute_scan_fails_closed_for_paper_grade_when_harvest_ineligible(
    monkeypatch,
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    _configure_scan_flow(monkeypatch, calls=calls)
    group = _make_group(
        tmp_path,
        package_name="com.example.drifted",
        harvest_manifest={
            "execution_state": "completed",
            "status": {
                "capture_status": "drifted",
                "persistence_status": "mirrored",
                "research_status": "ineligible",
            },
            "comparison": {
                "matches_planned_artifacts": False,
                "observed_hashes_complete": False,
            },
        },
    )
    params = RunParameters(
        profile="full",
        scope="app",
        scope_label="Example",
        paper_grade_requested=True,
        dry_run=False,
    )

    outcome = scan_flow.execute_scan(
        ScopeSelection(scope="app", label="Example", groups=(group,)),
        params,
        tmp_path,
    )

    assert calls == []
    assert len(outcome.results) == 1
    assert outcome.results[0].exploratory_only is True
    assert outcome.results[0].executed_artifacts == 0
    assert any("exploratory-only" in failure for failure in outcome.failures)


def test_classify_static_contract_uses_harvest_authority() -> None:
    run_class, reasons = run_summary._classify_static_contract(
        package_name="com.example.partial",
        version_code=101,
        base_apk_sha256="a" * 64,
        identity_mode="full_hash",
        identity_conflict_flag=False,
        static_handoff_hash="b" * 64,
        static_handoff_json_path="evidence/static_runs/1/static_handoff.json",
        masvs_mapping_hash="c" * 64,
        schema_version="2026.03",
        tool_semver="2.1.1",
        tool_git_commit="deadbeef",
        static_config_hash="d" * 64,
        harvest_manifest_path=None,
        harvest_capture_status="partial",
        harvest_research_status="ineligible",
        harvest_matches_planned_artifacts=False,
        harvest_observed_hashes_complete=True,
        harvest_non_canonical_reasons=["HARVEST_CAPTURE_PARTIAL"],
        research_usable=False,
    )

    assert run_class == "NON_CANONICAL"
    assert "HARVEST_MANIFEST_MISSING" in reasons
    assert "HARVEST_CAPTURE_PARTIAL" in reasons
    assert "HARVEST_RESEARCH_INELIGIBLE" in reasons


def test_execute_scan_creates_started_static_run_ledger_before_scan(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []
    ledger_calls: list[dict[str, object]] = []
    _configure_scan_flow(monkeypatch, calls=calls)
    monkeypatch.setattr(
        scan_flow,
        "create_static_run_ledger",
        lambda **kwargs: ledger_calls.append(kwargs) or 321,
    )
    group = _make_group(
        tmp_path,
        package_name="com.example.started",
        harvest_manifest={
            "execution_state": "completed",
            "status": {
                "capture_status": "clean",
                "persistence_status": "mirrored",
                "research_status": "pending_audit",
            },
            "comparison": {
                "matches_planned_artifacts": True,
                "observed_hashes_complete": True,
            },
        },
    )
    params = RunParameters(
        profile="full",
        scope="app",
        scope_label="Example",
        session_stamp="sess-visible",
        paper_grade_requested=False,
        dry_run=False,
        persistence_ready=True,
    )

    outcome = scan_flow.execute_scan(
        ScopeSelection(scope="app", label="Example", groups=(group,)),
        params,
        tmp_path,
    )

    assert len(ledger_calls) == 1
    assert ledger_calls[0]["package_name"] == "com.example.started"
    assert ledger_calls[0]["session_stamp"] == "sess-visible"
    assert ledger_calls[0]["scope_label"] == "Example"
    assert outcome.results[0].static_run_id == 321


def test_execute_scan_prints_batch_persistence_timing_note(monkeypatch, tmp_path: Path, capsys) -> None:
    calls: list[str] = []
    _configure_scan_flow(monkeypatch, calls=calls)
    monkeypatch.setattr(scan_flow, "create_static_run_ledger", lambda **_kwargs: 321)

    group_a = _make_group(
        tmp_path,
        package_name="com.example.a",
        harvest_manifest={
            "execution_state": "completed",
            "status": {
                "capture_status": "clean",
                "persistence_status": "mirrored",
                "research_status": "pending_audit",
            },
            "comparison": {
                "matches_planned_artifacts": True,
                "observed_hashes_complete": True,
            },
        },
    )
    group_b = _make_group(
        tmp_path,
        package_name="com.example.b",
        harvest_manifest={
            "execution_state": "completed",
            "status": {
                "capture_status": "clean",
                "persistence_status": "mirrored",
                "research_status": "pending_audit",
            },
            "comparison": {
                "matches_planned_artifacts": True,
                "observed_hashes_complete": True,
            },
        },
    )
    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="sess-batch",
        paper_grade_requested=False,
        dry_run=False,
        persistence_ready=True,
    )

    scan_flow.execute_scan(
        ScopeSelection(scope="all", label="All apps", groups=(group_a, group_b)),
        params,
        tmp_path,
    )

    out = capsys.readouterr().out
    assert "Batch persistence timing:" not in out


def test_execute_scan_compact_mode_omits_copy_marker_by_default(monkeypatch, tmp_path: Path, capsys) -> None:
    calls: list[str] = []
    _configure_scan_flow(monkeypatch, calls=calls)
    monkeypatch.setattr(scan_flow, "create_static_run_ledger", lambda **_kwargs: 321)
    monkeypatch.setattr(scan_flow, "is_compact_card_mode", lambda *_a, **_k: True)

    group_a = _make_group(
        tmp_path,
        package_name="com.example.a",
        harvest_manifest={
            "execution_state": "completed",
            "status": {
                "capture_status": "clean",
                "persistence_status": "mirrored",
                "research_status": "pending_audit",
            },
            "comparison": {
                "matches_planned_artifacts": True,
                "observed_hashes_complete": True,
            },
        },
    )
    group_b = _make_group(
        tmp_path,
        package_name="com.example.b",
        harvest_manifest={
            "execution_state": "completed",
            "status": {
                "capture_status": "clean",
                "persistence_status": "mirrored",
                "research_status": "pending_audit",
            },
            "comparison": {
                "matches_planned_artifacts": True,
                "observed_hashes_complete": True,
            },
        },
    )
    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="sess-batch-copy",
        paper_grade_requested=False,
        dry_run=False,
        persistence_ready=True,
    )

    scan_flow.execute_scan(
        ScopeSelection(scope="all", label="All apps", groups=(group_a, group_b)),
        params,
        tmp_path,
    )

    out = capsys.readouterr().out
    assert "[COPY] static_app_done" not in out


def test_format_compact_progress_text_aggregates_top_fail_detectors() -> None:
    text = scan_flow._format_compact_progress_text(
        apps_completed=27,
        total_apps=120,
        artifacts_done=106,
        total_artifacts=459,
        agg_checks=Counter({"ok": 888, "warn": 312, "fail": 51, "error": 0}),
        elapsed_text="24m 18s",
        eta_text="1h 12m",
        current_app_label="Switch Access",
        current_package_name="com.google.android.accessibility.switchaccess",
        recent_completions=[
            "#22 Foo 00:19 w3 f1 h1 m2",
            "#23 Bar 00:12 w1 f0 m1",
            "#24 Newsmax 00:32 w4 f0 m1",
        ],
    )

    assert "Working on: Switch Access" in text
    assert "com.google.android.accessibility.switchaccess" in text
    assert "(app 28/120)" in text  # ordinal = apps completed + active app
    assert "Package:" not in text
    assert "Progress: 106/459 artifacts" in text
    assert "elapsed 24m 18s" in text
    assert "ETA ~1h 12m" in text
    assert "warn=312 fail=51 error=0" in text
    assert "Recent:" in text
    assert "#23 Bar 00:12 w1 f0 m1" in text
    assert "#24 Newsmax 00:32 w4 f0 m1" in text
