from collections import Counter
from pathlib import Path

from scytaledroid.DeviceAnalysis.harvest.models import (
    ArtifactError,
    ArtifactPlan,
    HarvestPlan,
    InventoryRow,
    PackagePlan,
    PullResult,
    ScopeSelection,
)
from scytaledroid.DeviceAnalysis.harvest.summary import (
    HarvestRunMetrics,
    HarvestRunReport,
    build_harvest_run_report,
    render_harvest_summary,
    _build_summary_card_lines,
)


def test_build_summary_card_lines_surfaces_executed_and_blocked_counts():
    metrics = HarvestRunMetrics(
        total_packages=546,
        blocked_packages=429,
        executed_packages=117,
        planned_artifacts=446,
        artifacts_written=117,
        artifacts_failed=0,
        artifact_status_counter=Counter({"written": 446}),
        packages_with_writes=117,
        packages_with_errors=0,
        packages_failed=0,
        packages_drifted=0,
        packages_with_mirror_failures=0,
        packages_skipped_runtime=0,
        runtime_skips=Counter(),
        runtime_notes=Counter(),
        preflight_skips=Counter({"policy_non_root": 411, "no_paths": 18}),
    )

    lines = _build_summary_card_lines(
        selection_label="Everything",
        pull_mode="inventory",
        metadata={"candidate_count": 546, "selected_count": 546},
        guard_brief=None,
        metrics=metrics,
        pull_errors=0,
    )

    assert any("Packages" in line and "546 total" in line and "117 executed" in line and "429 blocked" in line for line in lines)
    assert any("Results" in line and "clean" in line for line in lines)


def _dummy_inventory(package_name: str = "com.example.app", app_label: str = "Example") -> InventoryRow:
    raw = {
        "package_name": package_name,
        "app_label": app_label,
        "installer": "play",
        "category": "social",
        "primary_path": f"/data/app/{package_name}/base.apk",
        "profile_key": "SOCIAL",
        "profile": "social",
        "version_code": "1",
        "version_name": "1.0",
        "apk_paths": [f"/data/app/{package_name}/base.apk"],
        "split_count": 1,
    }
    return InventoryRow(
        raw=raw,
        package_name=package_name,
        app_label=app_label,
        installer="play",
        category="social",
        profile="social",
        profile_key="SOCIAL",
        primary_path=f"/data/app/{package_name}/base.apk",
        apk_paths=[f"/data/app/{package_name}/base.apk"],
        split_count=1,
        version_code="1",
        version_name="1.0",
    )


def _single_package_plan() -> tuple[ScopeSelection, HarvestPlan, PackagePlan]:
    inv = _dummy_inventory()
    pkg_plan = PackagePlan(
        inventory=inv,
        artifacts=[ArtifactPlan(inv.primary_path or "", "artifact.apk", "artifact.apk", False)],
        total_paths=1,
    )
    selection = ScopeSelection(
        label="Test Scope",
        packages=[inv],
        kind="test",
        metadata={"candidate_count": 1, "selected_count": 1},
    )
    return selection, HarvestPlan(packages=[pkg_plan], policy_filtered={}, failures=[]), pkg_plan


def test_build_harvest_run_report_status_derivation_degraded_total_loss():
    selection, plan, pkg_plan = _single_package_plan()
    result = PullResult(
        plan=pkg_plan,
        skipped=["apk_record_failed"],
        persistence_status="mirror_failed",
        capture_status="clean",
    )

    report = build_harvest_run_report(plan, [result], selection=selection)

    assert report.status == "degraded_db_mirror_total_loss"
    assert report.status_level == "error"


def test_build_harvest_run_report_runtime_note_summary():
    selection, plan, pkg_plan = _single_package_plan()
    result = PullResult(
        plan=pkg_plan,
        ok=[],
        skipped=[],
        capture_status="clean",
    )
    result.ok.append(
        type(
            "ArtifactResultLike",
            (),
            {
                "status": "written",
                "file_name": "artifact.apk",
                "dest_path": "/tmp/artifact.apk",
                "sha256": None,
                "skip_reason": None,
            },
        )()
    )
    result.skipped = ["apk_record_failed", "artifact_path_failed"]

    report = build_harvest_run_report(plan, [result], selection=selection)

    assert report.runtime_note_summary is not None
    assert report.runtime_note_summary.total == 2
    assert report.runtime_note_summary.affected_package_count == 1
    assert report.runtime_note_summary.packages_by_reason["apk_record_failed"] == ["com.example.app"]


def test_build_harvest_run_report_scope_and_exclusion_summary():
    selection, plan, pkg_plan = _single_package_plan()
    selection.metadata.update(
        {
            "candidate_count": 6,
            "selected_count": 1,
            "excluded_counts": {"family_excluded": 3, "not_in_scope": 2},
        }
    )
    result = PullResult(plan=pkg_plan)

    report = build_harvest_run_report(plan, [result], selection=selection)

    assert report.excluded_counts == {"family_excluded": 3, "not_in_scope": 2}
    assert any("kept 1 of 6 candidates" in line for line in report.summary_card_lines)
    assert any("filtered 5" in line for line in report.summary_card_lines)
    assert report.policy_details is None


def test_build_harvest_run_report_respects_explicit_harvest_session_root(tmp_path: Path) -> None:
    selection, plan, pkg_plan = _single_package_plan()
    result = PullResult(plan=pkg_plan)
    root = tmp_path / "device_apks" / "ABC" / "20990101" / "120000_000001"
    report = build_harvest_run_report(
        plan,
        [result],
        selection=selection,
        run_timestamp="20990101_120000_000001",
        harvest_session_root=root,
    )
    assert report.artifacts_root == str(root.resolve())


def test_build_harvest_run_report_collects_policy_and_denied_packages():
    selection, plan, pkg_plan = _single_package_plan()
    plan.policy_filtered = {"non_root_paths": 2}
    result = PullResult(
        plan=pkg_plan,
        errors=[ArtifactError(source_path="/data/app/com.example.app/base.apk", reason="permission denied while pulling")],
    )

    report = build_harvest_run_report(plan, [result], selection=selection)

    assert report.policy_details == "System/vendor/mainline (non-root policy)=2"
    assert report.denied_packages == ["com.example.app"]


def test_render_harvest_summary_consumes_report_without_rederiving_status(monkeypatch, capsys):
    metrics = HarvestRunMetrics(
        total_packages=1,
        blocked_packages=0,
        executed_packages=1,
        planned_artifacts=1,
        artifacts_written=1,
        artifacts_failed=0,
        artifact_status_counter=Counter({"written": 1}),
        packages_with_writes=1,
        packages_with_errors=0,
        packages_failed=0,
        packages_drifted=0,
        packages_with_mirror_failures=0,
        packages_skipped_runtime=0,
        runtime_skips=Counter(),
        runtime_notes=Counter(),
        preflight_skips=Counter(),
    )
    selection, plan, _pkg_plan = _single_package_plan()
    fake_report = HarvestRunReport(
        harvest_result=type(
            "HarvestResultLike",
            (),
            {"packages": [], "device_serial": None, "scope_name": "Test Scope"},
        )(),
        metrics=metrics,
        pull_errors=0,
        files_written=1,
        status="degraded_db_mirror_total_loss",
        status_level="error",
        metadata={},
        scope_hash_changed=False,
        policy_filtered={},
        policy_details=None,
        excluded_counts={},
        excluded_samples={},
        denied_packages=[],
        top_package_limit=5,
        summary_card_lines=["Scope   : Test Scope"],
        highlights=[],
        artifacts_root="/tmp/artifacts",
        receipts_root="/tmp/receipts",
        runtime_note_summary=None,
        no_new=[],
        delta_summary=None,
        copy_line="[COPY] harvest scope='Test Scope' status=degraded_db_mirror_total_loss",
        delta_line=None,
        skip_counts_line=None,
        package_rollup_line="packages: total=1",
        artifact_rollup_line="artifacts: 1 planned / 1 written / 0 failed",
    )

    monkeypatch.setattr(
        "scytaledroid.DeviceAnalysis.harvest.summary.build_harvest_run_report",
        lambda *args, **kwargs: fake_report,
    )
    monkeypatch.setattr("scytaledroid.DeviceAnalysis.harvest.summary._harvest_simple_mode", lambda: True)
    monkeypatch.setattr("scytaledroid.DeviceAnalysis.harvest.summary._harvest_compact_mode", lambda: True)

    render_harvest_summary(plan, [], selection=selection)
    out = capsys.readouterr().out

    assert "Harvest finished (degraded_db_mirror_total_loss)" in out
    assert "scope=Test Scope" in out
    assert "[COPY] harvest" not in out

    monkeypatch.setattr(
        "scytaledroid.DeviceAnalysis.harvest.summary._harvest_transcript_copy_stdout",
        lambda: True,
    )
    render_harvest_summary(plan, [], selection=selection)
    assert "[COPY] harvest" in capsys.readouterr().out
