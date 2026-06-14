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
from scytaledroid.DeviceAnalysis.harvest.status import HarvestRunStatus
from scytaledroid.DeviceAnalysis.harvest.status import build_harvest_run_status_from_runtime_stats


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
        reviewed_packages=546,
        eligible_packages=117,
        harvested_packages=117,
    )

    lines = _build_summary_card_lines(
        selection_label="All pullable packages (full inventory)",
        pull_mode="inventory",
        metadata={"candidate_count": 546, "selected_count": 546},
        guard_brief=None,
        metrics=metrics,
        pull_errors=0,
    )

    assert any(
        "Packages" in line
        and "546 total" in line
        and "546 reviewed" in line
        and "117 eligible" in line
        and "117 attempted" in line
        and "429 blocked before pull" in line
        for line in lines
    )
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
    assert report.status_summary.status == "degraded_db_mirror_total_loss"
    assert report.status_summary.status_reason == "db_mirror_total_loss"


def test_build_harvest_run_report_exposes_authoritative_status_summary():
    selection, plan, pkg_plan = _single_package_plan()
    result = PullResult(
        plan=pkg_plan,
        ok=[],
        skipped=[],
        capture_status="drifted",
        stale_replan_required=True,
        stale_replan_outcome="path_stale_replan_failed",
    )

    report = build_harvest_run_report(plan, [result], selection=selection)

    assert report.status == report.status_summary.status
    assert report.status_level == report.status_summary.status_level
    assert report.status_summary.path_stale_count == 1
    assert report.status_summary.replanned_count == 1
    assert report.status_summary.replan_failed_count == 1
    assert report.status_summary.operator_summary.startswith("reviewed 1/1")


def test_build_harvest_run_status_from_runtime_stats_enforces_count_invariants():
    status = build_harvest_run_status_from_runtime_stats(
        {
            "packages_total": 5,
            "packages_reviewed": 9,
            "packages_eligible": 4,
            "packages_attempted": 3,
            "packages_harvested": 2,
            "packages_skipped": 1,
            "packages_runtime_skipped": 1,
            "packages_failed": 1,
            "packages_partial": 0,
            "packages_drifted": 1,
            "packages_path_stale": 2,
            "packages_replanned": 2,
            "packages_replan_success": 1,
            "packages_replan_failed": 1,
        },
        run_error=None,
        write_db_requested=False,
        write_db_effective=True,
    )

    assert status.packages_reviewed == 5
    assert status.attempted_count <= status.eligible_count
    assert status.harvested_count <= status.attempted_count
    assert status.replan_success_count + status.replan_failed_count <= status.replanned_count
    assert status.path_stale_count >= status.replanned_count


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


def test_build_harvest_run_report_counts_only_attempted_packages_on_early_abort():
    selection, plan, pkg_plan = _single_package_plan()
    second_inventory = _dummy_inventory("com.example.two", "Second")
    second_plan = PackagePlan(
        inventory=second_inventory,
        artifacts=[
            ArtifactPlan(
                second_inventory.primary_path or "",
                "artifact.apk",
                "artifact.apk",
                False,
            )
        ],
        total_paths=1,
    )
    selection.packages.append(second_inventory)
    selection.metadata["candidate_count"] = 2
    selection.metadata["selected_count"] = 2
    plan.packages.append(second_plan)

    result = PullResult(
        plan=pkg_plan,
        errors=[ArtifactError(source_path="/data/app/com.example.app/base.apk", reason="device_unavailable")],
        capture_status="failed",
    )

    report = build_harvest_run_report(plan, [result], selection=selection)

    assert report.metrics.total_packages == 2
    assert report.metrics.executed_packages == 1
    assert report.metrics.eligible_packages == 2
    assert report.metrics.reviewed_packages == 1
    assert report.status == "aborted_device_unavailable"
    assert report.status_level == "error"


def test_build_harvest_run_report_counts_path_stale_replan_outcomes():
    selection, plan, pkg_plan = _single_package_plan()
    result = PullResult(
        plan=pkg_plan,
        ok=[],
        skipped=[],
        capture_status="drifted",
        stale_replan_required=True,
        stale_replan_outcome="path_stale_blocked_before_pull",
    )

    report = build_harvest_run_report(plan, [result], selection=selection)

    assert report.metrics.path_stale_packages == 1
    assert report.metrics.replanned_packages == 1
    assert report.metrics.replan_success_packages == 1
    assert report.metrics.replan_failed_packages == 0


def test_build_harvest_run_report_counts_path_set_change_as_successful_replan():
    selection, plan, pkg_plan = _single_package_plan()
    result = PullResult(
        plan=pkg_plan,
        ok=[],
        skipped=[],
        capture_status="clean",
        stale_replan_required=True,
        stale_replan_outcome="path_stale_package_paths_changed_since_inventory",
    )

    report = build_harvest_run_report(plan, [result], selection=selection)

    assert report.metrics.path_stale_packages == 1
    assert report.metrics.replanned_packages == 1
    assert report.metrics.replan_success_packages == 1
    assert report.metrics.replan_failed_packages == 0


def test_build_harvest_run_report_tolerates_legacy_pull_result_without_replan_fields():
    selection, plan, pkg_plan = _single_package_plan()
    result = PullResult(
        plan=pkg_plan,
        ok=[],
        skipped=[],
        capture_status="clean",
    )
    delattr(result, "stale_replan_required")
    delattr(result, "stale_replan_outcome")

    report = build_harvest_run_report(plan, [result], selection=selection)

    assert report.metrics.path_stale_packages == 0
    assert report.metrics.replanned_packages == 0
    assert report.status == "success"


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
        status_summary=HarvestRunStatus(
            packages_total=1,
            packages_reviewed=1,
            eligible_count=1,
            attempted_count=1,
            harvested_count=1,
            blocked_preflight_count=0,
            skipped_count=0,
            failed_count=0,
            partial_count=0,
            drifted_count=0,
            path_stale_count=0,
            replanned_count=0,
            replan_success_count=0,
            replan_failed_count=0,
            status="degraded_db_mirror_total_loss",
            status_reason="db_mirror_total_loss",
            status_level="error",
            operator_summary="reviewed 1/1 · eligible 1 · attempted 1 · harvested 1 · OK",
        ),
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


def test_render_harvest_summary_uses_supplied_report_without_rebuild(monkeypatch, capsys):
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
        status_summary=HarvestRunStatus(
            packages_total=1,
            packages_reviewed=1,
            eligible_count=1,
            attempted_count=1,
            harvested_count=1,
            blocked_preflight_count=0,
            skipped_count=0,
            failed_count=0,
            partial_count=0,
            drifted_count=0,
            path_stale_count=0,
            replanned_count=0,
            replan_success_count=0,
            replan_failed_count=0,
            status="success",
            status_reason="completed_clean",
            status_level="success",
            operator_summary="reviewed 1/1 · eligible 1 · attempted 1 · harvested 1 · OK",
        ),
        pull_errors=0,
        files_written=1,
        status="success",
        status_level="success",
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
        copy_line="[COPY] harvest scope='Test Scope' status=success",
        delta_line=None,
        skip_counts_line=None,
        package_rollup_line="packages: total=1",
        artifact_rollup_line="artifacts: 1 planned / 1 written / 0 failed",
    )

    monkeypatch.setattr(
        "scytaledroid.DeviceAnalysis.harvest.summary.build_harvest_run_report",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not rebuild report")),
    )
    monkeypatch.setattr("scytaledroid.DeviceAnalysis.harvest.summary._harvest_simple_mode", lambda: True)
    monkeypatch.setattr("scytaledroid.DeviceAnalysis.harvest.summary._harvest_compact_mode", lambda: True)

    render_harvest_summary(plan, [], selection=selection, report=fake_report)
    out = capsys.readouterr().out

    assert "Harvest finished (success)" in out
    assert "scope=Test Scope" in out
