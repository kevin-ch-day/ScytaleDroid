from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.apk.models import PlanResolution, SnapshotContext
from scytaledroid.DeviceAnalysis.apk.workflow import run_apk_pull
from scytaledroid.DeviceAnalysis.harvest.models import (
    HarvestPlan,
    InventoryRow,
    PackagePlan,
    PullResult,
    ScopeSelection,
)
from scytaledroid.DeviceAnalysis.harvest.status import HarvestRunStatus


def _inventory_row(package_name: str = "com.example.app") -> InventoryRow:
    return InventoryRow(
        raw={},
        package_name=package_name,
        app_label=package_name,
        installer="com.android.vending",
        category=None,
        primary_path=f"/data/app/{package_name}/base.apk",
        profile_key=None,
        profile=None,
        version_name="1.0",
        version_code="1",
        apk_paths=[f"/data/app/{package_name}/base.apk"],
        split_count=1,
    )


def _resolution() -> PlanResolution:
    row = _inventory_row()
    selection = ScopeSelection(
        label="Test Scope",
        packages=[row],
        kind="test",
        metadata={},
    )
    plan = HarvestPlan(
        packages=[PackagePlan(inventory=row, artifacts=[], total_paths=1)],
        policy_filtered={},
        failures=[],
    )
    return PlanResolution(
        plan=plan,
        selection=selection,
        stats={},
        pull_mode="inventory",
        verbose=False,
        guard_metadata=None,
    )


def _snapshot() -> SnapshotContext:
    row = _inventory_row()
    return SnapshotContext(
        snapshot={"packages": [row.raw]},
        rows=[row],
        snapshot_id=53,
        snapshot_captured_at="2026-06-13T00:00:00Z",
    )


def test_harvest_result_context_counts_include_replan_recovery() -> None:
    from scytaledroid.DeviceAnalysis.apk.workflow import _harvest_result_context_counts

    plan = _resolution().plan.packages[0]
    recovered = PullResult(
        plan=plan,
        ok=[SimpleNamespace(status="written")],
        capture_status="clean",
        stale_replan_required=True,
        stale_replan_outcome="path_stale_refreshed_and_retried",
    )
    failed = PullResult(
        plan=plan,
        capture_status="drifted",
        stale_replan_required=True,
        stale_replan_outcome="path_stale_replan_failed",
    )

    counts = _harvest_result_context_counts([recovered, failed])

    assert counts["packages_replanned"] == 2
    assert counts["packages_replan_success"] == 1
    assert counts["packages_replan_failed"] == 1
    assert counts["packages_replan_recovered"] == 1


def _status_summary(
    *,
    status: str,
    status_reason: str,
    packages_reviewed: int,
    packages_eligible: int,
    packages_executed: int,
    packages_harvested: int,
    packages_blocked_preflight: int,
    packages_replanned: int,
    packages_replan_recovered: int = 0,
    packages_path_stale: int = 0,
    packages_failed: int = 0,
    packages_partial: int = 0,
    packages_drifted: int = 0,
    level: str = "info",
) -> HarvestRunStatus:
    return HarvestRunStatus(
        packages_total=packages_reviewed,
        packages_reviewed=packages_reviewed,
        eligible_count=packages_eligible,
        attempted_count=packages_executed,
        harvested_count=packages_harvested,
        blocked_preflight_count=packages_blocked_preflight,
        skipped_count=0,
        failed_count=packages_failed,
        partial_count=packages_partial,
        drifted_count=packages_drifted,
        path_stale_count=packages_path_stale,
        replanned_count=packages_replanned,
        replan_success_count=max(packages_replanned - packages_failed, 0),
        replan_failed_count=packages_failed,
        replan_recovered_count=packages_replan_recovered,
        status=status,
        status_reason=status_reason,
        status_level=level,
        operator_summary="test summary",
    )


def test_run_apk_pull_returns_partial_when_harvest_aborts(monkeypatch, tmp_path: Path) -> None:
    from scytaledroid.DeviceAnalysis import harvest
    from scytaledroid.DeviceAnalysis.apk import workflow

    dest_root = tmp_path / "artifacts"
    monkeypatch.setattr(workflow.adb_client, "is_available", lambda: True)
    monkeypatch.setattr(workflow.adb_client, "get_adb_binary", lambda: "adb")
    monkeypatch.setattr(workflow, "ensure_inventory_snapshot", lambda _serial: _snapshot())
    monkeypatch.setattr(workflow, "device_is_rooted", lambda _serial: False)
    monkeypatch.setattr(workflow, "resolve_harvest_plan", lambda **_kwargs: _resolution())
    monkeypatch.setattr(
        workflow.artifact_store,
        "compose_harvest_run_destination",
        lambda **_kwargs: (dest_root, "RUNSTAMP"),
    )
    monkeypatch.setattr(workflow.log, "harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(workflow.log, "close_harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(harvest, "execute_harvest", lambda **_kwargs: [])
    monkeypatch.setattr(harvest, "render_harvest_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(harvest, "is_harvest_simple_mode", lambda: True)
    monkeypatch.setattr(workflow.ui, "maybe_save_watchlist", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        harvest,
        "build_harvest_run_report",
        lambda *args, **kwargs: SimpleNamespace(
            status="aborted_device_unavailable",
            status_summary=_status_summary(
                status="aborted_device_unavailable",
                status_reason="device_unavailable",
                packages_reviewed=2,
                packages_eligible=1,
                packages_executed=1,
                packages_harvested=0,
                packages_blocked_preflight=1,
                packages_replanned=1,
                level="error",
            ),
            metrics=SimpleNamespace(
                reviewed_packages=2,
                eligible_packages=1,
                executed_packages=1,
                harvested_packages=0,
                blocked_packages=1,
                replanned_packages=1,
                artifacts_written=0,
                artifacts_failed=1,
            ),
        ),
    )

    result = run_apk_pull("SERIAL123")

    assert result.ok is False
    assert result.status == "PARTIAL"
    assert result.error_code == "apk_pull_device_unavailable"
    assert result.context["harvest_status"] == "aborted_device_unavailable"
    assert result.context["packages"] == 0
    assert result.context["packages_blocked"] == 1
    assert result.context["packages_reviewed"] == 2
    assert result.context["packages_eligible"] == 1
    assert result.context["packages_executed"] == 1
    assert result.context["packages_harvested"] == 0
    assert result.context["packages_blocked_preflight"] == 1
    assert result.context["packages_replanned"] == 1
    assert result.context["harvest_status_reason"] == "device_unavailable"
    assert result.context["artifacts_failed"] == 1


def test_run_apk_pull_keeps_report_counts_when_summary_render_fails(
    monkeypatch, tmp_path: Path
) -> None:
    from scytaledroid.DeviceAnalysis import harvest
    from scytaledroid.DeviceAnalysis.apk import workflow

    dest_root = tmp_path / "artifacts"
    monkeypatch.setattr(workflow.adb_client, "is_available", lambda: True)
    monkeypatch.setattr(workflow.adb_client, "get_adb_binary", lambda: "adb")
    monkeypatch.setattr(workflow, "ensure_inventory_snapshot", lambda _serial: _snapshot())
    monkeypatch.setattr(workflow, "device_is_rooted", lambda _serial: False)
    monkeypatch.setattr(workflow, "resolve_harvest_plan", lambda **_kwargs: _resolution())
    monkeypatch.setattr(
        workflow.artifact_store,
        "compose_harvest_run_destination",
        lambda **_kwargs: (dest_root, "RUNSTAMP"),
    )
    monkeypatch.setattr(workflow.log, "harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(workflow.log, "close_harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(harvest, "execute_harvest", lambda **_kwargs: [])
    monkeypatch.setattr(
        harvest,
        "build_harvest_run_report",
        lambda *args, **kwargs: SimpleNamespace(
            status="partial",
            status_summary=_status_summary(
                status="partial",
                status_reason="package_failures_or_drift",
                packages_reviewed=10,
                packages_eligible=7,
                packages_executed=7,
                packages_harvested=5,
                packages_blocked_preflight=3,
                packages_replanned=2,
                level="warn",
            ),
            metrics=SimpleNamespace(
                reviewed_packages=10,
                eligible_packages=7,
                executed_packages=7,
                harvested_packages=5,
                blocked_packages=3,
                replanned_packages=2,
                artifacts_written=9,
                artifacts_failed=4,
            ),
        ),
    )
    monkeypatch.setattr(
        harvest,
        "render_harvest_summary",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("render boom")),
    )
    monkeypatch.setattr(harvest, "is_harvest_simple_mode", lambda: True)
    monkeypatch.setattr(workflow.ui, "maybe_save_watchlist", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(workflow.ui, "report_summary_failure", lambda _exc: None)

    result = run_apk_pull("SERIAL123")

    assert result.ok is False
    assert result.status == "PARTIAL"
    assert result.error_code == "apk_harvest_summary_failed"
    assert result.context["harvest_status"] == "partial"
    assert result.context["packages"] == 5
    assert result.context["packages_blocked"] == 3
    assert result.context["packages_reviewed"] == 10
    assert result.context["packages_eligible"] == 7
    assert result.context["packages_executed"] == 7
    assert result.context["packages_harvested"] == 5
    assert result.context["packages_blocked_preflight"] == 3
    assert result.context["packages_replanned"] == 2
    assert result.context["harvest_status_reason"] == "package_failures_or_drift"
    assert result.context["artifacts_written"] == 9
    assert result.context["artifacts_failed"] == 4


def test_run_apk_pull_prefers_authoritative_status_summary_for_package_counts(
    monkeypatch, tmp_path: Path
) -> None:
    from scytaledroid.DeviceAnalysis import harvest
    from scytaledroid.DeviceAnalysis.apk import workflow

    dest_root = tmp_path / "artifacts"
    monkeypatch.setattr(workflow.adb_client, "is_available", lambda: True)
    monkeypatch.setattr(workflow.adb_client, "get_adb_binary", lambda: "adb")
    monkeypatch.setattr(workflow, "ensure_inventory_snapshot", lambda _serial: _snapshot())
    monkeypatch.setattr(workflow, "device_is_rooted", lambda _serial: False)
    monkeypatch.setattr(workflow, "resolve_harvest_plan", lambda **_kwargs: _resolution())
    monkeypatch.setattr(
        workflow.artifact_store,
        "compose_harvest_run_destination",
        lambda **_kwargs: (dest_root, "RUNSTAMP"),
    )
    monkeypatch.setattr(workflow.log, "harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(workflow.log, "close_harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(harvest, "execute_harvest", lambda **_kwargs: [])
    monkeypatch.setattr(harvest, "render_harvest_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(harvest, "is_harvest_simple_mode", lambda: True)
    monkeypatch.setattr(workflow.ui, "maybe_save_watchlist", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        harvest,
        "build_harvest_run_report",
        lambda *args, **kwargs: SimpleNamespace(
            status="partial",
            status_summary=_status_summary(
                status="partial",
                status_reason="package_failures_or_drift",
                packages_reviewed=12,
                packages_eligible=8,
                packages_executed=7,
                packages_harvested=6,
                packages_blocked_preflight=4,
                packages_replanned=2,
                packages_replan_recovered=1,
                packages_path_stale=2,
                level="warn",
            ),
            metrics=SimpleNamespace(
                reviewed_packages=999,
                eligible_packages=999,
                executed_packages=999,
                harvested_packages=999,
                blocked_packages=999,
                replanned_packages=999,
                artifacts_written=11,
                artifacts_failed=2,
            ),
        ),
    )

    result = run_apk_pull("SERIAL123")

    assert result.context["packages_reviewed"] == 12
    assert result.context["packages_eligible"] == 8
    assert result.context["packages_executed"] == 7
    assert result.context["packages_harvested"] == 6
    assert result.context["packages_blocked_preflight"] == 4
    assert result.context["packages_replanned"] == 2
    assert result.context["packages_path_stale"] == 2
    assert result.context["packages_replan_success"] == 2
    assert result.context["packages_replan_failed"] == 0
    assert result.context["packages_replan_recovered"] == 1
    assert result.context["artifacts_written"] == 11
    assert result.context["artifacts_failed"] == 2


def test_run_apk_pull_returns_partial_when_report_build_fails(monkeypatch, tmp_path: Path) -> None:
    from scytaledroid.DeviceAnalysis import harvest
    from scytaledroid.DeviceAnalysis.apk import workflow

    dest_root = tmp_path / "artifacts"
    monkeypatch.setattr(workflow.adb_client, "is_available", lambda: True)
    monkeypatch.setattr(workflow.adb_client, "get_adb_binary", lambda: "adb")
    monkeypatch.setattr(workflow, "ensure_inventory_snapshot", lambda _serial: _snapshot())
    monkeypatch.setattr(workflow, "device_is_rooted", lambda _serial: False)
    monkeypatch.setattr(workflow, "resolve_harvest_plan", lambda **_kwargs: _resolution())
    monkeypatch.setattr(
        workflow.artifact_store,
        "compose_harvest_run_destination",
        lambda **_kwargs: (dest_root, "RUNSTAMP"),
    )
    monkeypatch.setattr(workflow.log, "harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(workflow.log, "close_harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(harvest, "execute_harvest", lambda **_kwargs: [])
    reported = {}
    monkeypatch.setattr(
        harvest,
        "build_harvest_run_report",
        lambda *args, **kwargs: (_ for _ in ()).throw(AttributeError("legacy result mismatch")),
    )
    monkeypatch.setattr(harvest, "is_harvest_simple_mode", lambda: True)
    monkeypatch.setattr(workflow.ui, "maybe_save_watchlist", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        workflow.ui,
        "report_report_failure",
        lambda exc: reported.setdefault("msg", str(exc)),
    )

    result = run_apk_pull("SERIAL123")

    assert result.ok is False
    assert result.status == "PARTIAL"
    assert result.error_code == "apk_harvest_report_failed"
    assert reported["msg"] == "legacy result mismatch"
    assert result.context["packages_reviewed"] == 0
    assert result.context["packages_eligible"] == 0
    assert result.context["packages_executed"] == 0
    assert result.context["packages_harvested"] == 0
    assert result.context["packages_blocked_preflight"] == 0
    assert result.context["packages_replanned"] == 0


def test_harvest_run_context_detail_lines_include_status_and_counts() -> None:
    from scytaledroid.DeviceAnalysis.device_menu.actions import _harvest_run_context_detail_lines

    lines = _harvest_run_context_detail_lines(
        {
            "harvest_status": "aborted_device_unavailable",
            "harvest_status_reason": "device_unavailable",
            "harvest_operator_summary": "reviewed 2/2 · eligible 1 · attempted 1 · resolved 0 · blocked before pull 1 · issues (failed=1 drifted=0 partial=0)",
            "packages_reviewed": 2,
            "packages_eligible": 1,
            "packages_executed": 1,
            "packages_harvested": 0,
            "packages_blocked_preflight": 1,
            "packages_path_stale": 1,
            "packages_replanned": 1,
            "packages_replan_recovered": 1,
            "packages_replan_success": 1,
            "packages_replan_failed": 0,
            "artifacts_written": 0,
            "artifacts_failed": 1,
            "run_id": "RUN123",
        }
    )

    assert "Harvest status: aborted_device_unavailable" in lines
    assert "Harvest status reason: device_unavailable" in lines
    assert "Harvest summary: reviewed 2/2 · eligible 1 · attempted 1 · resolved 0 · blocked before pull 1 · issues (failed=1 drifted=0 partial=0)" in lines
    assert "Packages reviewed: 2" in lines
    assert "Packages eligible: 1" in lines
    assert "Packages executed: 1" in lines
    assert "Packages resolved: 0" in lines
    assert "Packages blocked before pull: 1" in lines
    assert "Packages with path drift: 1" in lines
    assert "Packages replanned: 1" in lines
    assert "Packages replan recovered: 1" in lines
    assert "Packages replan OK: 1" in lines
    assert "Packages replan failed: 0" in lines
    assert "Artifacts written: 0" in lines
    assert "Artifacts failed: 1" in lines


def test_print_harvest_success_menu_feedback_prefers_actual_harvest_counts(
    monkeypatch, capsys
) -> None:
    from scytaledroid.DeviceAnalysis.device_menu.actions import _print_harvest_success_menu_feedback

    monkeypatch.setattr(
        "scytaledroid.DeviceAnalysis.harvest.is_harvest_simple_mode",
        lambda: False,
    )
    _print_harvest_success_menu_feedback(
        {
            "packages": 109,
            "packages_total": 578,
            "packages_harvested": 105,
            "packages_eligible": 109,
            "packages_blocked_preflight": 469,
            "packages_reviewed": 578,
        }
    )

    out = capsys.readouterr().out
    assert "Harvest complete: 105 resolved / 109 eligible / 578 in scope (469 blocked before pull)." in out
