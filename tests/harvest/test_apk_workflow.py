from __future__ import annotations

from scytaledroid.DeviceAnalysis.apk import workflow
from scytaledroid.DeviceAnalysis.harvest.models import HarvestPlan, InventoryRow, ScopeSelection


def _inventory_row(package_name: str) -> InventoryRow:
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


def test_resolve_harvest_plan_reports_scheduled_pullable_count(monkeypatch) -> None:
    row = _inventory_row("com.example.one")
    selection = ScopeSelection(
        label="All pullable packages (full inventory)",
        packages=[row],
        kind="everything",
        metadata={
            "candidate_count": 578,
            "selected_count": 578,
            "policy": "non_root_paths",
        },
    )

    scheduled_package = type("Pkg", (), {"skip_reason": None, "artifacts": [object()] * 571})()
    plan = HarvestPlan(packages=[scheduled_package], policy_filtered={}, failures=[])
    captured: dict[str, object] = {}
    sentinel = object()

    monkeypatch.setattr(workflow.harvest.rules, "load_google_allowlist", lambda: set())
    monkeypatch.setattr(workflow, "get_latest_inventory_metadata", lambda *args, **kwargs: None)
    monkeypatch.setattr(workflow, "get_last_guard_decision", lambda: None)
    monkeypatch.setattr(workflow.harvest, "select_package_scope", lambda *args, **kwargs: selection)
    monkeypatch.setattr(workflow.delta, "extract_delta_summary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(workflow.harvest, "build_harvest_plan", lambda *args, **kwargs: plan)
    monkeypatch.setattr(
        workflow.planner,
        "compute_plan_stats",
        lambda *args, **kwargs: {
            "scheduled_packages": 152,
            "blocked_packages": 426,
            "scheduled_files": 571,
            "policy_blocked": 426,
            "policy": "non_root_paths",
        },
    )
    monkeypatch.setattr(workflow.ui, "render_plan_overview", lambda *args, **kwargs: None)
    monkeypatch.setattr(workflow.ui, "prompt_plan_action", lambda *_args, **_kwargs: "pull_snapshot")
    monkeypatch.setattr(workflow.ui, "is_harvest_simple_mode", lambda: True)
    monkeypatch.setattr(
        workflow.ui,
        "report_harvest_started",
        lambda **kwargs: captured.update(kwargs),
    )
    monkeypatch.setattr(workflow.planner, "build_plan", lambda *args, **kwargs: sentinel)

    resolved = workflow.resolve_harvest_plan(
        serial="SERIAL123",
        rows=[row],
        is_rooted=False,
        snapshot_id=53,
        snapshot_captured_at="2026-06-13T00:00:00Z",
    )

    assert resolved is sentinel
    assert captured["candidate_count"] == 578
    assert captured["selected_count"] == 578
    assert captured["policy_eligible"] == 152
    assert captured["scheduled"] == 152
    assert captured["blocked_policy"] == 426
