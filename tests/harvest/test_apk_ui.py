from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.apk import ui, workflow
from scytaledroid.DeviceAnalysis.harvest.models import HarvestPlan, InventoryRow, ScopeSelection
from scytaledroid.Utils.DisplayUtils import colors


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


def test_describe_harvest_policy_mentions_product_partition_for_non_root() -> None:
    text = ui._describe_harvest_policy("non_root_paths", is_rooted=False)

    assert text == "non-root paths (system/product/vendor APK paths not harvested)"


def test_report_harvest_started_retains_non_root_policy_context(capsys) -> None:
    ui.report_harvest_started(
        selection_label="All pullable packages (full inventory)",
        candidate_count=578,
        selected_count=578,
        policy_eligible=152,
        scheduled=152,
        blocked_policy=426,
        blocked_scope=0,
        artifacts=571,
        policy="non_root_paths",
        harvest_mode="full_refresh",
        delta_filter_applied=False,
        is_rooted=False,
    )

    out = colors.strip(capsys.readouterr().out)
    assert "Harvest start: Pull all available APKs" in out
    assert "Processing: 152 pullable package(s) · ~571 APK path(s) (pull or reuse)" in out
    assert "Blocked: policy-blocked 426" in out
    assert "Policy: non-root paths (system/product/vendor APK paths not harvested)" in out
    assert "Mode: full_refresh · Delta: off" in out


def test_prompt_plan_action_simple_mode_defaults_to_execute(monkeypatch, capsys) -> None:
    monkeypatch.setattr(ui, "is_harvest_simple_mode", lambda: True)
    monkeypatch.setattr(ui.prompt_utils, "prompt_yes_no", lambda *args, **kwargs: True)

    action = ui.prompt_plan_action(
        SimpleNamespace(
            selection=SimpleNamespace(label="All pullable packages (full inventory)"),
            stats={"scheduled_packages": 152, "scheduled_files": 576, "blocked_packages": 426},
        )
    )

    out = colors.strip(capsys.readouterr().out)
    assert action == "pull_snapshot"
    assert "Harvest action" in out
    assert "Scope: Pull all available APKs" in out
    assert "Will pull: 152 package(s) · ~576 APK file(s), including splits" in out
    assert "Not available: 426 system package(s) on this non-root device" in out
    assert "Start harvest now?" not in out


def test_prompt_plan_action_simple_mode_accepts_cancel(monkeypatch) -> None:
    monkeypatch.setattr(ui, "is_harvest_simple_mode", lambda: True)
    monkeypatch.setattr(ui.prompt_utils, "prompt_yes_no", lambda *args, **kwargs: False)
    resolution = SimpleNamespace(
        selection=SimpleNamespace(label="Play Store & user-installed"),
        stats={"scheduled_packages": 1, "scheduled_files": 1, "blocked_packages": 0},
    )

    assert ui.prompt_plan_action(resolution) == "cancel"


def test_prompt_plan_action_full_mode_uses_yes_no_start(monkeypatch, capsys) -> None:
    monkeypatch.setattr(ui, "is_harvest_simple_mode", lambda: False)
    monkeypatch.setattr(ui.prompt_utils, "prompt_yes_no", lambda *args, **kwargs: True)

    action = ui.prompt_plan_action(
        SimpleNamespace(
            selection=SimpleNamespace(label="Play & user apps"),
            stats={"scheduled_packages": 152, "scheduled_files": 576, "blocked_packages": 426},
        )
    )

    out = colors.strip(capsys.readouterr().out)
    assert action == "pull_snapshot"
    assert "Harvest action" in out
    assert "Y) Start harvest" in out
    assert "N) Cancel" in out


def test_report_full_refresh_scope_applied_uses_full_device_wording(capsys) -> None:
    ui.report_full_refresh_scope_applied(578, pullable_count=152)

    out = colors.strip(capsys.readouterr().out)
    assert "Whole collection selected: 152 available package(s)" in out


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
