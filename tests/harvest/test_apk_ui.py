from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.apk import ui
from scytaledroid.Utils.DisplayUtils import colors


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
    assert "Harvest start: All pullable packages (full inventory)" in out
    assert "Pulling: 152 package(s) · ~571 APK path(s)" in out
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
    assert "Scope: All pullable packages" in out
    assert "Ready: 152 package(s) · ~576 APK path(s)" in out
    assert "Blocked before pull: 426 package(s)" in out
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
    ui.report_full_refresh_scope_applied(152)

    out = colors.strip(capsys.readouterr().out)
    assert "Full-device scope: 152 package(s) scheduled" in out
    assert "Full refresh scope" not in out
