from __future__ import annotations

from types import SimpleNamespace

import pytest

from scytaledroid.DynamicAnalysis.controllers import guided_run

from tests.dynamic._guided_run_state_support import make_dataset_state, one_shot_package_selector, patch_guided_run_context


pytestmark = [pytest.mark.contract, pytest.mark.state_contract]


def test_guided_run_blocks_early_when_static_plan_identity_drift_exists(monkeypatch, capsys) -> None:
    package = "com.facebook.katana"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="Facebook",
        active_device=None,
        patch_static_drift_detector=False,
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=4,
            valid_runs=3,
            baseline_valid_runs=3,
            interactive_valid_runs=0,
            quota_met=False,
            extra_valid_runs=1,
            local_evidence_dir_count=4,
            reset_available=True,
            paper_eligible_local=4,
            quota_counted_local=3,
            suggested_profile_from_tracker="interaction_manual",
            effective_suggested_profile="interaction_manual",
            suggested_slot=4,
            historical_valid_runs=2,
            historical_build_count=1,
        ),
    )
    monkeypatch.setattr(
        guided_run,
        "ensure_plan_or_error",
        lambda *_args, **_kwargs: {
            "plan_path": "plan.json",
            "static_run_id": 4290,
            "version_name": "565.0.0.49.74",
            "version_code": "472143276",
        },
    )
    monkeypatch.setattr(guided_run, "_load_plan_identity", lambda _path: {"version_code": "472143276"})
    monkeypatch.setattr(
        guided_run,
        "_read_observed_version_code_details",
        lambda _serial, _package: {
            "version_code": "472224766",
            "command": "dumpsys package com.facebook.katana",
            "pattern": "scoped:versionCode+minSdk",
            "matched_line": "versionCode=472224766 minSdk=30 targetSdk=36",
        },
    )
    monkeypatch.setattr(guided_run.prompt_utils, "press_enter_to_continue", lambda: None)
    choices = iter(["1", "0"])
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choices))

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Static Plan / Device Drift" not in out
    assert "Installed build drift detected" in out
    assert "tracked-build evidence (local+db)" in out
    assert "tracked quota 3/5 n2" in out
    assert "Installed build 472224766 · tracked static-plan build 472143276" in out
    assert "R) Refresh checklist [default]" in out
    assert "Reason: installed build does not match the newest static plan." in out
    assert "Blocked: installed build 472224766 does not match static-plan build 472143276." in out
    assert "Refresh harvest/static for this app or choose another app." in out
    assert "472224766" in out
    assert "472143276" in out
    assert "Review / inspect" in out
    assert "H) Run history" in out
    assert "G) Diagnostics" in out


def test_load_selected_app_context_uses_refresh_action_when_live_build_drift_is_true(monkeypatch) -> None:
    package = "com.cnn.mobile.android.phone"

    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=6,
            valid_runs=5,
            baseline_valid_runs=3,
            interactive_valid_runs=2,
            quota_met=True,
        ),
    )
    monkeypatch.setattr(guided_run, "_scripted_template_available", lambda _package_name: True)
    monkeypatch.setattr(guided_run, "_load_db_dynamic_lineage_context", lambda _package_name: {"db_active_sessions": 1, "db_historical_sessions": 0})
    monkeypatch.setattr(guided_run, "_selected_app_latest_recent_summary", lambda **_kwargs: None)
    monkeypatch.setattr(guided_run, "_selected_app_has_identity_mismatch", lambda **_kwargs: False)

    app = guided_run._load_selected_app_context(package_name=package, live_build_drift=True)

    assert app.queue_action == "refresh"
    assert app.queue_reason == "installed build does not match the newest static plan"
    assert app.live_build_drift is True


def test_selected_app_state_snapshot_supports_refresh_action() -> None:
    snapshot = guided_run._selected_app_state_snapshot(
        lineage_state="current_build_observed",
        active_valid_runs=0,
        legacy_valid_runs=2,
        db_active_sessions=0,
        db_historical_sessions=1,
        latest_valid=True,
        queue_action="refresh",
        baseline_valid_runs=0,
        interactive_valid_runs=0,
        baseline_required=3,
        interactive_required=2,
        extra_valid_runs=0,
    )

    assert snapshot.need == "refresh"
    assert snapshot.action == "refresh"
    assert snapshot.quota == "0/5 n5"


def test_drift_workbench_passes_refresh_queue_action_internally(monkeypatch, capsys) -> None:
    captured: dict[str, str] = {}
    original = guided_run._selected_app_state_snapshot

    def _capturing_snapshot(**kwargs):
        captured["queue_action"] = str(kwargs.get("queue_action"))
        return original(**kwargs)

    monkeypatch.setattr(guided_run, "_selected_app_state_snapshot", _capturing_snapshot)
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    app = SimpleNamespace(
        package_name="com.twitter.android",
        display_label="X (Twitter)",
        historical_valid_local=3,
        historical_build_count=1,
        db_active_sessions=0,
        db_historical_sessions=0,
        latest_valid=None,
        counts=SimpleNamespace(baseline_valid_runs=0, interactive_valid_runs=0),
        cfg=SimpleNamespace(baseline_required=3, interactive_required=2),
        extra_valid_local=0,
        has_identity_mismatch=False,
        state=SimpleNamespace(),
    )
    plan_drift = {
        "observed_version_code": "312021000",
        "expected_version_code": "312011000",
        "expected_version_name": "12.1.1-release.0",
        "static_run_id": 4695,
    }

    guided_run._render_selected_app_drift_workbench(app=app, plan_drift=plan_drift)

    out = capsys.readouterr().out
    assert captured["queue_action"] == "refresh"
    assert "Installed build drift detected · historical evidence (local-only) · QA unknown · tracked quota 0/5 n5" in out
    assert "Installed build 312021000 · tracked static-plan build 312011000" in out
    assert "R) Refresh checklist [default]" in out


def test_drift_workbench_refresh_checklist_includes_menu_path(monkeypatch, capsys) -> None:
    choices = iter(["R", "0"])
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *_a, **_k: next(choices))
    monkeypatch.setattr(guided_run.prompt_utils, "press_enter_to_continue", lambda: None)

    app = SimpleNamespace(
        package_name="org.theguardian.app",
        display_label="The Guardian",
        historical_valid_local=0,
        historical_build_count=0,
        db_active_sessions=0,
        db_historical_sessions=0,
        latest_valid=None,
        counts=SimpleNamespace(baseline_valid_runs=0, interactive_valid_runs=0),
        cfg=SimpleNamespace(baseline_required=3, interactive_required=2),
        extra_valid_local=0,
        has_identity_mismatch=False,
        state=SimpleNamespace(),
    )
    plan_drift = {
        "observed_version_code": "22987",
        "expected_version_code": "22964",
        "expected_version_name": "6.224.22964",
        "static_run_id": 4651,
    }

    guided_run._render_selected_app_drift_workbench(app=app, plan_drift=plan_drift)

    out = capsys.readouterr().out
    assert "Refresh checklist" in out
    assert "Installed build" in out
    assert "Static plan" in out
    assert "Static run" in out
    assert "tracked static-plan build, not the newly installed build" in out
    assert "Device Inventory & Harvest" in out
    assert "Static Analysis Pipeline" in out
    assert "Analyze one app" in out
    assert "Dynamic Analysis" in out
    assert "App queue / next action" in out
    assert "new current build target" in out


def test_drift_workbench_refresh_checklist_includes_identity_mismatch_caution(monkeypatch, capsys) -> None:
    choices = iter(["R", "0"])
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *_a, **_k: next(choices))
    monkeypatch.setattr(guided_run.prompt_utils, "press_enter_to_continue", lambda: None)

    app = SimpleNamespace(
        package_name="com.twitter.android",
        display_label="X (Twitter)",
        historical_valid_local=3,
        historical_build_count=1,
        db_active_sessions=0,
        db_historical_sessions=0,
        latest_valid=None,
        counts=SimpleNamespace(baseline_valid_runs=0, interactive_valid_runs=0),
        cfg=SimpleNamespace(baseline_required=3, interactive_required=2),
        extra_valid_local=0,
        has_identity_mismatch=True,
        state=SimpleNamespace(),
    )
    plan_drift = {
        "observed_version_code": "312021000",
        "expected_version_code": "312011000",
        "expected_version_name": "12.1.1-release.0",
        "static_run_id": 4695,
    }

    guided_run._render_selected_app_drift_workbench(app=app, plan_drift=plan_drift)

    out = capsys.readouterr().out
    assert "Caution:" in out
    assert "Identity mismatch context exists." in out
