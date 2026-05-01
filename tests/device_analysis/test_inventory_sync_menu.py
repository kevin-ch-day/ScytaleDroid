from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.device_menu import actions, inventory_sync_feedback


def test_select_inventory_sync_profile_auto_selects_single_active_profile(monkeypatch, capsys) -> None:
    from scytaledroid.DynamicAnalysis import profile_loader

    monkeypatch.setattr(
        profile_loader,
        "load_db_profiles",
        lambda: [
            {
                "profile_key": "RESEARCH_DATASET_ALPHA",
                "display_name": "Research Dataset Alpha",
                "app_count": 12,
            }
        ],
    )
    monkeypatch.setattr(
        profile_loader,
        "load_profile_packages",
        lambda profile_key: {"com.example.alpha"} if profile_key == "RESEARCH_DATASET_ALPHA" else set(),
    )
    monkeypatch.setattr(actions.prompt_utils, "press_enter_to_continue", lambda: None)

    selected = actions._select_inventory_sync_profile()

    assert selected is not None
    assert selected["profile_key"] == "RESEARCH_DATASET_ALPHA"
    assert selected["scope_id"] == "profile::research_dataset_alpha"
    out = capsys.readouterr().out
    assert "Only one active profile is available" in out


def test_run_inventory_sync_menu_uses_profile_scoped_sync_and_drops_paper_labels(monkeypatch) -> None:
    from scytaledroid.DeviceAnalysis import runtime_flags
    from scytaledroid.DeviceAnalysis.workflows import inventory_workflow
    from scytaledroid.DynamicAnalysis import profile_loader

    captured_menu: dict[str, list[str]] = {}
    scoped_call: dict[str, object] = {}

    monkeypatch.setattr(
        actions.device_service,
        "fetch_inventory_metadata",
        lambda _serial: SimpleNamespace(status_label="STALE", is_stale=True),
    )
    monkeypatch.setattr(runtime_flags, "set_allow_inventory_fallbacks", lambda _enabled: None)
    monkeypatch.setattr(actions.menu_utils, "print_header", lambda *args, **kwargs: None)

    def _capture_menu(spec):
        captured_menu["labels"] = [item.label for item in spec.items]

    monkeypatch.setattr(actions.menu_utils, "render_menu", _capture_menu)
    monkeypatch.setattr(actions.prompt_utils, "press_enter_to_continue", lambda: None)

    prompts = iter(["2"])
    monkeypatch.setattr(actions.prompt_utils, "get_choice", lambda *args, **kwargs: next(prompts))

    monkeypatch.setattr(
        profile_loader,
        "load_db_profiles",
        lambda: [
            {
                "profile_key": "RESEARCH_DATASET_ALPHA",
                "display_name": "Research Dataset Alpha",
                "app_count": 12,
            }
        ],
    )
    monkeypatch.setattr(
        profile_loader,
        "load_profile_packages",
        lambda profile_key: {"com.example.alpha", "com.example.beta"}
        if profile_key == "RESEARCH_DATASET_ALPHA"
        else set(),
    )

    monkeypatch.setattr(
        inventory_workflow,
        "run_inventory_scoped_sync",
        lambda **kwargs: scoped_call.update(kwargs),
    )
    monkeypatch.setattr(
        inventory_workflow,
        "run_inventory_sync",
        lambda *args, **kwargs: None,
    )

    actions._run_inventory_sync({"serial": "SERIAL123", "is_rooted": "Unknown"})

    assert captured_menu["labels"] == [
        actions.inventory_cli_labels.MENU_OPTION_FULL,
        actions.inventory_cli_labels.MENU_OPTION_SCOPED,
    ]
    assert scoped_call["serial"] == "SERIAL123"
    assert scoped_call["scope_id"] == "profile::research_dataset_alpha"
    assert scoped_call["packages"] == {"com.example.alpha", "com.example.beta"}


def test_build_main_menu_options_uses_pipeline_language(monkeypatch) -> None:
    monkeypatch.setattr(
        actions.device_service,
        "fetch_inventory_metadata",
        lambda _serial: SimpleNamespace(status_label="FRESH", is_stale=False),
    )

    options = actions.build_main_menu_options({"serial": "SERIAL123"})
    labels = [option.label for option in options]

    assert labels[:4] == [
        "Refresh inventory",
        "Execute harvest",
        "View inventory and harvest details",
        "Open device logcat",
    ]
    assert labels[5] == "Switch device"
    assert "Browse harvested APKs" in labels
    assert "Export device summary" in labels
    assert "Manage harvest scope/watchlists" in labels


def test_run_inventory_sync_uses_compact_fresh_resync_confirmation(monkeypatch, capsys) -> None:
    from scytaledroid.DeviceAnalysis import runtime_flags
    from scytaledroid.DeviceAnalysis.workflows import inventory_workflow

    monkeypatch.setattr(
        actions.device_service,
        "fetch_inventory_metadata",
        lambda _serial: SimpleNamespace(
            status_label="FRESH",
            is_stale=False,
            age_display="34s",
            package_count=546,
        ),
    )
    monkeypatch.setattr(runtime_flags, "set_allow_inventory_fallbacks", lambda _enabled: None)
    monkeypatch.setattr(actions.menu_utils, "print_header", lambda *args, **kwargs: None)
    monkeypatch.setattr(actions.menu_utils, "render_menu", lambda _spec: None)
    monkeypatch.setattr(actions.prompt_utils, "press_enter_to_continue", lambda: None)
    monkeypatch.setattr(actions.prompt_utils, "get_choice", lambda *args, **kwargs: "1")

    prompted: dict[str, object] = {}

    def _prompt_yes_no(prompt: str, *, default: bool = False) -> bool:
        prompted["prompt"] = prompt
        prompted["default"] = default
        return False

    monkeypatch.setattr(actions.prompt_utils, "prompt_yes_no", _prompt_yes_no)
    monkeypatch.setattr(inventory_workflow, "run_inventory_sync", lambda *args, **kwargs: None)

    actions._run_inventory_sync({"serial": "SERIAL123", "is_rooted": "Unknown"})

    out = capsys.readouterr().out
    assert "Snapshot already fresh (34s · 546 pkgs)" in out
    assert prompted["prompt"] == "Continue"
    assert prompted["default"] is False


def test_print_inventory_run_feedback_uses_single_compact_success_line(capsys) -> None:
    result = SimpleNamespace(
        stats=SimpleNamespace(total_packages=546),
        snapshot_id=33,
        elapsed_seconds=125.0,
    )

    inventory_sync_feedback.print_inventory_run_feedback(result)

    out = capsys.readouterr().out
    assert "Refresh inventory ·" in out
    assert "546 pkgs" in out and "snap 33" in out
    assert "2m 05s" in out
    assert "Snapshot ID:" not in out
