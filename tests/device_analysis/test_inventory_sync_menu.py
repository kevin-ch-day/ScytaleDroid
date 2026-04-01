from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.device_menu import actions


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
        "Full device inventory sync (canonical)",
        "Scoped sync: app profile",
    ]
    assert scoped_call["serial"] == "SERIAL123"
    assert scoped_call["scope_id"] == "profile::research_dataset_alpha"
    assert scoped_call["packages"] == {"com.example.alpha", "com.example.beta"}
