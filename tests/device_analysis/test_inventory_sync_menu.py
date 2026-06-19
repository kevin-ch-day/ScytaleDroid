from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.device_menu import actions, inventory_sync_feedback


def test_run_inventory_sync_runs_full_baseline_mode_directly(monkeypatch) -> None:
    from scytaledroid.DeviceAnalysis import runtime_flags
    from scytaledroid.DeviceAnalysis.workflows import inventory_workflow

    captured: dict[str, object] = {}

    monkeypatch.setattr(
        actions.device_service,
        "fetch_inventory_metadata",
        lambda _serial: SimpleNamespace(status_label="STALE", is_stale=True),
    )
    monkeypatch.setattr(runtime_flags, "set_allow_inventory_fallbacks", lambda _enabled: None)
    monkeypatch.setattr(actions.prompt_utils, "press_enter_to_continue", lambda: None)
    monkeypatch.setattr(
        inventory_workflow,
        "run_inventory_sync",
        lambda *args, **kwargs: captured.update({"args": args, "kwargs": kwargs})
        or SimpleNamespace(stats=SimpleNamespace(total_packages=10), snapshot_id=1, elapsed_seconds=4.0),
    )

    actions._run_inventory_sync({"serial": "SERIAL123", "is_rooted": "Unknown"})

    assert captured["args"][0] == "SERIAL123"
    assert captured["kwargs"]["mode"] == "baseline"


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
    assert options[0].description == "Run a full-device inventory refresh and write a new snapshot."


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
    monkeypatch.setattr(actions.prompt_utils, "press_enter_to_continue", lambda: None)

    prompted: dict[str, object] = {}

    def _prompt_yes_no(prompt: str, *, default: bool = False) -> bool:
        prompted["prompt"] = prompt
        prompted["default"] = default
        return False

    monkeypatch.setattr(actions.prompt_utils, "prompt_yes_no", _prompt_yes_no)
    monkeypatch.setattr(inventory_workflow, "run_inventory_sync", lambda *args, **kwargs: None)

    actions._run_inventory_sync({"serial": "SERIAL123", "is_rooted": "Unknown"})

    out = capsys.readouterr().out
    assert "Snapshot already fresh (34 secs · 546 pkgs)" in out
    assert "This reruns the full-device inventory and writes a new snapshot." in out
    assert prompted["prompt"] == "Continue"
    assert prompted["default"] is False


def test_run_inventory_sync_does_not_show_scope_picker(monkeypatch) -> None:
    from scytaledroid.DeviceAnalysis import runtime_flags
    from scytaledroid.DeviceAnalysis.workflows import inventory_workflow

    captured: dict[str, object] = {"menu_rendered": False}

    monkeypatch.setattr(
        actions.device_service,
        "fetch_inventory_metadata",
        lambda _serial: SimpleNamespace(status_label="STALE", is_stale=True),
    )
    monkeypatch.setattr(runtime_flags, "set_allow_inventory_fallbacks", lambda _enabled: None)
    monkeypatch.setattr(actions.prompt_utils, "press_enter_to_continue", lambda: None)
    monkeypatch.setattr(actions.menu_utils, "render_menu", lambda _spec: captured.__setitem__("menu_rendered", True))
    monkeypatch.setattr(
        inventory_workflow,
        "run_inventory_sync",
        lambda *args, **kwargs: captured.update({"ran": True, "kwargs": kwargs})
        or SimpleNamespace(stats=SimpleNamespace(total_packages=10), snapshot_id=1, elapsed_seconds=4.0),
    )

    actions._run_inventory_sync({"serial": "SERIAL123", "is_rooted": "Unknown"})

    assert captured["menu_rendered"] is False
    assert captured["ran"] is True
    assert captured["kwargs"]["mode"] == "baseline"


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


def test_print_inventory_run_feedback_can_include_mode_label(capsys) -> None:
    result = SimpleNamespace(
        stats=SimpleNamespace(total_packages=546),
        snapshot_id=33,
        elapsed_seconds=125.0,
    )

    inventory_sync_feedback.print_inventory_run_feedback(result, mode_label="harvest-ready")

    out = capsys.readouterr().out
    assert "Refresh inventory (harvest-ready)" in out


def test_run_inventory_sync_feedback_omits_internal_mode_label_for_default_path(monkeypatch, capsys) -> None:
    from scytaledroid.DeviceAnalysis import runtime_flags
    from scytaledroid.DeviceAnalysis.workflows import inventory_workflow

    monkeypatch.setattr(
        actions.device_service,
        "fetch_inventory_metadata",
        lambda _serial: SimpleNamespace(status_label="STALE", is_stale=True),
    )
    monkeypatch.setattr(runtime_flags, "set_allow_inventory_fallbacks", lambda _enabled: None)
    monkeypatch.setattr(actions.prompt_utils, "press_enter_to_continue", lambda: None)
    monkeypatch.setattr(
        inventory_workflow,
        "run_inventory_sync",
        lambda *args, **kwargs: SimpleNamespace(
            stats=SimpleNamespace(total_packages=578),
            snapshot_id=61,
            elapsed_seconds=7.0,
        ),
    )

    actions._run_inventory_sync({"serial": "SERIAL123", "is_rooted": "Unknown"})

    out = capsys.readouterr().out
    assert "Refresh inventory · 578 pkgs · snap 61 · 7s" not in out
    assert "baseline-full" not in out
