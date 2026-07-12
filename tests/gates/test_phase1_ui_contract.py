from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import main as app_main
import pytest
from scytaledroid.Database.db_utils import schema_gate
from scytaledroid.DeviceAnalysis.device_menu import dashboard
from scytaledroid.Utils.DisplayUtils import status_messages

pytestmark = [pytest.mark.contract, pytest.mark.ui_contract, pytest.mark.gate]


def test_main_menu_uses_phase1_platform_labels(monkeypatch) -> None:
    rendered_menus: list[tuple[list[str], dict[str, object]]] = []

    monkeypatch.setattr(app_main, "ensure_db_ready", lambda: None)
    monkeypatch.setattr(
        schema_gate,
        "check_base_schema",
        lambda: (True, "ready", ""),
    )
    monkeypatch.setattr(app_main, "_print_tier1_status_banner", lambda: {})
    monkeypatch.setattr(app_main.menu_utils, "print_header", lambda *_a, **_k: None)

    def _capture_menu(items, **kwargs):
        rendered_menus.append(([item.label for item in items], kwargs))

    monkeypatch.setattr(app_main.menu_utils, "print_menu", _capture_menu)
    monkeypatch.setattr(app_main.prompt_utils, "get_choice", lambda *_a, **_k: "0")
    monkeypatch.setattr(app_main.status_messages, "print_status", lambda *_a, **_k: None)
    monkeypatch.setattr(app_main.status_messages, "print_strip", lambda *_a, **_k: None)

    app_main.main_menu()

    assert rendered_menus == [
        (
                [
                    "Select device",
                    "Device Inventory & Harvest",
                    "Static Analysis Pipeline",
                    "Dynamic Analysis",
                    "API server",
                    "Reporting",
                    "Database tools",
                    "Governance & Readiness",
                    "Evidence & Workspace",
                    "APK library",
                    "Mercury APK storage mount",
                    "Machine Learning",
                    "About ScytaleDroid",
                ],
            {
                "show_exit": True,
                "exit_label": "Exit",
                "show_descriptions": False,
                "compact": True,
            },
        )
    ]


def test_main_menu_dashboard_shows_selected_device_and_database(monkeypatch, capsys) -> None:
    monkeypatch.setattr(app_main, "ensure_db_ready", lambda: None)
    monkeypatch.setattr(
        schema_gate,
        "check_base_schema",
        lambda: (True, "ready", ""),
    )
    monkeypatch.setattr(app_main, "_print_tier1_status_banner", lambda: {})
    monkeypatch.setattr(app_main, "_emit_main_menu_db_connection_line", lambda *_a, **_k: None)

    from scytaledroid.DeviceAnalysis import device_manager

    monkeypatch.setattr(
        device_manager,
        "describe_active_device",
        lambda: "moto g 5G 2024 · ZY22JK89DR",
    )
    monkeypatch.setattr(
        app_main,
        "_describe_main_menu_database",
        lambda *_a, **_k: "scytaledroid_core_prod @ localhost:3306",
    )
    monkeypatch.setattr(
        app_main,
        "_describe_main_menu_mercury",
        lambda: "mounted at /mnt/MERCURY_DATA_V2",
    )
    monkeypatch.setattr(app_main.prompt_utils, "get_choice", lambda *_a, **_k: "0")
    monkeypatch.setattr(app_main.status_messages, "print_status", lambda *_a, **_k: None)
    monkeypatch.setattr(app_main.status_messages, "print_strip", lambda *_a, **_k: None)

    app_main.main_menu()

    out = capsys.readouterr().out
    assert "Selected device: moto g 5G 2024 · ZY22JK89DR" in out
    assert "Database: scytaledroid_core_prod @ localhost:3306" in out
    assert "Mercury: mounted at /mnt/MERCURY_DATA_V2" in out
    assert "-----" in out


def test_main_menu_mercury_status_variants(monkeypatch) -> None:
    from scytaledroid.Utils.System import mercury_storage

    def _status(*, mounted=False, user_mounted=False, device_exists=True):
        return mercury_storage.MercuryStorageStatus(
            label="MERCURY_DATA_V2",
            device_path=Path("/dev/disk/by-label/MERCURY_DATA_V2"),
            device_exists=device_exists,
            mountpoint=Path("/mnt/MERCURY_DATA_V2"),
            mountpoint_exists=True,
            mountpoint_mounted=mounted,
            user_media_mount=Path("/run/media/secadmin/MERCURY_DATA_V2"),
            user_media_mounted=user_mounted,
            compatibility_alias_exists=False,
            compatibility_alias_target=None,
        )

    monkeypatch.setattr(mercury_storage, "mercury_storage_status", lambda: _status(mounted=True))
    assert app_main._describe_main_menu_mercury() == "mounted at /mnt/MERCURY_DATA_V2"

    monkeypatch.setattr(
        mercury_storage,
        "mercury_storage_status",
        lambda: _status(user_mounted=True),
    )
    assert (
        app_main._describe_main_menu_mercury()
        == "user-session only at /run/media/secadmin/MERCURY_DATA_V2 (use menu 11)"
    )

    monkeypatch.setattr(mercury_storage, "mercury_storage_status", lambda: _status())
    assert app_main._describe_main_menu_mercury() == "not mounted (use menu 11)"

    monkeypatch.setattr(
        mercury_storage,
        "mercury_storage_status",
        lambda: _status(device_exists=False),
    )
    assert app_main._describe_main_menu_mercury() == "drive not detected"


def test_handle_select_device_starts_selector_on_new_line(monkeypatch, capsys) -> None:
    selector_calls = {"count": 0}

    def _fake_select_device(**_kwargs):
        selector_calls["count"] += 1
        print("SELECTOR HEADER")
        return None

    import scytaledroid.DynamicAnalysis.controllers.device_select as device_select_module

    monkeypatch.setattr(device_select_module, "select_device", _fake_select_device)

    app_main.handle_select_device()

    out = capsys.readouterr().out
    assert selector_calls["count"] == 1
    assert out.startswith("\nSELECTOR HEADER\n")


def test_handle_database_starts_menu_on_new_line(monkeypatch, capsys) -> None:
    menu_calls = {"count": 0}

    def _fake_database_menu():
        menu_calls["count"] += 1
        print("DATABASE HEADER")

    import scytaledroid.Database.db_utils.database_menu as database_menu_module

    monkeypatch.setattr(database_menu_module, "database_menu", _fake_database_menu)

    app_main.handle_database()

    out = capsys.readouterr().out
    assert menu_calls["count"] == 1
    assert out.startswith("\nDATABASE HEADER\n")


def test_handle_machine_learning_starts_menu_on_new_line(monkeypatch, capsys) -> None:
    menu_calls = {"count": 0}

    def _fake_ml_menu():
        menu_calls["count"] += 1
        print("ML HEADER")

    import scytaledroid.DynamicAnalysis.ml.menu as ml_menu_module

    monkeypatch.setattr(ml_menu_module, "machine_learning_menu", _fake_ml_menu)

    app_main.handle_machine_learning()

    out = capsys.readouterr().out
    assert menu_calls["count"] == 1
    assert out.startswith("\nML HEADER\n")


def test_main_menu_db_status_suppression_consumes_once() -> None:
    app_main._MAIN_MENU_UI_STATE["suppress_db_status_once"] = False

    app_main._suppress_main_menu_db_status_once()

    assert app_main._consume_main_menu_db_status_suppressed() is True
    assert app_main._consume_main_menu_db_status_suppressed() is False


def test_emit_main_menu_db_disabled_hint_points_to_database_tools(monkeypatch) -> None:
    messages: list[tuple[str, str]] = []

    monkeypatch.setattr(
        app_main.status_messages,
        "print_status",
        lambda message, level="info", **_kwargs: messages.append((str(message), str(level))),
    )

    app_main._emit_main_menu_db_connection_line(False, "Database disabled.", "DB is optional.")

    assert messages[0] == ("DB: off — set DSN in .env (menu 7)", "warn")


def test_environment_metrics_hidden_in_normal_prod_mode(monkeypatch) -> None:
    monkeypatch.setattr(app_main.app_config, "DEBUG_MODE", False)
    monkeypatch.setattr(app_main.app_config, "EXECUTION_MODE", "PROD")
    monkeypatch.setattr(app_main.app_config, "SHOW_RUNTIME_IDENTITY", False)

    metrics = app_main._build_environment_metrics()

    assert metrics == []


def test_environment_metrics_include_debug_runtime_identity(monkeypatch) -> None:
    monkeypatch.setattr(app_main.app_config, "DEBUG_MODE", True)
    monkeypatch.setattr(app_main.app_config, "SYS_TEST", False)
    monkeypatch.setattr(app_main.app_config, "RUNTIME_PRESET", "virtual")
    monkeypatch.setattr(app_main.app_config, "EXECUTION_MODE", "DEV")
    monkeypatch.setattr(app_main.app_config, "SYS_ENV", "VIRTUAL")
    monkeypatch.setattr(app_main.app_config, "SHOW_RUNTIME_IDENTITY", True)

    metrics = app_main._build_environment_metrics()

    assert metrics == [
        ("Preset", "VIRTUAL"),
        ("Mode", "DEV"),
        ("System", "VIRTUAL"),
        ("Debug", "ON"),
    ]


def test_blocked_and_non_root_status_contract(monkeypatch) -> None:
    palette = SimpleNamespace(
        success=("SUCCESS",),
        warning=("WARNING",),
        error=("ERROR",),
        blocked=("BLOCKED",),
        info=("INFO",),
        muted=("MUTED",),
    )

    monkeypatch.setattr(dashboard.colors, "get_palette", lambda: palette)
    monkeypatch.setattr(dashboard.colors, "colors_enabled", lambda: True)
    monkeypatch.setattr(dashboard.colors, "apply", lambda text, style, bold=False: f"<{','.join(style)}>{text}</>")

    blocked_line = status_messages.status("blocked by policy", level="blocked")
    non_root_badge = dashboard._root_badge("NO")

    assert "[BLOCKED]" in blocked_line
    assert "blocked by policy" in blocked_line
    assert any(marker in blocked_line for marker in ("⊘", "-"))

    assert "<INFO>" in non_root_badge
    assert "NON-ROOT" in non_root_badge
    assert "<WARNING>" not in non_root_badge
