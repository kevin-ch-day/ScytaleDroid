from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.device_menu import dashboard
from scytaledroid.Utils.DisplayUtils import colors


def test_print_dashboard_uses_compact_active_device_layout(monkeypatch, capsys) -> None:
    active = {
        "serial": "ZY22JK89DR",
        "model": "moto g 5G - 2024",
        "manufacturer": "Motorola",
        "android_release": "15",
        "device_type": "Physical",
        "wifi_state": "On",
        "battery_pct": "100",
        "battery_status": "Charging",
        "is_rooted": "NO",
    }
    inventory = SimpleNamespace(status_label="FRESH", age_display="14 Hrs 39 Mins", package_count=546)

    monkeypatch.setattr(
        dashboard,
        "_compute_pipeline_state",
        lambda _serial: {
            "inventoried": 546,
            "in_scope": 546,
            "policy_eligible": 117,
            "scheduled": 117,
            "harvested": 117,
            "receipts": 546,
            "blocked_policy": 411,
            "blocked_scope": 18,
            "inventory_snapshot_id": 26,
            "latest_harvest": {
                "session_label": "20260416",
                "snapshot_id": 26,
                "artifacts_root": "data/device_apks/ZY22JK89DR/20260416",
                "receipts_root": "data/receipts/harvest/20260416",
            },
        },
    )
    dashboard.print_dashboard(
        summaries=[active],
        active_details=active,
        warnings=[],
        last_refresh_ts=None,
        serial_map={"ZY22JK89DR": active},
        inventory_metadata=inventory,
    )

    out = colors.strip(capsys.readouterr().out)
    assert "moto g 5G - 2024 (ZY22JK89DR)" in out
    assert "moto g 5G - 2024 (ZY22JK89DR) | Physical | Motorola" not in out
    assert "Motorola" in out and "Android 15" in out and "Physical" in out and "NON-ROOT" in out
    assert "Inv" in out and "Har" in out and "Ev" in out
    assert "546 pkgs" in out and "14h 39m ago" in out
    assert "117 hv" in out and "411 pol" in out and "18 sc" in out
    assert "OK @ 26" in out
    assert "Next: static analysis (menu 2)" in out
    assert "Device Capability" not in out
    assert "Pipeline State" not in out
    assert "Artifacts root:" not in out
    assert "Receipts root:" not in out
    assert "Root access" not in out
    assert "NON-ROOT" in out
    assert "1) Refresh inventory" in out
    assert "2) Execute harvest" in out
    assert "6) Switch device" in out
    assert "7) Export device summary" in out
    assert "9) Manage harvest scope/watchlists" in out
    assert "0) Back" in out
    assert "Primary" not in out
    assert "Device tools" not in out
    assert "Artifacts / exports" not in out
    assert "Advanced" not in out


def test_print_dashboard_hint_when_active_but_no_adb_rows(capsys) -> None:
    active = {"serial": "ZY22JK89DR", "model": "test", "manufacturer": "ACME", "android_release": "15"}
    dashboard.print_dashboard(
        summaries=[],
        active_details=active,
        warnings=[],
        last_refresh_ts=None,
        serial_map={},
        inventory_metadata=None,
    )
    out = colors.strip(capsys.readouterr().out)
    assert "ADB listed no devices" in out
    assert "ZY22JK89DR" in out


def test_print_device_details_shows_moved_pipeline_and_evidence_blocks(monkeypatch, capsys) -> None:
    active = {
        "serial": "ZY22JK89DR",
        "model": "moto g 5G - 2024",
        "manufacturer": "Motorola",
        "android_release": "15",
        "device_type": "Physical",
        "wifi_state": "On",
        "battery_pct": "100",
        "battery_status": "Charging",
        "is_rooted": "NO",
    }
    inventory = SimpleNamespace(status_label="FRESH", age_display="14 Hrs 39 Mins", package_count=546)

    monkeypatch.setattr(
        dashboard,
        "_compute_pipeline_state",
        lambda _serial: {
            "inventoried": 546,
            "in_scope": 546,
            "policy_eligible": 117,
            "scheduled": 117,
            "harvested": 117,
            "receipts": 546,
            "blocked_policy": 411,
            "blocked_scope": 18,
            "inventory_snapshot_id": 26,
            "latest_harvest": {
                "session_label": "20260416",
                "snapshot_id": 26,
                "artifacts_root": "data/device_apks/ZY22JK89DR/20260416",
                "receipts_root": "data/receipts/harvest/20260416",
            },
        },
    )

    dashboard.print_device_details(active, inventory)
    out = colors.strip(capsys.readouterr().out)

    assert "Device Capability" in out
    assert "Wi-Fi" in out
    assert "Battery" in out
    assert "Root access" in out
    assert "Inventory and Harvest" in out
    assert "Status       : FRESH | Last sync : 14h 39m ago | Packages : 546" in out
    assert "Inventory    : 546 inventoried | 546 in scope | 117 eligible" in out
    assert "Harvest      : 117 scheduled | 117 harvested | 546 receipts" in out
    assert "Blocked      : 411 policy | 18 scope" in out
    assert "Evidence and Paths" in out
    assert "Latest harvest  : 20260416" in out
    assert "Alignment       : current" in out
    assert "Artifacts root  : data/device_apks/ZY22JK89DR/20260416" in out
    assert "Receipts root   : data/receipts/harvest/20260416" in out


def test_dashboard_next_step_explains_inventory_harvest_misalignment(monkeypatch, capsys) -> None:
    active = {
        "serial": "ZY22JK89DR",
        "model": "moto g 5G - 2024",
        "manufacturer": "Motorola",
        "android_release": "15",
        "device_type": "Physical",
        "wifi_state": "On",
        "battery_pct": "100",
        "battery_status": "Charging",
        "is_rooted": "NO",
    }
    inventory = SimpleNamespace(status_label="FRESH", age_display="10 Secs", package_count=546)

    monkeypatch.setattr(
        dashboard,
        "_compute_pipeline_state",
        lambda _serial: {
            "inventoried": 546,
            "in_scope": 546,
            "policy_eligible": 120,
            "scheduled": 120,
            "harvested": 120,
            "receipts": 546,
            "blocked_policy": 426,
            "blocked_scope": 0,
            "inventory_snapshot_id": 31,
            "latest_harvest": {
                "session_label": "20260427",
                "snapshot_id": 30,
                "artifacts_root": "data/device_apks/ZY22JK89DR/20260427",
                "receipts_root": "data/receipts/harvest/20260427",
            },
        },
    )
    dashboard.print_dashboard(
        summaries=[active],
        active_details=active,
        warnings=[],
        last_refresh_ts=None,
        serial_map={"ZY22JK89DR": active},
        inventory_metadata=inventory,
    )

    out = colors.strip(capsys.readouterr().out)
    assert "stale hv 30 vs inv 31" in out
    assert "Next: run harvest (2) to match latest inventory." in out
