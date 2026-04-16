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
            "persisted": 117,
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
    assert "Motorola | 15 | Physical | NON-ROOT" in out
    assert "Summary" in out
    assert "Inventory    : FRESH | 546 packages | 14h 39m ago" in out
    assert "Harvest      : 117 persisted | 411 policy blocked | 18 scope blocked" in out
    assert "Evidence     : aligned with snapshot 26" in out
    assert "Next Step" in out
    assert "Inventory and harvest are aligned. Static analysis can proceed." in out
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
            "persisted": 117,
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
    assert "Status       : FRESH | Last sync : 14 Hrs 39 Mins ago | Packages : 546" in out
    assert "Inventory    : inventoried 546 | in scope 546 | eligible 117" in out
    assert "Harvest      : scheduled 117 | harvested 117 | persisted 117" in out
    assert "Blocked      : 411 policy | 18 scope" in out
    assert "Evidence and Paths" in out
    assert "Latest harvest  : 20260416" in out
    assert "Alignment       : current" in out
    assert "Artifacts root  : data/device_apks/ZY22JK89DR/20260416" in out
    assert "Receipts root   : data/receipts/harvest/20260416" in out
