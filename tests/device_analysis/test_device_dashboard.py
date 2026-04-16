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
    monkeypatch.setattr("scytaledroid.DeviceAnalysis.device_menu.actions.build_main_menu_options", lambda *_a, **_k: [])
    monkeypatch.setattr(dashboard.menu_utils, "render_menu", lambda *_a, **_k: None)

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
    assert "Device Capability" in out
    assert "State        : FRESH" in out
    assert "Packages     : 546" in out
    assert "Root access" in out
    assert "NON-ROOT" in out
    assert "Pipeline State" in out
    assert "Inventory" in out
    assert "Planning" in out
    assert "Execution" in out
    assert "Alignment: current" in out
    assert "Note: scope is selected before policy filtering." not in out
    assert "Root access" in out
    assert "Latest harvest: 20260416" in out
