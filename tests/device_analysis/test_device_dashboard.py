from __future__ import annotations

import json
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
    inventory = SimpleNamespace(
        status_label="FRESH",
        age_display="14 Hrs 39 Mins",
        package_count=546,
        collection_mode="bulk",
    )

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
    assert "546 pkgs" in out and "14 hrs 39 mins ago" in out
    assert "Inv FRESH" in out and "harvest-ready" in out
    # Compact pipeline strip: word labels (operator-readable) vs legacy "117 hv" tokens
    assert "117" in out and "411" in out and "18" in out
    assert "pullable" in out and "policy-blocked" in out and "scope-blocked" in out
    assert "117 resolved" in out
    assert "Harvest 117" not in out
    assert "aligned to 26" in out
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
    inventory = SimpleNamespace(
        status_label="FRESH",
        age_display="14 Hrs 39 Mins",
        package_count=546,
        collection_mode="bulk",
        identity_source="pm_list_show_versioncode",
        identity_quality="strict",
        path_enriched_packages=117,
        bulk_identity_only_packages=429,
        current_state_unavailable_reason="pm list unsupported",
    )

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
    assert "Status       : FRESH | Last sync : 14 hrs 39 mins ago | Packages : 546" in out
    assert "Inventory    : 546 inventoried | 546 in scope | 117 eligible" in out
    assert "Harvest      : 117 scheduled | 117 resolved | 546 receipts" in out
    assert "Blocked      : 411 policy | 18 scope" in out
    assert "Mode         : harvest-ready" in out
    assert "Identity     : pm_list_show_versioncode | strict" in out
    assert "Path detail  : 117 enriched | 429 bulk-only" in out
    assert "Live compare : unavailable" in out
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
    inventory = SimpleNamespace(
        status_label="FRESH",
        age_display="10 Secs",
        package_count=546,
        collection_mode="bulk",
    )

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
    assert "harvest 30 vs inventory 31" in out
    assert "Next: run harvest (2) to match latest inventory." in out


def test_dashboard_compact_status_marks_aligned_drifted_harvest_for_review(monkeypatch, capsys) -> None:
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
    inventory = SimpleNamespace(
        status_label="FRESH",
        age_display="10 Secs",
        package_count=546,
        collection_mode="bulk",
    )

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
                "snapshot_id": 31,
                "session_state": "drifted",
                "session_note": "1 drifted package(s)",
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
    assert "aligned to 31 but latest harvest needs review (1 drifted package(s))" in out
    assert "Next: review latest harvest drift/issues, then refresh inventory or re-harvest as needed." in out


def test_latest_harvest_overview_groups_package_manifests_by_session_and_ignores_policy_blocks(
    monkeypatch, tmp_path
) -> None:
    serial = "ZY22JK89DR"
    session = "ZY22JK89DR-20260708-025120-462407"
    device_root = tmp_path / "device_apks"
    receipts_root = tmp_path / "receipts" / "harvest"

    def write_manifest(package: str, capture_status: str, *, preflight_reason: str | None) -> None:
        leaf = device_root / serial / "runs" / session / package / f"{package}_v1"
        leaf.mkdir(parents=True)
        payload = {
            "package": {"package_name": package, "session_label": session, "snapshot_id": 79},
            "planning": {"preflight_reason": preflight_reason},
            "status": {
                "capture_status": capture_status,
                "persistence_status": "not_requested" if preflight_reason else "mirrored",
                "research_status": "ineligible" if preflight_reason else "pending_audit",
            },
        }
        (leaf / "harvest_package_manifest.json").write_text(json.dumps(payload), encoding="utf-8")

    write_manifest("com.example.clean_one", "clean", preflight_reason=None)
    write_manifest("com.example.clean_two", "clean", preflight_reason=None)
    write_manifest("com.example.policy_blocked", "failed", preflight_reason="policy_non_root")
    (receipts_root / session).mkdir(parents=True)
    for package in ("com.example.clean_one", "com.example.clean_two", "com.example.policy_blocked"):
        (receipts_root / session / f"{package}.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(dashboard.artifact_store, "device_apks_root", lambda: device_root)
    monkeypatch.setattr(dashboard.artifact_store, "harvest_receipts_root", lambda: receipts_root)
    monkeypatch.setattr(dashboard.artifact_store, "repo_relative_path", lambda path: str(path))

    overview = dashboard._load_latest_harvest_overview(serial)

    assert overview["session_label"] == session
    assert overview["manifest_count"] == 3
    assert overview["receipt_count"] == 3
    assert overview["executed"] == 2
    assert overview["blocked_policy"] == 1
    assert overview["session_state"] == "current"
    assert overview["session_note"] is None


def test_dashboard_compact_status_uses_operator_friendly_full_refresh_label(monkeypatch, capsys) -> None:
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
    inventory = SimpleNamespace(
        status_label="STALE",
        age_display="2 Days 22 Hrs 16 Mins",
        package_count=578,
        collection_mode="baseline",
    )

    monkeypatch.setattr(
        dashboard,
        "_compute_pipeline_state",
        lambda _serial: {
            "inventoried": 578,
            "in_scope": 578,
            "policy_eligible": 152,
            "scheduled": 152,
            "harvested": 1,
            "receipts": 578,
            "blocked_policy": 426,
            "blocked_scope": 0,
            "inventory_snapshot_id": 60,
            "latest_harvest": {
                "session_label": "20260615",
                "snapshot_id": 60,
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
    assert "full device" in out
    assert "baseline-full" not in out
    assert "aligned to 60" in out
    assert "1 resolved" in out


def test_print_device_details_marks_aligned_drifted_harvest_for_review(monkeypatch, capsys) -> None:
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
    inventory = SimpleNamespace(
        status_label="FRESH",
        age_display="14 Hrs 39 Mins",
        package_count=546,
        collection_mode="bulk",
        identity_source="pm_list_show_versioncode",
        identity_quality="strict",
        path_enriched_packages=117,
        bulk_identity_only_packages=429,
        current_state_unavailable_reason="pm list unsupported",
    )

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
                "session_state": "drifted",
                "session_note": "1 drifted package(s)",
                "artifacts_root": "data/device_apks/ZY22JK89DR/20260416",
                "receipts_root": "data/receipts/harvest/20260416",
            },
        },
    )

    dashboard.print_device_details(active, inventory)
    out = colors.strip(capsys.readouterr().out)

    assert "Snapshot link   : inventory snapshot 26" in out
    assert "Alignment       : needs review (1 drifted package(s))" in out
    assert "Alignment       : current" not in out
