from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.metadata import loader


def test_get_latest_inventory_metadata_degrades_when_current_state_listing_is_blocked(
    monkeypatch,
) -> None:
    snapshot_meta = SimpleNamespace(
        captured_at=datetime.now(UTC),
        package_count=10,
        snapshot_id=7,
        package_list_hash="abc",
        package_signature_hash="def",
        build_fingerprint="fingerprint",
        duration_seconds=12.5,
        scope_hashes=None,
        snapshot_type=None,
        scope_hash=None,
        scope_size=None,
        delta_new=None,
        delta_removed=None,
        delta_updated=None,
        delta_changed_count=None,
        delta_split_delta=None,
        delta_details=None,
    )

    monkeypatch.setattr(loader.inventory_service, "load_latest_snapshot_meta", lambda _serial: snapshot_meta)
    monkeypatch.setattr(
        loader.device_service,
        "list_packages_with_versions",
        lambda _serial: (_ for _ in ()).throw(
            RuntimeError(
                "Inventory fallback blocked (pm --show-version* unsupported). "
                "Enable inventory fallbacks in the Device Analysis menu to proceed."
            )
        ),
    )

    metadata = loader.get_latest_inventory_metadata(
        "SER123",
        with_current_state=True,
    )

    assert metadata is not None
    assert metadata["snapshot_id"] == 7
    assert metadata["packages_changed"] is False
    assert metadata["scope_changed"] is False
    assert metadata["build_fingerprint_changed"] is False
    assert metadata["state_changed"] is False
    assert "current_state_unavailable_reason" in metadata


def test_get_latest_inventory_metadata_treats_version_code_change_as_package_change(
    monkeypatch,
) -> None:
    snapshot_meta = SimpleNamespace(
        captured_at=datetime.now(UTC),
        package_count=1,
        snapshot_id=8,
        package_list_hash="abc",
        package_signature_hash="def",
        build_fingerprint="fingerprint",
        duration_seconds=5.0,
        scope_hashes=None,
        snapshot_type=None,
        scope_hash=None,
        scope_size=None,
        delta_new=None,
        delta_removed=None,
        delta_updated=None,
        delta_changed_count=None,
        delta_split_delta=None,
        delta_details=None,
    )

    monkeypatch.setattr(loader.inventory_service, "load_latest_snapshot_meta", lambda _serial: snapshot_meta)
    monkeypatch.setattr(
        loader.inventory_service,
        "load_latest_inventory",
        lambda _serial: {
            "packages": [
                {
                    "package_name": "com.example.app",
                    "version_code": "1",
                    "version_name": "1.0",
                }
            ]
        },
    )
    monkeypatch.setattr(
        loader.device_service,
        "list_packages_with_versions",
        lambda _serial: [("com.example.app", "2", "1.0")],
    )
    monkeypatch.setattr(loader.device_service, "get_basic_properties", lambda _serial: {"build_fingerprint": "fingerprint"})
    monkeypatch.setattr(loader.inventory_service, "compute_signature_hash", lambda entries: "sig")

    metadata = loader.get_latest_inventory_metadata("SER123", with_current_state=True)

    assert metadata is not None
    assert metadata["packages_changed"] is True
    assert metadata["state_changed"] is True
    assert metadata["package_delta_summary"]["total_updated"] == 1


def test_get_latest_inventory_metadata_ignores_version_name_only_change_for_package_identity(
    monkeypatch,
) -> None:
    snapshot_meta = SimpleNamespace(
        captured_at=datetime.now(UTC),
        package_count=1,
        snapshot_id=9,
        package_list_hash="abc",
        package_signature_hash="def",
        build_fingerprint="fingerprint",
        duration_seconds=5.0,
        scope_hashes=None,
        snapshot_type=None,
        scope_hash=None,
        scope_size=None,
        delta_new=None,
        delta_removed=None,
        delta_updated=None,
        delta_changed_count=None,
        delta_split_delta=None,
        delta_details=None,
    )

    monkeypatch.setattr(loader.inventory_service, "load_latest_snapshot_meta", lambda _serial: snapshot_meta)
    monkeypatch.setattr(
        loader.inventory_service,
        "load_latest_inventory",
        lambda _serial: {
            "packages": [
                {
                    "package_name": "com.example.app",
                    "version_code": "1",
                    "version_name": "1.0",
                }
            ]
        },
    )
    monkeypatch.setattr(
        loader.device_service,
        "list_packages_with_versions",
        lambda _serial: [("com.example.app", "1", "2.0")],
    )
    monkeypatch.setattr(loader.device_service, "get_basic_properties", lambda _serial: {"build_fingerprint": "fingerprint"})
    monkeypatch.setattr(loader.inventory_service, "compute_signature_hash", lambda entries: "sig")

    metadata = loader.get_latest_inventory_metadata("SER123", with_current_state=True)

    assert metadata is not None
    assert metadata["packages_changed"] is False
    assert metadata["state_changed"] is False
    assert "package_delta_summary" not in metadata


def test_get_latest_inventory_metadata_ignores_missing_live_version_name_when_version_code_matches(
    monkeypatch,
) -> None:
    snapshot_meta = SimpleNamespace(
        captured_at=datetime.now(UTC),
        package_count=1,
        snapshot_id=11,
        package_list_hash="abc",
        package_signature_hash="def",
        build_fingerprint="fingerprint",
        duration_seconds=5.0,
        scope_hashes=None,
        snapshot_type=None,
        scope_hash=None,
        scope_size=None,
        delta_new=None,
        delta_removed=None,
        delta_updated=None,
        delta_changed_count=None,
        delta_split_delta=None,
        delta_details=None,
    )

    monkeypatch.setattr(loader.inventory_service, "load_latest_snapshot_meta", lambda _serial: snapshot_meta)
    monkeypatch.setattr(
        loader.inventory_service,
        "load_latest_inventory",
        lambda _serial: {
            "packages": [
                {
                    "package_name": "com.example.app",
                    "version_code": "1",
                    "version_name": "1.0",
                }
            ]
        },
    )
    monkeypatch.setattr(
        loader.device_service,
        "list_packages_with_versions",
        lambda _serial: [("com.example.app", "1", None)],
    )
    monkeypatch.setattr(loader.device_service, "get_basic_properties", lambda _serial: {"build_fingerprint": "fingerprint"})
    monkeypatch.setattr(loader.inventory_service, "compute_signature_hash", lambda entries: "sig")

    metadata = loader.get_latest_inventory_metadata("SER123", with_current_state=True)

    assert metadata is not None
    assert metadata["packages_changed"] is False
    assert metadata["state_changed"] is False
    assert "package_delta_summary" not in metadata


def test_get_latest_inventory_metadata_surfaces_collection_mode_and_path_fidelity(
    monkeypatch,
) -> None:
    snapshot_meta = SimpleNamespace(
        captured_at=datetime.now(UTC),
        package_count=2,
        snapshot_id=10,
        package_list_hash="abc",
        package_signature_hash="def",
        build_fingerprint="fingerprint",
        duration_seconds=2.0,
        scope_hashes=None,
        snapshot_type=None,
        scope_hash=None,
        scope_size=None,
        delta_new=None,
        delta_removed=None,
        delta_updated=None,
        delta_changed_count=None,
        delta_split_delta=None,
        delta_details=None,
        collection_mode="bulk",
        identity_source="pm_list_show_versioncode",
        identity_quality="strict",
        path_enriched_packages=1,
        bulk_identity_only_packages=1,
    )

    monkeypatch.setattr(loader.inventory_service, "load_latest_snapshot_meta", lambda _serial: snapshot_meta)
    monkeypatch.setattr(
        loader.inventory_service,
        "load_latest_inventory",
        lambda _serial: {
            "collection_mode": "bulk",
            "identity_source": "pm_list_show_versioncode",
            "identity_quality": "strict",
            "path_enriched_packages": 1,
            "bulk_identity_only_packages": 1,
            "packages": [
                {"package_name": "com.example.one", "path_fidelity": "pm_path"},
                {"package_name": "com.example.two", "path_fidelity": "bulk_base_only"},
            ],
        },
    )

    metadata = loader.get_latest_inventory_metadata("SER123", with_current_state=False)

    assert metadata is not None
    assert metadata["collection_mode"] == "bulk"
    assert metadata["identity_source"] == "pm_list_show_versioncode"
    assert metadata["identity_quality"] == "strict"
    assert metadata["path_enriched_packages"] == 1
    assert metadata["bulk_identity_only_packages"] == 1
