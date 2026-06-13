from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.harvest import package_refresh
from scytaledroid.DeviceAnalysis.harvest.models import ArtifactPlan, InventoryRow, PackagePlan


def test_refresh_inventory_row_from_device_avoids_pm_dump_when_identity_metadata_exists(
    monkeypatch,
) -> None:
    from scytaledroid.DeviceAnalysis.adb import packages as adb_packages
    from scytaledroid.DeviceAnalysis import runtime_flags

    monkeypatch.setattr(runtime_flags, "allow_inventory_fallbacks", lambda: False)
    monkeypatch.setattr(
        adb_packages,
        "get_package_paths",
        lambda *_args, **_kwargs: [
            "/data/app/~~newtoken/com.example.app/base.apk",
            "/data/app/~~newtoken/com.example.app/split_config.en.apk",
        ],
    )
    monkeypatch.setattr(
        adb_packages,
        "list_packages_with_versions",
        lambda *_args, **_kwargs: [("com.example.app", "42", None)],
    )
    monkeypatch.setattr(
        adb_packages,
        "get_package_metadata",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("pm dump should not run")),
    )

    inventory = InventoryRow(
        raw={},
        package_name="com.example.app",
        app_label="Example App",
        installer="com.android.vending",
        category=None,
        primary_path="/data/app/~~oldtoken/com.example.app/base.apk",
        profile_key="TEST_PROFILE",
        profile=None,
        version_name="4.1",
        version_code="41",
        apk_paths=["/data/app/~~oldtoken/com.example.app/base.apk"],
        split_count=1,
    )

    refreshed = package_refresh.refresh_inventory_row_from_device("SER123", inventory)

    assert refreshed.version_code == "42"
    assert refreshed.version_name == "4.1"
    assert refreshed.app_label == "Example App"
    assert refreshed.installer == "com.android.vending"
    assert refreshed.primary_path == "/data/app/~~newtoken/com.example.app/base.apk"
    assert refreshed.apk_paths == [
        "/data/app/~~newtoken/com.example.app/base.apk",
        "/data/app/~~newtoken/com.example.app/split_config.en.apk",
    ]
    assert refreshed.split_count == 2


def test_refresh_inventory_row_from_device_falls_back_to_pm_dump_when_metadata_missing(
    monkeypatch,
) -> None:
    from scytaledroid.DeviceAnalysis.adb import packages as adb_packages
    from scytaledroid.DeviceAnalysis import runtime_flags

    monkeypatch.setattr(runtime_flags, "allow_inventory_fallbacks", lambda: False)
    monkeypatch.setattr(
        adb_packages,
        "get_package_paths",
        lambda *_args, **_kwargs: ["/data/app/~~newtoken/com.example.app/base.apk"],
    )
    monkeypatch.setattr(
        adb_packages,
        "list_packages_with_versions",
        lambda *_args, **_kwargs: [("com.example.app", "42", "4.2")],
    )
    monkeypatch.setattr(
        adb_packages,
        "get_package_metadata",
        lambda *_args, **_kwargs: {
            "app_label": "Example App",
            "installer": "com.android.vending",
            "version_name": "4.2",
        },
    )

    inventory = InventoryRow(
        raw={},
        package_name="com.example.app",
        app_label=None,
        installer=None,
        category=None,
        primary_path="/data/app/~~oldtoken/com.example.app/base.apk",
        profile_key="TEST_PROFILE",
        profile=None,
        version_name=None,
        version_code="41",
        apk_paths=["/data/app/~~oldtoken/com.example.app/base.apk"],
        split_count=1,
    )

    refreshed = package_refresh.refresh_inventory_row_from_device("SER123", inventory)

    assert refreshed.version_code == "42"
    assert refreshed.version_name == "4.2"
    assert refreshed.app_label == "Example App"
    assert refreshed.installer == "com.android.vending"


def test_replan_package_after_stale_path_ignores_version_name_only_drift(monkeypatch) -> None:
    inventory = InventoryRow(
        raw={},
        package_name="com.example.app",
        app_label="Example App",
        installer="com.android.vending",
        category=None,
        primary_path="/data/app/com.example.app/base.apk",
        profile_key="TEST_PROFILE",
        profile=None,
        version_name="1.0",
        version_code="42",
        apk_paths=["/data/app/com.example.app/base.apk"],
        split_count=1,
    )
    original_plan = PackagePlan(
        inventory=inventory,
        artifacts=[
            ArtifactPlan(
                source_path="/data/app/com.example.app/base.apk",
                artifact="base",
                file_name="com_example_app_42__base.apk",
                is_split_member=False,
            )
        ],
        total_paths=1,
    )
    refreshed_inventory = InventoryRow(
        raw={},
        package_name="com.example.app",
        app_label="Example App",
        installer="com.android.vending",
        category=None,
        primary_path="/data/app/com.example.app/base.apk",
        profile_key="TEST_PROFILE",
        profile=None,
        version_name=None,
        version_code="42",
        apk_paths=["/data/app/com.example.app/base.apk"],
        split_count=1,
    )
    refreshed_plan = PackagePlan(
        inventory=refreshed_inventory,
        artifacts=[
            ArtifactPlan(
                source_path="/data/app/com.example.app/base.apk",
                artifact="base",
                file_name="com_example_app_42__base.apk",
                is_split_member=False,
            )
        ],
        total_paths=1,
    )

    monkeypatch.setattr(
        package_refresh,
        "refresh_inventory_row_from_device",
        lambda _serial, _inventory: refreshed_inventory,
    )
    monkeypatch.setattr(
        package_refresh,
        "include_system_partitions_for_plan",
        lambda _plan: False,
    )
    monkeypatch.setattr(
        "scytaledroid.DeviceAnalysis.harvest.planner.build_harvest_plan",
        lambda *_args, **_kwargs: SimpleNamespace(packages=[refreshed_plan]),
    )

    updated_plan, drift_reasons = package_refresh.replan_package_after_stale_path(
        serial="SER123",
        plan=original_plan,
    )

    assert updated_plan == refreshed_plan
    assert drift_reasons == ()
