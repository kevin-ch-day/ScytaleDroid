from scytaledroid.DeviceAnalysis.harvest import scope_context
from scytaledroid.DeviceAnalysis.harvest.models import InventoryRow


def _row(package: str, *, installer="com.android.vending", primary="/data/app/pkg", split=1) -> InventoryRow:
    return InventoryRow(
        raw={},
        package_name=package,
        app_label=package,
        installer=installer,
        category=None,
        primary_path=primary,
        profile_key=None,
        profile=None,
        version_name=None,
        version_code=None,
        apk_paths=[],
        split_count=split,
    )


def test_apply_default_scope_filters_non_user_partition():
    rows = [
        _row("com.play.app", primary="/system/app/foo"),
        _row("com.play.user", primary="/data/app/foo"),
    ]
    kept, excluded = scope_context.apply_default_scope(rows, set())
    assert len(kept) == 1
    assert kept[0].package_name == "com.play.user"
    assert excluded.get("non_root_paths") == 1


def test_hydrate_missing_rows_includes_version_code(monkeypatch):
    # Import inside test so monkeypatches apply to the module under test.
    from scytaledroid.DeviceAnalysis.harvest import scope as scope_mod

    pkg = "com.example.app"

    # Stub runtime flag used by hydration.
    import scytaledroid.DeviceAnalysis.runtime_flags as runtime_flags

    monkeypatch.setattr(runtime_flags, "allow_inventory_fallbacks", lambda: True)

    # The function imports scytaledroid.DeviceAnalysis.adb.packages lazily; patch that module.
    import scytaledroid.DeviceAnalysis.adb.packages as adb_packages

    monkeypatch.setattr(
        adb_packages,
        "list_packages_with_versions",
        lambda serial, allow_fallbacks=False: [(pkg, "123", "1.2.3")],
    )
    monkeypatch.setattr(
        adb_packages,
        "get_package_paths",
        lambda serial, package_name, refresh=False, allow_fallbacks=False: [
            "/data/app/com.example.app/base.apk"
        ],
    )
    monkeypatch.setattr(
        adb_packages,
        "get_package_metadata",
        lambda serial, package_name, refresh=False: {
            "app_label": "Example",
            "installer": "com.android.vending",
        },
    )

    hydrated = scope_mod._hydrate_missing_rows_from_adb(
        device_serial="SERIAL", missing_packages={pkg}
    )
    assert hydrated
    row = hydrated[0]
    assert row.package_name == pkg
    assert row.version_code == "123"
    assert row.version_name == "1.2.3"


def test_estimated_files_counts_splits():
    rows = [_row("com.example", split=3)]
    assert scope_context.estimated_files(rows) == 3


def test_sample_names_limits_length():
    rows = [_row(f"pkg{i}") for i in range(5)]
    names = scope_context.sample_names(rows, limit=3)
    assert names == ["pkg0", "pkg1", "pkg2"]
