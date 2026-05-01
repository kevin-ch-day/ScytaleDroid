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
        lambda serial, package_name, refresh=False, allow_fallbacks=False: ["/data/app/com.example.app/base.apk"],
    )
    monkeypatch.setattr(
        adb_packages,
        "get_package_metadata",
        lambda serial, package_name, refresh=False: {"app_label": "Example", "installer": "com.android.vending"},
    )

    hydrated = scope_mod._hydrate_missing_rows_from_adb(device_serial="SERIAL", missing_packages={pkg})
    assert hydrated
    row = hydrated[0]
    assert row.package_name == pkg
    assert row.version_code == "123"
    assert row.version_name == "1.2.3"
