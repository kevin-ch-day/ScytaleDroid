from scytaledroid.DeviceAnalysis import inventory_meta, package_inventory
from scytaledroid.DeviceAnalysis.inventory import adb_bulk
from scytaledroid.DeviceAnalysis.inventory import normalizer, package_collection
from types import SimpleNamespace


def test_compose_inventory_entry_sorts_paths_and_counts_splits():
    paths = [
        "/product/app/pkg/base.apk",
        "/product/app/pkg/split_b.apk",
        "/product/app/pkg/split_a.apk",
    ]
    metadata = {"installer": "com.android.vending", "version_name": "1.0", "version_code": "100"}
    entry = normalizer.compose_inventory_entry("com.example.app", paths, metadata, canonical=None)

    assert entry["package_name"] == "com.example.app"
    assert entry["split_count"] == 3
    # apk_dirs should be sorted unique directories
    assert entry["apk_dirs"] == ["/product/app/pkg"]
    # primary_path preserves first element
    assert entry["primary_path"] == paths[0]


def test_split_count_defaults_to_one_when_single_path():
    entry = normalizer.compose_inventory_entry("com.example.app", ["/data/app/base.apk"], {}, None)
    assert entry["split_count"] == 1
    assert entry["split_flag"] == "No"


def test_split_count_handles_string_flags():
    entry = {"apk_paths": ["/data/app/base.apk", "/data/app/split.apk"], "split_count": "yes"}
    assert normalizer.split_count(entry) == 2


def test_parse_package_listing_preserves_raw_package_case():
    parsed = package_inventory._parse_package_listing(
        "package:com.qualcomm.qti.uimGbaApp versionCode:35\n"
    )

    assert parsed == [("com.qualcomm.qti.uimGbaApp", "35", None)]


def test_list_packages_with_versions_uses_portable_versioncode_only_probe(monkeypatch):
    calls: list[list[str]] = []

    def _run_shell_command(_serial, command, timeout=20):
        calls.append(command)
        return SimpleNamespace(
            returncode=0,
            stdout="package:com.example.app versionCode:42\n",
        )

    monkeypatch.setattr(package_inventory.adb_client, "run_shell_command", _run_shell_command)

    rows = package_inventory.list_packages_with_versions("SER123", allow_fallbacks=False)

    assert calls == [["pm", "list", "packages", "--show-versioncode"]]
    assert rows == [("com.example.app", "42", None)]


def test_list_packages_with_versions_falls_back_to_package_only_when_versioncode_unsupported(
    monkeypatch,
):
    monkeypatch.setattr(
        package_inventory.adb_client,
        "run_shell_command",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout=""),
    )
    monkeypatch.setattr(package_inventory, "list_packages", lambda _serial: ["com.example.app"])

    rows = package_inventory.list_packages_with_versions("SER123", allow_fallbacks=True)

    assert rows == [("com.example.app", None, None)]


def test_collect_inventory_uses_raw_package_for_adb_and_normalized_hash(monkeypatch):
    raw_package_name = "com.qualcomm.qti.uimGbaApp"
    adb_calls: list[str] = []

    monkeypatch.setattr(package_collection.adb_client, "clear_package_caches", lambda _serial: None)
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_packages",
        lambda _serial, _use_bulk, allow_fallbacks=False: (
            [(raw_package_name, "35", None)],
            [raw_package_name],
            False,
            False,
        ),
    )
    monkeypatch.setattr(package_collection.adb_client, "get_device_properties", lambda _serial: {})
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_paths",
        lambda _serial, package_name, allow_fallbacks=False: adb_calls.append(package_name)
        or ["/product/app/uimgbaservice/uimgbaservice.apk"],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata",
        lambda _serial, _package_name: {"app_label": "uimGbaApp"},
    )
    monkeypatch.setattr(package_collection.snapshot_io, "load_canonical_metadata", lambda _names: {})

    rows, stats = package_collection.collect_inventory("SER123", allow_fallbacks=False)

    assert adb_calls == [raw_package_name]
    assert rows[0]["package_name"] == "com.qualcomm.qti.uimgbaapp"
    assert rows[0]["version_code"] == "35"
    assert stats.package_list_hash == inventory_meta.compute_name_hash(["com.qualcomm.qti.uimgbaapp"])


def test_parse_bulk_package_listing_captures_path_installer_uid_and_version_code():
    entry = adb_bulk._parse_pm_list_line(
        "package:/data/app/~~abc/pkg-base/base.apk=com.example.app "
        "installer=com.android.vending uid:10234 versionCode:77 user:0"
    )

    assert entry is not None
    assert entry.package_name == "com.example.app"
    assert entry.apk_path == "/data/app/~~abc/pkg-base/base.apk"
    assert entry.installer == "com.android.vending"
    assert entry.uid == 10234
    assert entry.version_code == "77"
    assert entry.user == "0"


def test_parse_bulk_package_listing_real_android15_line_tolerates_null_installer():
    entry = adb_bulk._parse_pm_list_line(
        "package:/product/priv-app/VzwDeviceSetup/VzwDeviceSetup.apk="
        "com.motorola.setupwizard.devicesetup versionCode:35 installer=null uid:10281"
    )

    assert entry is not None
    assert entry.package_name == "com.motorola.setupwizard.devicesetup"
    assert entry.apk_path == "/product/priv-app/VzwDeviceSetup/VzwDeviceSetup.apk"
    assert entry.version_code == "35"
    assert entry.installer is None
    assert entry.uid == 10281


def test_parse_bulk_package_listing_tolerates_missing_uid():
    entry = adb_bulk._parse_pm_list_line(
        "package:/data/app/~~abc/pkg-base/base.apk=com.example.app "
        "versionCode:77 installer=com.android.vending"
    )

    assert entry is not None
    assert entry.package_name == "com.example.app"
    assert entry.uid is None
    assert entry.installer == "com.android.vending"
    assert entry.version_code == "77"


def test_collect_inventory_bulk_mode_uses_bulk_metadata_and_enriches_data_app_paths(monkeypatch):
    calls: list[str] = []

    monkeypatch.setattr(package_collection.adb_client, "clear_package_caches", lambda _serial: None)
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_packages",
        lambda _serial, _use_bulk, allow_fallbacks=False: (
            [("com.example.bulk", "77", None)],
            ["com.example.bulk"],
            True,
            False,
        ),
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_package_bulk_entries",
        lambda _serial: [
            adb_bulk.BulkPackageEntry(
                package_name="com.example.bulk",
                apk_path="/data/app/~~abc/pkg-base/base.apk",
                user="0",
                uid=10234,
                installer="com.android.vending",
                version_code="77",
            )
        ],
    )
    monkeypatch.setattr(package_collection.adb_client, "get_device_properties", lambda _serial: {})
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_paths",
        lambda _serial, package_name, allow_fallbacks=False: calls.append(package_name)
        or ["/data/app/~~abc/pkg-base/base.apk"],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("pm dump should not run in bulk mode")),
    )
    monkeypatch.setattr(package_collection.snapshot_io, "load_canonical_metadata", lambda _names: {})

    rows, stats = package_collection.collect_inventory("SER123", use_bulk=True, allow_fallbacks=False)

    assert calls == ["com.example.bulk"]
    assert rows[0]["package_name"] == "com.example.bulk"
    assert rows[0]["version_code"] == "77"
    assert rows[0]["installer"] == "com.android.vending"
    assert rows[0]["primary_path"] == "/data/app/~~abc/pkg-base/base.apk"
    assert rows[0]["apk_paths"] == ["/data/app/~~abc/pkg-base/base.apk"]
    assert rows[0]["split_count"] == 1
    assert rows[0]["path_fidelity"] == "pm_path"
    assert rows[0]["version_name"] is None
    assert stats.identity_quality == "strict"
    assert stats.collection_mode == "bulk"


def test_collect_inventory_bulk_mode_skips_pm_path_for_non_relevant_blocked_package(monkeypatch):
    calls: list[str] = []

    monkeypatch.setattr(package_collection.adb_client, "clear_package_caches", lambda _serial: None)
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_packages",
        lambda _serial, _use_bulk, allow_fallbacks=False: (
            [("com.vendor.blocked", "1", None)],
            ["com.vendor.blocked"],
            True,
            False,
        ),
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_package_bulk_entries",
        lambda _serial: [
            adb_bulk.BulkPackageEntry(
                package_name="com.vendor.blocked",
                apk_path="/vendor/app/Blocked/Blocked.apk",
                user="0",
                uid=10001,
                installer=None,
                version_code="1",
            )
        ],
    )
    monkeypatch.setattr(package_collection.adb_client, "get_device_properties", lambda _serial: {})
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_paths",
        lambda _serial, package_name, allow_fallbacks=False: calls.append(package_name) or ["/vendor/app/Blocked/Blocked.apk"],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("pm dump should not run in bulk mode")),
    )
    monkeypatch.setattr(package_collection.snapshot_io, "load_canonical_metadata", lambda _names: {})

    rows, _stats = package_collection.collect_inventory("SER123", use_bulk=True, allow_fallbacks=False)

    assert calls == []
    assert rows[0]["apk_paths"] == ["/vendor/app/Blocked/Blocked.apk"]
    assert rows[0]["path_fidelity"] == "bulk_base_only"


def test_collect_inventory_bulk_mode_enriches_profiled_package_even_when_not_data_path(monkeypatch):
    calls: list[str] = []

    monkeypatch.setattr(package_collection.adb_client, "clear_package_caches", lambda _serial: None)
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_packages",
        lambda _serial, _use_bulk, allow_fallbacks=False: (
            [("com.example.profiled", "9", None)],
            ["com.example.profiled"],
            True,
            False,
        ),
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_package_bulk_entries",
        lambda _serial: [
            adb_bulk.BulkPackageEntry(
                package_name="com.example.profiled",
                apk_path="/product/app/Profiled/Profiled.apk",
                user="0",
                uid=10009,
                installer=None,
                version_code="9",
            )
        ],
    )
    monkeypatch.setattr(package_collection.adb_client, "get_device_properties", lambda _serial: {})
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_paths",
        lambda _serial, package_name, allow_fallbacks=False: calls.append(package_name)
        or [
            "/product/app/Profiled/Profiled.apk",
            "/product/app/Profiled/split_config.en.apk",
        ],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("pm dump should not run in bulk mode")),
    )
    monkeypatch.setattr(
        package_collection.snapshot_io,
        "load_canonical_metadata",
        lambda _names: {
            "com.example.profiled": {
                "profile_key": "SOCIAL",
                "profile_name": "Social",
            }
        },
    )

    rows, _stats = package_collection.collect_inventory("SER123", use_bulk=True, allow_fallbacks=False)

    assert calls == ["com.example.profiled"]
    assert rows[0]["split_count"] == 2
    assert rows[0]["path_fidelity"] == "pm_path"


def test_collect_inventory_bulk_mode_progress_reports_bulk_rows_not_metadata(monkeypatch):
    events: list[dict[str, object]] = []

    monkeypatch.setattr(package_collection.adb_client, "clear_package_caches", lambda _serial: None)
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_packages",
        lambda _serial, _use_bulk, allow_fallbacks=False: (
            [("com.example.bulk", "77", None)],
            ["com.example.bulk"],
            True,
            False,
        ),
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_package_bulk_entries",
        lambda _serial: [
            adb_bulk.BulkPackageEntry(
                package_name="com.example.bulk",
                apk_path="/data/app/~~abc/pkg-base/base.apk",
                user="0",
                uid=10234,
                installer="com.android.vending",
                version_code="77",
            )
        ],
    )
    monkeypatch.setattr(package_collection.adb_client, "get_device_properties", lambda _serial: {})
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_paths",
        lambda _serial, _package_name, allow_fallbacks=False: ["/data/app/~~abc/pkg-base/base.apk"],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("pm dump should not run in bulk mode")),
    )
    monkeypatch.setattr(package_collection.snapshot_io, "load_canonical_metadata", lambda _names: {})

    def _progress_cb(
        processed,
        total,
        elapsed_seconds,
        eta_seconds,
        split_apks,
        **kwargs,
    ):
        events.append(
            {
                "processed": processed,
                "total": total,
                "elapsed_seconds": elapsed_seconds,
                "eta_seconds": eta_seconds,
                "split_apks": split_apks,
                **kwargs,
            }
        )

    package_collection.collect_inventory(
        "SER123",
        use_bulk=True,
        allow_fallbacks=False,
        progress_cb=_progress_cb,
    )

    completion_events = [event for event in events if event.get("current_stage") == "complete"]
    assert completion_events
    assert completion_events[-1]["bulk_rows_completed"] == 1
    assert completion_events[-1]["path_calls_completed"] == 1
    assert completion_events[-1]["metadata_calls_completed"] is None


def test_collect_inventory_bulk_mode_falls_back_to_pm_path_when_bulk_entry_missing(monkeypatch):
    calls: list[str] = []

    monkeypatch.setattr(package_collection.adb_client, "clear_package_caches", lambda _serial: None)
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_packages",
        lambda _serial, _use_bulk, allow_fallbacks=False: (
            [("com.example.missingbulk", "77", None)],
            ["com.example.missingbulk"],
            True,
            False,
        ),
    )
    monkeypatch.setattr(package_collection.adb_client, "list_package_bulk_entries", lambda _serial: [])
    monkeypatch.setattr(package_collection.adb_client, "get_device_properties", lambda _serial: {})
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_paths",
        lambda _serial, package_name, allow_fallbacks=False: calls.append(package_name)
        or ["/data/app/~~abc/com.example.missingbulk/base.apk"],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("pm dump should not run in bulk mode")),
    )
    monkeypatch.setattr(package_collection.snapshot_io, "load_canonical_metadata", lambda _names: {})

    rows, stats = package_collection.collect_inventory("SER123", use_bulk=True, allow_fallbacks=False)

    assert calls == ["com.example.missingbulk"]
    assert rows[0]["apk_paths"] == ["/data/app/~~abc/com.example.missingbulk/base.apk"]
    assert rows[0]["path_fidelity"] == "pm_path"
    assert stats.path_enriched_packages == 1
    assert stats.bulk_identity_only_packages == 0


def test_collect_inventory_bulk_mode_counters_match_enriched_vs_bulk_only_rows(monkeypatch):
    events: list[dict[str, object]] = []

    monkeypatch.setattr(package_collection.adb_client, "clear_package_caches", lambda _serial: None)
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_packages",
        lambda _serial, _use_bulk, allow_fallbacks=False: (
            [
                ("com.example.userapp", "77", None),
                ("com.vendor.blocked", "1", None),
            ],
            ["com.example.userapp", "com.vendor.blocked"],
            True,
            False,
        ),
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_package_bulk_entries",
        lambda _serial: [
            adb_bulk.BulkPackageEntry(
                package_name="com.example.userapp",
                apk_path="/data/app/~~abc/com.example.userapp/base.apk",
                user="0",
                uid=10234,
                installer="com.android.vending",
                version_code="77",
            ),
            adb_bulk.BulkPackageEntry(
                package_name="com.vendor.blocked",
                apk_path="/vendor/app/Blocked/Blocked.apk",
                user="0",
                uid=10001,
                installer=None,
                version_code="1",
            ),
        ],
    )
    monkeypatch.setattr(package_collection.adb_client, "get_device_properties", lambda _serial: {})
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_paths",
        lambda _serial, package_name, allow_fallbacks=False: [
            f"/data/app/~~abc/{package_name}/base.apk",
            f"/data/app/~~abc/{package_name}/split_config.en.apk",
        ],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("pm dump should not run in bulk mode")),
    )
    monkeypatch.setattr(package_collection.snapshot_io, "load_canonical_metadata", lambda _names: {})

    def _progress_cb(
        processed,
        total,
        elapsed_seconds,
        eta_seconds,
        split_apks,
        **kwargs,
    ):
        events.append(
            {
                "processed": processed,
                "total": total,
                "elapsed_seconds": elapsed_seconds,
                "eta_seconds": eta_seconds,
                "split_apks": split_apks,
                **kwargs,
            }
        )

    rows, stats = package_collection.collect_inventory(
        "SER123",
        use_bulk=True,
        allow_fallbacks=False,
        progress_cb=_progress_cb,
    )

    assert [row["path_fidelity"] for row in rows] == ["pm_path", "bulk_base_only"]
    assert stats.path_enriched_packages == 1
    assert stats.bulk_identity_only_packages == 1
    completion_events = [event for event in events if event.get("current_stage") == "complete"]
    assert completion_events
    assert completion_events[-1]["bulk_rows_completed"] == 2
    assert completion_events[-1]["path_calls_completed"] == 1
    assert completion_events[-1]["metadata_calls_completed"] is None


def test_collect_inventory_baseline_mode_keeps_full_diagnostic_metadata_path(monkeypatch):
    events: list[dict[str, object]] = []
    metadata_calls: list[str] = []

    monkeypatch.setattr(package_collection.adb_client, "clear_package_caches", lambda _serial: None)
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_packages",
        lambda _serial, _use_bulk, allow_fallbacks=False: (
            [("com.example.baseline", "42", None)],
            ["com.example.baseline"],
            False,
            False,
        ),
    )
    monkeypatch.setattr(package_collection.adb_client, "get_device_properties", lambda _serial: {})
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_paths",
        lambda _serial, _package_name, allow_fallbacks=False: [
            "/data/app/~~abc/com.example.baseline/base.apk",
            "/data/app/~~abc/com.example.baseline/split_config.en.apk",
        ],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata",
        lambda _serial, package_name: metadata_calls.append(package_name)
        or {
            "app_label": "Baseline Example",
            "installer": "com.android.vending",
            "version_name": "4.2",
        },
    )
    monkeypatch.setattr(package_collection.snapshot_io, "load_canonical_metadata", lambda _names: {})

    def _progress_cb(
        processed,
        total,
        elapsed_seconds,
        eta_seconds,
        split_apks,
        **kwargs,
    ):
        events.append(
            {
                "processed": processed,
                "total": total,
                "elapsed_seconds": elapsed_seconds,
                "eta_seconds": eta_seconds,
                "split_apks": split_apks,
                **kwargs,
            }
        )

    rows, stats = package_collection.collect_inventory(
        "SER123",
        use_bulk=False,
        allow_fallbacks=False,
        progress_cb=_progress_cb,
    )

    assert metadata_calls == ["com.example.baseline"]
    assert rows[0]["version_name"] == "4.2"
    assert rows[0]["split_count"] == 2
    assert stats.collection_mode == "baseline"
    completion_events = [event for event in events if event.get("current_stage") == "complete"]
    assert completion_events
    assert completion_events[-1]["path_calls_completed"] == 1
    assert completion_events[-1]["metadata_calls_completed"] == 1
