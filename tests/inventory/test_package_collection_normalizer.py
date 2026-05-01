from scytaledroid.DeviceAnalysis import inventory_meta, package_inventory
from scytaledroid.DeviceAnalysis.inventory import normalizer, package_collection


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
