from scytaledroid.DeviceAnalysis.inventory import normalizer


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
