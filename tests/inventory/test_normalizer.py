from __future__ import annotations

import pytest
from scytaledroid.DeviceAnalysis.inventory import normalizer

pytestmark = [pytest.mark.unit]


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
    assert entry["apk_dirs"] == ["/product/app/pkg"]
    assert entry["primary_path"] == paths[0]


def test_split_count_defaults_to_one_when_single_path():
    entry = normalizer.compose_inventory_entry("com.example.app", ["/data/app/base.apk"], {}, None)
    assert entry["split_count"] == 1
    assert entry["split_flag"] == "No"


def test_compose_inventory_entry_preserves_signer_identity_metadata():
    entry = normalizer.compose_inventory_entry(
        "com.example.app",
        ["/data/app/base.apk"],
        {
            "installer": "com.android.vending",
            "version_code": "100",
            "signer_cert_digest": "a" * 64,
            "signer_set_hash": "b" * 64,
        },
        None,
    )

    assert entry["signer_cert_digest"] == "a" * 64
    assert entry["signer_set_hash"] == "b" * 64


def test_compose_inventory_entry_derives_split_membership_hash():
    entry = normalizer.compose_inventory_entry(
        "com.example.app",
        ["/data/app/base.apk", "/data/app/split_config.en.apk"],
        {"version_code": "100"},
        None,
    )

    assert entry["split_membership_hash"]
    assert len(str(entry["split_membership_hash"])) == 64


def test_compose_inventory_entry_preserves_independent_package_manager_split_count():
    entry = normalizer.compose_inventory_entry(
        "com.example.app",
        ["/data/app/base.apk", "/data/app/split_config.en.apk"],
        {
            "version_code": "100",
            "split_names": ["base", "config.en", "config.arm64_v8a"],
        },
        None,
    )

    assert entry["package_manager_split_names"] == [
        "base",
        "config.en",
        "config.arm64_v8a",
    ]
    assert entry["package_manager_split_count"] == 3
    assert entry["split_path_count_consistent"] is False


def test_split_count_handles_string_flags():
    entry = {"apk_paths": ["/data/app/base.apk", "/data/app/split.apk"], "split_count": "yes"}
    assert normalizer.split_count(entry) == 2
