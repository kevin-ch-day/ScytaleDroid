from __future__ import annotations

import pytest

from scytaledroid.DeviceAnalysis import inventory_meta
from scytaledroid.DeviceAnalysis.inventory import package_collection

from tests.inventory._package_collection_support import patch_inventory_collection_defaults


pytestmark = [pytest.mark.unit]


def test_collect_inventory_uses_raw_package_for_adb_and_normalized_hash(monkeypatch):
    raw_package_name = "com.qualcomm.qti.uimGbaApp"
    adb_calls: list[str] = []

    patch_inventory_collection_defaults(monkeypatch)
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
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata_bulk",
        lambda _serial: {
            "com.example.baseline": {
                "package_name": "com.example.baseline",
                "code_path": "/data/app/~~abc/com.example.baseline",
                "split_names": ["base", "config.en"],
                "version_name": "3.9",
                "last_update": "2026-06-14 00:40:13",
                "first_install": "2026-05-08 16:33:35",
            }
        },
    )
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

    rows, stats = package_collection.collect_inventory("SER123", allow_fallbacks=False)

    assert adb_calls == [raw_package_name]
    assert rows[0]["package_name"] == "com.qualcomm.qti.uimgbaapp"
    assert rows[0]["version_code"] == "35"
    assert stats.package_list_hash == inventory_meta.compute_name_hash(["com.qualcomm.qti.uimgbaapp"])
