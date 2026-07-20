from __future__ import annotations

import pytest
from scytaledroid.DeviceAnalysis.inventory import package_collection
from tests.inventory._package_collection_support import (
    bulk_entry,
    patch_inventory_collection_defaults,
)

pytestmark = [pytest.mark.unit]


def test_collect_inventory_baseline_mode_keeps_full_diagnostic_metadata_path(monkeypatch):
    events: list[dict[str, object]] = []
    metadata_calls: list[str] = []

    patch_inventory_collection_defaults(monkeypatch)
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
    monkeypatch.setattr(package_collection.adb_client, "get_package_metadata_bulk", lambda _serial: {})
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

    def _progress_cb(processed, total, elapsed_seconds, eta_seconds, split_apks, **kwargs):
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
    assert rows[0]["path_fidelity"] == "pm_path"
    assert stats.collection_mode == "baseline"
    completion_events = [event for event in events if event.get("current_stage") == "complete"]
    assert completion_events
    assert completion_events[-1]["path_calls_completed"] == 1
    assert completion_events[-1]["metadata_calls_completed"] == 1


def test_collect_inventory_baseline_mode_preloads_bulk_metadata_even_for_single_package(
    monkeypatch,
):
    metadata_calls: list[str] = []
    path_calls: list[str] = []
    bulk_calls: list[str] = []

    patch_inventory_collection_defaults(monkeypatch)
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_packages",
        lambda _serial, _use_bulk, allow_fallbacks=False: (
            [("com.example.single", "42", None)],
            ["com.example.single"],
            False,
            False,
        ),
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata_bulk",
        lambda _serial: bulk_calls.append(_serial)
        or {
            "com.example.single": {
                "package_name": "com.example.single",
                "code_path": "/data/app/~~abc/com.example.single",
                "split_names": ["base", "config.en"],
                "user_id": "10123",
                "version_name": "4.2",
                "last_update": "2026-06-14 00:40:13",
                "first_install": "2026-05-08 16:33:35",
                "installer": "com.android.vending",
            }
        },
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_paths",
        lambda _serial, package_name, allow_fallbacks=False: path_calls.append(package_name) or [],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata",
        lambda _serial, package_name: metadata_calls.append(package_name) or {},
    )

    rows, stats = package_collection.collect_inventory(
        "SER123",
        use_bulk=False,
        allow_fallbacks=False,
    )

    assert bulk_calls == ["SER123"]
    assert path_calls == []
    assert metadata_calls == []
    assert stats.collection_mode == "baseline"
    assert rows[0]["path_fidelity"] == "dumpsys_reconstructed"
    assert rows[0]["apk_paths"] == [
        "/data/app/~~abc/com.example.single/base.apk",
        "/data/app/~~abc/com.example.single/split_config.en.apk",
    ]
    assert rows[0]["version_name"] == "4.2"
    assert rows[0]["installer"] == "com.android.vending"


def test_collect_inventory_baseline_mode_uses_bulk_single_path_before_pm_path(
    monkeypatch,
):
    metadata_calls: list[str] = []
    path_calls: list[str] = []
    bulk_calls: list[str] = []

    patch_inventory_collection_defaults(monkeypatch)
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_packages",
        lambda _serial, _use_bulk, allow_fallbacks=False: (
            [("com.example.single", "42", None)],
            ["com.example.single"],
            False,
            False,
        ),
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_package_bulk_entries",
        lambda _serial: bulk_calls.append(_serial)
        or [
            bulk_entry(
                package_name="com.example.single",
                apk_path="/product/app/Single/Single.apk",
                uid=10123,
                installer=None,
                version_code="42",
            )
        ],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata_bulk",
        lambda _serial: {
            "com.example.single": {
                "package_name": "com.example.single",
                "user_id": "10123",
                "version_name": "4.2",
                "last_update": "2026-06-14 00:40:13",
                "first_install": "2026-05-08 16:33:35",
                "installer": "com.android.vending",
            }
        },
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_paths",
        lambda _serial, package_name, allow_fallbacks=False: path_calls.append(package_name) or ["/should/not/be/used.apk"],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata",
        lambda _serial, package_name: metadata_calls.append(package_name) or {},
    )

    rows, stats = package_collection.collect_inventory(
        "SER123",
        use_bulk=False,
        allow_fallbacks=False,
    )

    assert bulk_calls == ["SER123"]
    assert path_calls == []
    assert metadata_calls == []
    assert stats.collection_mode == "baseline"
    assert stats.path_enriched_packages == 1
    assert stats.bulk_identity_only_packages == 0
    assert rows[0]["path_fidelity"] == "bulk_single_path"
    assert rows[0]["apk_paths"] == ["/product/app/Single/Single.apk"]
    assert rows[0]["version_name"] == "4.2"
    assert rows[0]["installer"] == "com.android.vending"


def test_collect_inventory_baseline_mode_uses_bulk_metadata_and_skips_pm_dump_for_non_relevant_package(
    monkeypatch,
):
    metadata_calls: list[str] = []

    patch_inventory_collection_defaults(
        monkeypatch,
        canonical_metadata_loader=lambda _names: {
            "com.example.pkg0": {
                "profile_key": "SOCIAL",
                "profile_name": "Social",
            }
        },
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "list_packages",
        lambda _serial, _use_bulk, allow_fallbacks=False: (
            [(f"com.example.pkg{i}", str(i), None) for i in range(30)],
            [f"com.example.pkg{i}" for i in range(30)],
            False,
            False,
        ),
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_paths",
        lambda _serial, package_name, allow_fallbacks=False: [
            f"/product/app/{package_name}/base.apk"
        ],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata_bulk",
        lambda _serial: {
            f"com.example.pkg{i}": {
                "package_name": f"com.example.pkg{i}",
                "code_path": (
                    f"/product/app/com.example.pkg{i}"
                    if i == 0
                    else f"/system/app/com.example.pkg{i}"
                ),
                "split_names": ["base", "config.en"] if i == 0 else ["base"],
                "user_id": str(10000 + i),
                "version_name": f"{i}.0",
                "last_update": "2026-06-14 00:40:13",
                "first_install": "2026-05-08 16:33:35",
                "installer": None,
            }
            for i in range(30)
        },
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata",
        lambda _serial, package_name: metadata_calls.append(package_name)
        or {
            "app_label": f"Label for {package_name}",
            "installer": "com.android.vending",
            "version_name": "deep",
            "signer_cert_digest": "a" * 64,
            "signer_set_hash": "b" * 64,
        },
    )

    rows, stats = package_collection.collect_inventory(
        "SER123",
        use_bulk=False,
        allow_fallbacks=False,
    )

    assert stats.collection_mode == "baseline"
    assert metadata_calls == []
    by_package = {row["package_name"]: row for row in rows}
    assert by_package["com.example.pkg0"]["version_name"] == "0.0"
    assert "signer_set_hash" not in by_package["com.example.pkg0"]
    assert by_package["com.example.pkg1"]["version_name"] == "1.0"
    assert by_package["com.example.pkg1"]["first_install"] == "2026-05-08 16:33:35"
    assert by_package["com.example.pkg1"]["app_label"] == "com.example.pkg1"
    assert by_package["com.example.pkg1"]["path_fidelity"] == "dumpsys_reconstructed"
    assert by_package["com.example.pkg1"]["apk_paths"] == ["/system/app/com.example.pkg1/com.example.pkg1.apk"]
    assert "signer_set_hash" not in by_package["com.example.pkg1"]
