from __future__ import annotations

import pytest
from scytaledroid.DeviceAnalysis import inventory_meta
from scytaledroid.DeviceAnalysis.inventory import package_collection
from tests.inventory._package_collection_support import (
    bulk_entry,
    patch_inventory_collection_defaults,
)

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


def test_collect_inventory_bulk_mode_uses_bulk_metadata_and_enriches_data_app_paths(monkeypatch):
    calls: list[str] = []

    patch_inventory_collection_defaults(monkeypatch)
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
            bulk_entry(
                package_name="com.example.bulk",
                apk_path="/data/app/~~abc/pkg-base/base.apk",
                uid=10234,
                installer="com.android.vending",
                version_code="77",
            )
        ],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata_bulk",
        lambda _serial: {
            "com.example.bulk": {
                "package_name": "com.example.bulk",
                "code_path": "/data/app/~~abc/pkg-base",
                "split_names": ["base"],
                "version_name": "7.7",
                "last_update": "2026-06-14 00:40:13",
                "first_install": "2026-05-08 16:33:35",
                "installer": "com.android.vending",
            }
        },
    )
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

    rows, stats = package_collection.collect_inventory("SER123", use_bulk=True, allow_fallbacks=False)

    assert calls == []
    assert rows[0]["package_name"] == "com.example.bulk"
    assert rows[0]["version_code"] == "77"
    assert rows[0]["installer"] == "com.android.vending"
    assert rows[0]["primary_path"] == "/data/app/~~abc/pkg-base/base.apk"
    assert rows[0]["apk_paths"] == ["/data/app/~~abc/pkg-base/base.apk"]
    assert rows[0]["split_count"] == 1
    assert rows[0]["path_fidelity"] == "dumpsys_reconstructed"
    assert rows[0]["version_name"] == "7.7"
    assert stats.identity_quality == "strict"
    assert stats.collection_mode == "bulk"


def test_collect_inventory_bulk_mode_skips_pm_path_for_non_relevant_blocked_package(monkeypatch):
    calls: list[str] = []

    patch_inventory_collection_defaults(monkeypatch)
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
            bulk_entry(
                package_name="com.vendor.blocked",
                apk_path="/vendor/app/Blocked/Blocked.apk",
                uid=10001,
                installer=None,
                version_code="1",
            )
        ],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata_bulk",
        lambda _serial: {
            "com.example.profiled": {
                "package_name": "com.example.profiled",
                "code_path": "/product/app/Profiled",
                "split_names": ["base", "config.en"],
            }
        },
    )
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

    rows, _stats = package_collection.collect_inventory("SER123", use_bulk=True, allow_fallbacks=False)

    assert calls == []
    assert rows[0]["apk_paths"] == ["/vendor/app/Blocked/Blocked.apk"]
    assert rows[0]["path_fidelity"] == "bulk_base_only"


def test_collect_inventory_bulk_mode_enriches_profiled_package_even_when_not_data_path(monkeypatch):
    calls: list[str] = []

    patch_inventory_collection_defaults(
        monkeypatch,
        canonical_metadata_loader=lambda _names: {
            "com.example.profiled": {
                "profile_key": "SOCIAL",
                "profile_name": "Social",
            }
        },
    )
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
            bulk_entry(
                package_name="com.example.profiled",
                apk_path="/product/app/Profiled/Profiled.apk",
                uid=10009,
                installer=None,
                version_code="9",
            )
        ],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata_bulk",
        lambda _serial: {
            "com.example.profiled": {
                "package_name": "com.example.profiled",
                "code_path": "/product/app/Profiled",
                "split_names": ["base", "config.en"],
            }
        },
    )
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

    rows, _stats = package_collection.collect_inventory("SER123", use_bulk=True, allow_fallbacks=False)

    assert calls == []
    assert rows[0]["split_count"] == 2
    assert rows[0]["path_fidelity"] == "dumpsys_reconstructed"


def test_collect_inventory_bulk_mode_progress_reports_bulk_rows_not_metadata(monkeypatch):
    events: list[dict[str, object]] = []

    patch_inventory_collection_defaults(monkeypatch)
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
            bulk_entry(
                package_name="com.example.bulk",
                apk_path="/data/app/~~abc/pkg-base/base.apk",
                uid=10234,
                installer="com.android.vending",
                version_code="77",
            )
        ],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata_bulk",
        lambda _serial: {
            "com.example.bulk": {
                "package_name": "com.example.bulk",
                "code_path": "/data/app/~~abc/pkg-base",
                "split_names": ["base"],
                "version_name": "7.7",
                "last_update": "2026-06-14 00:40:13",
                "first_install": "2026-05-08 16:33:35",
            }
        },
    )
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

    package_collection.collect_inventory(
        "SER123",
        use_bulk=True,
        allow_fallbacks=False,
        progress_cb=_progress_cb,
    )

    completion_events = [event for event in events if event.get("current_stage") == "complete"]
    assert completion_events
    assert completion_events[-1]["bulk_rows_completed"] == 1
    assert completion_events[-1]["path_calls_completed"] == 0
    assert completion_events[-1]["metadata_calls_completed"] is None


def test_collect_inventory_bulk_mode_falls_back_to_pm_path_when_bulk_entry_missing(monkeypatch):
    calls: list[str] = []

    patch_inventory_collection_defaults(monkeypatch)
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
    monkeypatch.setattr(package_collection.adb_client, "get_package_metadata_bulk", lambda _serial: {})
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

    rows, stats = package_collection.collect_inventory("SER123", use_bulk=True, allow_fallbacks=False)

    assert calls == ["com.example.missingbulk"]
    assert rows[0]["apk_paths"] == ["/data/app/~~abc/com.example.missingbulk/base.apk"]
    assert rows[0]["path_fidelity"] == "pm_path"
    assert stats.path_enriched_packages == 1
    assert stats.bulk_identity_only_packages == 0


def test_collect_inventory_bulk_mode_counters_match_enriched_vs_bulk_only_rows(monkeypatch):
    events: list[dict[str, object]] = []

    patch_inventory_collection_defaults(monkeypatch)
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
            bulk_entry(
                package_name="com.example.userapp",
                apk_path="/data/app/~~abc/com.example.userapp/base.apk",
                uid=10234,
                installer="com.android.vending",
                version_code="77",
            ),
            bulk_entry(
                package_name="com.vendor.blocked",
                apk_path="/vendor/app/Blocked/Blocked.apk",
                uid=10001,
                installer=None,
                version_code="1",
            ),
        ],
    )
    monkeypatch.setattr(
        package_collection.adb_client,
        "get_package_metadata_bulk",
        lambda _serial: {
            "com.example.userapp": {
                "package_name": "com.example.userapp",
                "code_path": "/data/app/~~abc/com.example.userapp",
                "split_names": ["base", "config.en"],
                "version_name": "7.7",
                "last_update": "2026-06-14 00:40:13",
                "first_install": "2026-05-08 16:33:35",
            }
        },
    )
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
        use_bulk=True,
        allow_fallbacks=False,
        progress_cb=_progress_cb,
    )

    assert [row["path_fidelity"] for row in rows] == ["dumpsys_reconstructed", "bulk_base_only"]
    assert stats.path_enriched_packages == 1
    assert stats.bulk_identity_only_packages == 1
    completion_events = [event for event in events if event.get("current_stage") == "complete"]
    assert completion_events
    assert completion_events[-1]["bulk_rows_completed"] == 2
    assert completion_events[-1]["path_calls_completed"] == 0
    assert completion_events[-1]["metadata_calls_completed"] is None
