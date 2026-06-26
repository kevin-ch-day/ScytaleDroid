from __future__ import annotations

from collections.abc import Callable

from scytaledroid.DeviceAnalysis.inventory import adb_bulk, package_collection


def bulk_entry(
    *,
    package_name: str,
    apk_path: str,
    user: str = "0",
    uid: int | None = None,
    installer: str | None = None,
    version_code: str | None = None,
) -> adb_bulk.BulkPackageEntry:
    return adb_bulk.BulkPackageEntry(
        package_name=package_name,
        apk_path=apk_path,
        user=user,
        uid=uid,
        installer=installer,
        version_code=version_code,
    )


def patch_inventory_collection_defaults(
    monkeypatch,
    *,
    canonical_metadata_loader: Callable[[object], dict] | None = None,
) -> None:
    monkeypatch.setattr(package_collection.adb_client, "clear_package_caches", lambda _serial: None)
    monkeypatch.setattr(package_collection.adb_client, "get_device_properties", lambda _serial: {})
    monkeypatch.setattr(
        package_collection.snapshot_io,
        "load_canonical_metadata",
        canonical_metadata_loader or (lambda _names: {}),
    )
