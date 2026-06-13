from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.inventory import package_collection, runner


def test_run_full_sync_threads_bulk_mode_into_collection(monkeypatch) -> None:
    captured: dict[str, object] = {}

    monkeypatch.setattr(runner.snapshot_io, "load_latest_snapshot_meta", lambda _serial: None)
    monkeypatch.setattr(runner.snapshot_io, "load_latest_inventory", lambda _serial: None)

    def _collect_inventory(*, serial, filter_fn, package_allowlist, progress_cb, use_bulk, allow_fallbacks):
        captured["serial"] = serial
        captured["use_bulk"] = use_bulk
        return (
            [
                {
                    "package_name": "com.example.app",
                    "version_code": "1",
                    "split_count": 1,
                }
            ],
            package_collection.CollectionStats(
                total_packages=1,
                split_packages=0,
                new_packages=0,
                removed_packages=0,
                elapsed_seconds=0.5,
                collection_mode="bulk",
            ),
        )

    monkeypatch.setattr(runner.package_collection, "collect_inventory", _collect_inventory)
    monkeypatch.setattr(
        runner.snapshot_io,
        "persist_snapshot",
        lambda **_kwargs: SimpleNamespace(path=Path("data/state/test.json"), snapshot_id=7, persisted_rows=1),
    )
    monkeypatch.setattr(runner.db_sync, "sync_app_definitions", lambda _rows: 1)

    result = runner.run_full_sync("SER123", mode="bulk")

    assert captured["serial"] == "SER123"
    assert captured["use_bulk"] is True
    assert result.snapshot_id == 7


def test_run_scoped_sync_threads_bulk_mode_into_collection(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _collect_inventory(*, serial, filter_fn, package_allowlist, progress_cb, use_bulk, allow_fallbacks):
        captured["serial"] = serial
        captured["package_allowlist"] = package_allowlist
        captured["use_bulk"] = use_bulk
        return (
            [
                {
                    "package_name": "com.example.app",
                    "version_code": "1",
                    "split_count": 1,
                }
            ],
            package_collection.CollectionStats(
                total_packages=1,
                split_packages=0,
                new_packages=0,
                removed_packages=0,
                elapsed_seconds=0.5,
                collection_mode="bulk",
            ),
        )

    monkeypatch.setattr(runner.package_collection, "collect_inventory", _collect_inventory)
    monkeypatch.setattr(
        runner.snapshot_io,
        "persist_scoped_snapshot",
        lambda **_kwargs: SimpleNamespace(path=Path("data/state/scoped.json"), persisted_rows=1),
    )

    result = runner.run_scoped_sync(
        serial="SER123",
        package_allowlist={"com.example.app"},
        scope_id="profile::alpha",
        mode="bulk",
    )

    assert captured["serial"] == "SER123"
    assert captured["package_allowlist"] == {"com.example.app"}
    assert captured["use_bulk"] is True
    assert result.snapshot_id is None
