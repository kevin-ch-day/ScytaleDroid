from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DeviceAnalysis import device_manager, watchlist_manager


def test_load_state_restores_active_device(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_file = state_dir / "active_device.json"
    state_file.write_text(
        json.dumps({"active_serial": "SERIAL123", "last_serial": "SERIAL999"}),
        encoding="utf-8",
    )

    monkeypatch.setattr(device_manager, "_STATE_DIR", state_dir, raising=False)
    monkeypatch.setattr(device_manager, "_STATE_FILE", state_file, raising=False)
    monkeypatch.setattr(device_manager, "_ACTIVE_SERIAL", None, raising=False)
    monkeypatch.setattr(device_manager, "_LAST_SERIAL", None, raising=False)

    device_manager._load_state()

    assert device_manager.get_active_serial() == "SERIAL123"
    assert device_manager.get_last_serial() == "SERIAL999"


def test_load_state_handles_missing_active(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_file = state_dir / "active_device.json"
    state_file.write_text(json.dumps({"last_serial": "SERIAL777"}), encoding="utf-8")

    monkeypatch.setattr(device_manager, "_STATE_DIR", state_dir, raising=False)
    monkeypatch.setattr(device_manager, "_STATE_FILE", state_file, raising=False)
    monkeypatch.setattr(device_manager, "_ACTIVE_SERIAL", None, raising=False)
    monkeypatch.setattr(device_manager, "_LAST_SERIAL", None, raising=False)

    device_manager._load_state()

    assert device_manager.get_active_serial() is None
    assert device_manager.get_last_serial() == "SERIAL777"


def test_resolve_app_names_dedupes_and_caches(monkeypatch):
    calls: list[tuple[str, ...]] = []

    def fake_run_sql(query, params, **kwargs):
        calls.append(tuple(params))
        return [
            {"package_name": "com.example.one", "label": "Example One"},
        ]

    monkeypatch.setattr(watchlist_manager, "_APP_NAME_CACHE", {}, raising=False)
    monkeypatch.setattr(watchlist_manager.db_queries, "run_sql", fake_run_sql)

    first = watchlist_manager._resolve_app_names(
        ["com.example.one", "com.example.two", "com.example.one"]
    )

    assert first["com.example.one"] == "Example One"
    assert first["com.example.two"] == "com.example.two"
    assert calls == [("com.example.one", "com.example.two")]

    second = watchlist_manager._resolve_app_names(["com.example.two", "com.example.one"])
    assert second["com.example.one"] == "Example One"
    assert second["com.example.two"] == "com.example.two"
    assert len(calls) == 1


def test_format_watchlist_location_relative():
    target = Path.cwd() / "data" / "watchlists" / "demo.json"

    location = watchlist_manager._format_watchlist_location(target)

    assert location == str(Path("data/watchlists/demo.json"))


def test_format_watchlist_location_external(tmp_path):
    outside = tmp_path / "demo.json"

    location = watchlist_manager._format_watchlist_location(outside)

    assert location == str(outside.resolve())
