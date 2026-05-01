from __future__ import annotations

from scytaledroid.DeviceAnalysis.services import device_service


def test_resolve_active_device_empty_adb_list_retains_serial(monkeypatch) -> None:
    disconnect_calls = 0

    def _disconnect() -> None:
        nonlocal disconnect_calls
        disconnect_calls += 1

    monkeypatch.setattr(device_service.device_manager, "get_active_serial", lambda: "ZY22ABC")
    monkeypatch.setattr(device_service.device_manager, "disconnect", _disconnect)
    resolved = device_service.resolve_active_device([])
    assert resolved == {"serial": "ZY22ABC"}
    assert disconnect_calls == 0


def test_resolve_active_device_serial_missing_from_nonempty_list_disconnects(monkeypatch) -> None:
    disconnect_calls = 0

    def _disconnect() -> None:
        nonlocal disconnect_calls
        disconnect_calls += 1

    monkeypatch.setattr(device_service.device_manager, "get_active_serial", lambda: "ZY22ABC")
    monkeypatch.setattr(device_service.device_manager, "disconnect", _disconnect)
    resolved = device_service.resolve_active_device([{"serial": "OTHER"}])
    assert resolved is None
    assert disconnect_calls == 1


def test_resolve_active_device_no_active_serial(monkeypatch) -> None:
    monkeypatch.setattr(device_service.device_manager, "get_active_serial", lambda: None)
    assert device_service.resolve_active_device([{"serial": "X"}]) is None


def test_scan_devices_retries_once_when_active_set_and_first_scan_empty(monkeypatch) -> None:
    calls = 0

    def _scan() -> tuple[list[dict[str, str | None]], list[str]]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return [], []
        return [{"serial": "DEV1", "state": "device"}], []

    monkeypatch.setattr(device_service.device_manager, "get_active_serial", lambda: "DEV1")
    monkeypatch.setattr(device_service.adb_devices, "scan_devices", _scan)
    monkeypatch.setattr(device_service.time, "sleep", lambda _: None)

    devices, _warnings, summaries, serial_map = device_service.scan_devices()
    assert calls == 2
    assert len(devices) == 1
    assert summaries
    assert serial_map.get("DEV1") is summaries[0]


def test_scan_devices_no_retry_without_active(monkeypatch) -> None:
    scan_calls = 0

    def _scan() -> tuple[list[dict[str, str | None]], list[str]]:
        nonlocal scan_calls
        scan_calls += 1
        return [], []

    monkeypatch.setattr(device_service.device_manager, "get_active_serial", lambda: None)
    monkeypatch.setattr(device_service.adb_devices, "scan_devices", _scan)
    monkeypatch.setattr(device_service.time, "sleep", lambda _: AssertionError("should not sleep"))

    device_service.scan_devices()
    assert scan_calls == 1


def test_scan_devices_retry_merges_duplicate_warnings(monkeypatch) -> None:
    calls = 0

    def _scan() -> tuple[list[dict[str, str | None]], list[str]]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return [], ["daemon offline"]
        return [{"serial": "D2", "state": "device"}], ["daemon offline", "authorize"]

    monkeypatch.setattr(device_service.device_manager, "get_active_serial", lambda: "D2")
    monkeypatch.setattr(device_service.adb_devices, "scan_devices", _scan)
    monkeypatch.setattr(device_service.time, "sleep", lambda _: None)

    _d, warnings, *_ = device_service.scan_devices()
    assert warnings == ["daemon offline", "authorize"]
