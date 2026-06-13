from __future__ import annotations

from scytaledroid.DeviceAnalysis.services import device_service


def test_sync_inventory_threads_mode_to_runner(monkeypatch) -> None:
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        "scytaledroid.DeviceAnalysis.inventory.runner.run_full_sync",
        lambda **kwargs: captured.update(kwargs),
    )
    monkeypatch.setattr(
        device_service,
        "fetch_inventory_metadata",
        lambda _serial, with_current_state=True: None,
    )

    status = device_service.sync_inventory("SER123", mode="bulk")

    assert captured["serial"] == "SER123"
    assert captured["mode"] == "bulk"
    assert status.status_label == "NONE"
