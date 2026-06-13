from __future__ import annotations

import pytest

from scytaledroid.DeviceAnalysis.services import device_service
from scytaledroid.DeviceAnalysis.services import inventory_service
from scytaledroid.DeviceAnalysis.inventory.errors import InventoryCollectionError


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


def test_inventory_service_error_keeps_full_sync_persistence_hint(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.DeviceAnalysis.inventory.runner.run_full_sync",
        lambda **_kwargs: (_ for _ in ()).throw(
            InventoryCollectionError(
                package="com.example.app",
                index=3,
                total=10,
                stage="pm path",
                original=RuntimeError("boom"),
            )
        ),
    )

    with pytest.raises(inventory_service.InventoryServiceError) as excinfo:
        inventory_service.run_full_sync("SER123", ui_prefs=None, progress_sink="none")

    assert "Run aborted before persistence; last good snapshot preserved." in str(excinfo.value)


def test_inventory_service_error_keeps_scoped_sync_compact_message(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.DeviceAnalysis.inventory.runner.run_scoped_sync",
        lambda **_kwargs: (_ for _ in ()).throw(
            InventoryCollectionError(
                package="com.example.app",
                index=2,
                total=5,
                stage="bulk",
                original=RuntimeError("boom"),
            )
        ),
    )

    with pytest.raises(inventory_service.InventoryServiceError) as excinfo:
        inventory_service.run_scoped_sync(
            serial="SER123",
            packages={"com.example.app"},
            scope_id="profile::alpha",
            ui_prefs=None,
            progress_sink="none",
        )

    assert "Scoped inventory sync failed for SER123" in str(excinfo.value)
    assert "last good snapshot preserved" not in str(excinfo.value).lower()
