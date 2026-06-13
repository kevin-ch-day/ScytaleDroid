from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.device_menu import harvest_entry
from scytaledroid.Utils.DisplayUtils import text_blocks


def test_refresh_inventory_for_harvest_menu_uses_harvest_ready_mode(monkeypatch) -> None:
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        harvest_entry.device_service,
        "fetch_inventory_metadata",
        lambda _serial: SimpleNamespace(status_label="FRESH"),
    )
    monkeypatch.setattr(
        harvest_entry,
        "print_inventory_run_feedback",
        lambda result, **kwargs: captured.update({"feedback_kwargs": kwargs}),
    )
    monkeypatch.setattr(text_blocks, "UI_PREFS", None, raising=False)

    from scytaledroid.DeviceAnalysis.workflows import inventory_workflow

    monkeypatch.setattr(
        inventory_workflow,
        "run_inventory_sync",
        lambda **kwargs: captured.update({"run_kwargs": kwargs})
        or SimpleNamespace(stats=SimpleNamespace(total_packages=10), snapshot_id=5, elapsed_seconds=3.0),
    )

    ok, status = harvest_entry.refresh_inventory_for_harvest_menu("SERIAL123")

    assert ok is True
    assert status.status_label == "FRESH"
    assert captured["run_kwargs"]["mode"] == "bulk"
    assert captured["feedback_kwargs"]["mode_label"] == "harvest-ready"
