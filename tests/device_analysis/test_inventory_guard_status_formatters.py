from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.metadata import status_formatters


def test_format_inventory_status_uses_full_refresh_label(monkeypatch) -> None:
    monkeypatch.setattr(
        status_formatters.device_service,
        "fetch_inventory_metadata",
        lambda _serial: SimpleNamespace(
            last_run_ts=object(),
            status_label="FRESH",
            collection_mode="baseline",
            age_display="7 mins",
            is_stale=False,
        ),
    )

    text = status_formatters.format_inventory_status("SER123")

    assert text == "fresh full device 7 mins ago"


def test_format_pull_hint_uses_full_refresh_label(monkeypatch) -> None:
    monkeypatch.setattr(
        status_formatters.device_service,
        "fetch_inventory_metadata",
        lambda _serial: SimpleNamespace(
            last_run_ts=object(),
            package_count=578,
            collection_mode="baseline",
            is_stale=True,
        ),
    )

    text = status_formatters.format_pull_hint("SER123")

    assert text == "inventory stale (578 packages, full device)"
