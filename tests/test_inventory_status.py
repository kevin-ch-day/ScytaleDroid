from datetime import UTC, datetime, timedelta

from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.constants import (
    INVENTORY_STALE_SECONDS,
)
from scytaledroid.DeviceAnalysis.services.device_service import _compute_inventory_status


def test_inventory_status_none_snapshot():
    status = _compute_inventory_status(None, None)
    assert status.status_label == "NONE"
    assert status.is_stale is False
    assert status.age_display == "unknown"


def test_inventory_status_fresh_snapshot():
    ts = datetime.now(UTC)
    meta = {"timestamp": ts, "package_count": 5}
    status = _compute_inventory_status(meta, None)
    assert status.status_label == "FRESH"
    assert status.is_stale is False
    assert status.package_count == 5
    assert status.age_display != "unknown"


def test_inventory_status_stale_snapshot():
    ts = datetime.now(UTC) - timedelta(seconds=INVENTORY_STALE_SECONDS + 60)
    meta = {"timestamp": ts, "package_count": 10}
    status = _compute_inventory_status(meta, None)
    assert status.status_label == "STALE"
    assert status.is_stale is True
    assert status.package_count == 10
    assert status.age_display != "unknown"
