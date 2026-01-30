"""Device status + capability helpers."""

from __future__ import annotations

from typing import Dict, Optional

from scytaledroid.DeviceAnalysis import device_status


def get_device_stats(serial: str) -> Dict[str, Optional[str]]:
    """Collect live telemetry for the provided device."""
    return device_status.get_device_stats(serial)


def get_device_capabilities(serial: str) -> Dict[str, Optional[str]]:
    """Return capability snapshot for dynamic analysis."""
    return device_status.get_device_capabilities(serial)


__all__ = ["get_device_stats", "get_device_capabilities"]
