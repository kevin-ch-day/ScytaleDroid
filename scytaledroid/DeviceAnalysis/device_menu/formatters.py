"""Formatting helpers for the Device Analysis menu."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional, Union


def prettify_model(value: Optional[str]) -> str:
    if not value:
        return "Unknown"
    cleaned = (
        value.replace("___", " - ")
        .replace("__", " ")
        .replace("_", " ")
    )
    cleaned = " ".join(cleaned.split())
    return cleaned if cleaned else "Unknown"


def prettify_manufacturer(value: Optional[str]) -> str:
    if not value:
        return "Unknown"
    cleaned = " ".join(value.replace("_", " ").split())
    return cleaned.title()


def format_android_release(
    properties: Dict[str, Optional[str]],
    *,
    include_sdk: bool = False,
) -> str:
    if not properties:
        return "Unknown"

    release = properties.get("android_release")
    if release:
        cleaned = release.split(" (", 1)[0].strip()
        if include_sdk:
            return release
        return cleaned

    version = properties.get("android_version")
    sdk = properties.get("sdk_level")

    if version and include_sdk and sdk:
        return f"Android {version} (SDK {sdk})"
    if version:
        return f"Android {version}"
    if sdk:
        return f"SDK {sdk}"
    return "Unknown"


def format_battery(properties: Dict[str, Optional[str]]) -> str:
    level = properties.get("battery_level")
    status = properties.get("battery_status")
    if level and status:
        if status.lower() in level.lower():
            return level
        return f"{level} ({status})"
    if level:
        return level
    if status:
        return status
    return "Unknown"


def format_wifi_state(value: Optional[str]) -> str:
    if not value:
        return "Unknown"
    normalized = value.strip().lower()
    if normalized in {"1", "on", "enabled", "true"}:
        return "On"
    if normalized in {"0", "off", "disabled", "false"}:
        return "Off"
    return value


def format_build_tags(value: Optional[str]) -> str:
    if not value:
        return "Unknown"
    spaced = value.replace(",", ", ")
    while ", ," in spaced:
        spaced = spaced.replace(", ,", ", ")
    return spaced.strip()


def format_emulator_flag(value: Optional[str]) -> str:
    if not value:
        return "No"
    lowered = value.strip().lower()
    return "Yes" if lowered in {"1", "true", "yes"} else "No"


def format_device_line(
    device: Dict[str, Optional[str]],
    *,
    include_release: bool = False,
) -> str:
    model = prettify_model(device.get("model") or device.get("device"))
    serial = device.get("serial") or "Unknown"
    label = f"{model} ({serial})" if model != "Unknown" else serial
    extras: List[str] = []

    device_type = device.get("device_type")
    if device_type:
        extras.append(device_type)

    if include_release:
        release = format_android_release(device)
        if release and release != "Unknown":
            extras.append(release)

    manufacturer = prettify_manufacturer(
        device.get("manufacturer") or device.get("brand")
    )
    if manufacturer and manufacturer.lower() not in label.lower():
        extras.append(manufacturer)

    if extras:
        return f"{label} | {' | '.join(extras)}"
    return label


__all__ = [
    "format_timestamp_utc",
    "prettify_model",
    "prettify_manufacturer",
    "format_android_release",
    "format_battery",
    "format_wifi_state",
    "format_build_tags",
    "format_emulator_flag",
    "format_device_line",
]


def format_timestamp_utc(value: Union[datetime, float, int, None]) -> str:
    """Return a consistent, human-readable UTC timestamp string."""

    if value is None:
        return "Unknown"

    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
    elif isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
    else:
        return "Unknown"

    month = dt.strftime("%b")
    day = dt.strftime("%d").lstrip("0") or "0"
    year = dt.strftime("%Y")
    hour = dt.strftime("%I").lstrip("0") or "12"
    minute = dt.strftime("%M")
    ampm = dt.strftime("%p")
    return f"{month} {day}, {year} · {hour}:{minute} {ampm} (UTC)"
