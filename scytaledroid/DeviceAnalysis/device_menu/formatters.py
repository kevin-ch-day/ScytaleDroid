"""Formatting helpers for the Device Analysis menu."""

from __future__ import annotations

from datetime import UTC, datetime


def _clean_device_text(value: str | None) -> str:
    return " ".join(str(value or "").replace("_", " ").split()).strip()


def prettify_model(value: str | None) -> str:
    if not value:
        return "Unknown"
    cleaned = (
        value.replace("___", " - ")
        .replace("__", " ")
        .replace("_", " ")
    )
    cleaned = " ".join(cleaned.split())
    return cleaned if cleaned else "Unknown"


def prettify_manufacturer(value: str | None) -> str:
    if not value:
        return "Unknown"
    cleaned = " ".join(value.replace("_", " ").split())
    return cleaned.title()


def format_android_release(
    properties: dict[str, str | None],
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


def format_battery(properties: dict[str, str | None]) -> str:
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


def format_wifi_state(value: str | None) -> str:
    if not value:
        return "Unknown"
    normalized = value.strip().lower()
    if normalized in {"1", "on", "enabled", "true"}:
        return "On"
    if normalized in {"0", "off", "disabled", "false"}:
        return "Off"
    return value


def format_build_tags(value: str | None) -> str:
    if not value:
        return "Unknown"
    spaced = value.replace(",", ", ")
    while ", ," in spaced:
        spaced = spaced.replace(", ,", ", ")
    return spaced.strip()


def format_emulator_flag(value: str | None) -> str:
    if not value:
        return "No"
    lowered = value.strip().lower()
    return "Yes" if lowered in {"1", "true", "yes"} else "No"


def format_device_line(
    device: dict[str, str | None],
    *,
    include_release: bool = False,
) -> str:
    model = prettify_model(device.get("model") or device.get("device"))
    serial = device.get("serial") or "Unknown"
    label = f"{model} ({serial})" if model != "Unknown" else serial
    extras: list[str] = []

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


def format_device_display_name(device: dict[str, str | None]) -> str:
    """Return a human-readable device name for menu/UI display."""

    name = (
        device.get("model")
        or device.get("display_name")
        or device.get("device")
        or device.get("serial")
        or "Unknown device"
    )
    cleaned = _clean_device_text(name)
    if not cleaned:
        return "Unknown device"
    if cleaned == str(device.get("serial") or "").strip():
        return cleaned
    return prettify_model(cleaned)


def format_device_android_short(device: dict[str, str | None]) -> str | None:
    """Return a concise Android version string such as ``15`` when known."""

    version = str(device.get("android_version") or "").strip()
    if version:
        return version
    release = str(device.get("android_release") or "").strip()
    if not release:
        return None
    if release.lower().startswith("android "):
        return release.split(" ", 1)[1].split(" ", 1)[0].strip() or None
    return release.split(" ", 1)[0].strip() or None


def format_device_type_short(device: dict[str, str | None]) -> str | None:
    """Return a normalized lowercase device kind when known."""

    kind = str(device.get("device_type") or "").strip().lower()
    if kind in {"physical", "emulator"}:
        return kind
    return None


def format_device_context_line(
    device: dict[str, str | None],
    *,
    include_android: bool = True,
    include_type: bool = True,
) -> str:
    """Return a consistent selected-device line for cross-menu display."""

    parts = [
        format_device_display_name(device),
        str(device.get("serial") or "unknown").strip() or "unknown",
    ]
    if include_android:
        android = format_device_android_short(device)
        if android:
            parts.append(f"Android {android}")
    if include_type:
        kind = format_device_type_short(device)
        if kind:
            parts.append(kind)
    return " · ".join(parts)


def format_device_context_compact(device: dict[str, str | None]) -> str:
    """Return a compact device label with name and serial only."""

    return format_device_context_line(device, include_android=False, include_type=False)


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
    "format_device_display_name",
    "format_device_android_short",
    "format_device_type_short",
    "format_device_context_line",
    "format_device_context_compact",
]


def format_timestamp_utc(value: datetime | float | int | None) -> str:
    """Return a consistent, human-readable UTC timestamp string."""

    if value is None:
        return "Unknown"

    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, tz=UTC)
    elif isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        else:
            dt = dt.astimezone(UTC)
    else:
        return "Unknown"

    month = dt.strftime("%b")
    day = dt.strftime("%d").lstrip("0") or "0"
    year = dt.strftime("%Y")
    hour = dt.strftime("%I").lstrip("0") or "12"
    minute = dt.strftime("%M")
    ampm = dt.strftime("%p")
    return f"{month} {day}, {year} · {hour}:{minute} {ampm} (UTC)"
