"""Live device telemetry and capability checks."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.adb import client as adb_client


def get_device_stats(serial: str) -> dict[str, str | None]:
    """Collect live telemetry for the provided device."""
    stats: dict[str, str | None] = {}

    battery = _get_battery_info(serial)
    stats.update(battery)

    wifi_state = _get_wifi_state(serial)
    if wifi_state:
        stats["wifi_state"] = wifi_state

    root_state = _check_root_status(serial)
    if root_state:
        stats["is_rooted"] = root_state

    return stats


def get_device_capabilities(serial: str) -> dict[str, str | None]:
    """Return a capability snapshot for dynamic analysis decisions."""
    capabilities: dict[str, str | None] = {}

    root_state = _check_root_status(serial)
    if root_state:
        capabilities["is_rooted"] = root_state

    tcpdump_path = _find_tcpdump(serial)
    if tcpdump_path:
        capabilities["tcpdump_path"] = tcpdump_path

    netstats_ok = _check_netstats(serial)
    capabilities["netstats_access"] = "Yes" if netstats_ok else "No"

    return capabilities


def _get_battery_info(serial: str) -> dict[str, str | None]:
    try:
        completed = adb_client.run_shell_command(serial, ["dumpsys", "battery"])
    except RuntimeError:
        return {}
    if completed.returncode != 0:
        return {}

    level: str | None = None
    status: str | None = None
    charging: str | None = None

    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("level:"):
            level = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("status:"):
            status = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("AC powered:") or stripped.startswith("USB powered:"):
            if "true" in stripped:
                charging = "Charging"

    # Translate numeric status when available
    status_map = {
        "1": "Unknown",
        "2": "Charging",
        "3": "Discharging",
        "4": "Not charging",
        "5": "Full",
    }
    if status in status_map:
        status = status_map[status]

    if charging and charging not in (status or ""):
        status = charging if charging else status

    result: dict[str, str | None] = {}
    if level is not None and level.isdigit():
        result["battery_level"] = f"{level}%"
    if status:
        result["battery_status"] = status

    return result


def _get_wifi_state(serial: str) -> str | None:
    try:
        completed = adb_client.run_shell_command(serial, ["settings", "get", "global", "wifi_on"])
    except RuntimeError:
        return None
    if completed.returncode != 0:
        return None

    value = completed.stdout.strip()
    if value == "1":
        return "On"
    if value == "0":
        return "Off"
    return value or None


def _check_root_status(serial: str) -> str | None:
    try:
        completed = adb_client.run_shell_command(serial, ["id", "-u"])
    except RuntimeError:
        return None
    if completed.returncode == 0:
        user = completed.stdout.strip()
        if user == "0":
            return "Yes"
        return "No"
    return None


def _find_tcpdump(serial: str) -> str | None:
    try:
        output = adb_client.run_shell(serial, ["which", "tcpdump"], timeout=10)
    except RuntimeError:
        return None
    path = output.strip()
    return path or None


def _check_netstats(serial: str) -> bool:
    try:
        completed = adb_client.run_shell_command(
            serial,
            ["dumpsys", "netstats"],
            timeout=10,
        )
    except RuntimeError:
        return False
    return completed.returncode == 0
