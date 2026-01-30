"""adb_utils.py - Lightweight wrappers around selected ADB commands.

Public surface for callers:
    - run_shell(serial, args, ...)  # preferred entry point for adb shell
Everything else in this module should be treated as internal/legacy helpers.
Controllers/menus should never call subprocess directly; go through run_shell.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple


_PACKAGE_PATH_CACHE: Dict[Tuple[str, str], List[str]] = {}
_PACKAGE_META_CACHE: Dict[Tuple[str, str], Dict[str, Optional[str]]] = {}

from scytaledroid.Config import app_config


def _resolve_adb() -> Optional[str]:
    """Return the adb binary path when available."""
    return shutil.which("adb")


def is_available() -> bool:
    """Return True when the adb binary is available on PATH."""
    return _resolve_adb() is not None


def get_adb_binary() -> Optional[str]:
    """Expose the adb binary path for other helpers."""
    return _resolve_adb()


def scan_devices() -> Tuple[List[Dict[str, Optional[str]]], List[str]]:
    """Return devices and any informational warnings gathered during discovery."""
    adb_bin = _resolve_adb()
    warnings: List[str] = []
    if adb_bin is None:
        warnings.append(
            "adb binary not found on PATH. Install Android platform tools or update PATH."
        )
        return [], warnings

    try:
        result = subprocess.run(
            [adb_bin, "devices", "-l"],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:  # pragma: no cover - defensive
        warnings.append(f"Failed to execute adb: {exc}")
        return [], warnings

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if result.returncode != 0:
        if stderr:
            warnings.append(f"adb devices -l reported: {stderr}")
        return [], warnings

    if "no permissions" in stdout.lower():
        warnings.append(
            "ADB reports 'no permissions' – ensure udev rules or USB debugging permissions are granted."
        )

    devices: List[Dict[str, Optional[str]]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("List of devices"):
            continue

        parts = stripped.split()
        serial = parts[0]
        state = parts[1] if len(parts) > 1 else "unknown"
        details: Dict[str, Optional[str]] = {
            "serial": serial,
            "state": state,
            "model": None,
            "device": None,
            "product": None,
            "transport_id": None,
            "raw": stripped,
        }

        for token in parts[2:]:
            if ":" not in token:
                continue
            key, value = token.split(":", 1)
            details[key] = value

        if state.lower() == "unauthorized":
            warnings.append(
                f"Device {serial} is unauthorized. Confirm the USB debugging prompt on the device."
            )
        elif state.lower() == "offline":
            warnings.append(f"Device {serial} is offline. Reconnect USB or restart adb daemon.")

        devices.append(details)

    return devices, warnings


def list_devices() -> List[Dict[str, Optional[str]]]:
    """Return the list of devices reported by ``adb devices -l``."""
    devices, _ = scan_devices()
    return devices


def get_device_label(device: Dict[str, Optional[str]]) -> str:
    """Return a short human-readable label for a device entry."""
    model = device.get("model") or device.get("device")
    state = device.get("state", "unknown")
    serial = device.get("serial", "unknown")
    if model:
        return f"{model} ({serial}) - {state.upper()}"
    return f"{serial} - {state.upper()}"


def run_shell_command(
    serial: str,
    command: List[str],
    *,
    timeout: Optional[float] = None,
) -> subprocess.CompletedProcess[str]:
    """Execute an arbitrary ``adb shell`` command for the selected device."""
    adb_bin = _resolve_adb()
    if adb_bin is None:
        raise RuntimeError("adb binary not found on PATH")

    adb_command = [adb_bin, "-s", serial, "shell"] + command
    try:
        return subprocess.run(
            adb_command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - defensive
        raise RuntimeError(
            f"adb shell {' '.join(command)} timed out after {timeout}s"
        ) from exc


def run_shell(
    serial: str,
    command: List[str],
    *,
    timeout: Optional[float] = None,
    check: bool = False,
) -> str:
    """
    Execute an adb shell command and return stdout text.

    Args:
        serial: device serial
        command: list of command tokens to run after ``adb shell``
        timeout: optional timeout in seconds
        check: when True, raise RuntimeError on non-zero return code
    """
    completed = run_shell_command(serial, command, timeout=timeout)
    if check and completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        raise RuntimeError(
            f"adb shell {' '.join(command)} exited with {completed.returncode}: {stderr}"
        )
    return completed.stdout or ""


def _fetch_all_properties(serial: str) -> Dict[str, str]:
    """Return the full ``getprop`` dictionary for the provided device."""
    try:
        completed = run_shell_command(serial, ["getprop"])
    except RuntimeError as exc:
        return {}

    if completed.returncode != 0:
        return {}

    props: Dict[str, str] = {}
    for raw_line in completed.stdout.splitlines():
        line = raw_line.strip()
        if not line.startswith("[") or "]" not in line:
            continue
        try:
            key_part, value_part = line.split("]: [", 1)
        except ValueError:
            continue
        key = key_part.strip("[")
        value = value_part.rstrip("]")
        props[key] = value

    return props


def _is_emulator(props: Dict[str, str]) -> bool:
    """Attempt to determine whether the device is an emulator."""
    flag = props.get("ro.boot.qemu", "").strip().lower()
    if flag in {"1", "true", "yes"}:
        return True

    hardware = props.get("ro.hardware", "").lower()
    if hardware in {"goldfish", "cutf", "cutf_64", "ranchu", "emulator"}:
        return True

    product_model = props.get("ro.product.model", "").lower()
    emulator_tokens = {"sdk", "emulator", "simulator", "generic"}
    if any(token in product_model for token in emulator_tokens):
        return True

    product_name = props.get("ro.product.name", "").lower()
    if any(token in product_name for token in emulator_tokens):
        return True

    return False


def get_basic_properties(serial: str) -> Dict[str, str]:
    """Return curated device properties plus derived metadata."""
    props = _fetch_all_properties(serial)
    if not props:
        return {}

    mapping = getattr(app_config, "DEVICE_PROPERTY_KEYS", {})
    if not mapping:
        mapping = {
            "ro.product.manufacturer": "manufacturer",
            "ro.product.model": "model",
            "ro.build.version.release": "android_version",
            "ro.build.version.sdk": "sdk_level",
        }

    result: Dict[str, str] = {}
    for prop, label in mapping.items():
        value = props.get(prop)
        if value:
            result[label] = value

    result["device_type"] = "Emulator" if _is_emulator(props) else "Physical"

    # Provide friendly fallbacks
    if "android_version" in result and "sdk_level" in result:
        result["android_release"] = f"Android {result['android_version']} (SDK {result['sdk_level']})"

    tags = props.get("ro.build.tags")
    if tags:
        result["build_tags"] = tags

    fingerprint = props.get("ro.build.fingerprint")
    if fingerprint:
        result["build_fingerprint"] = fingerprint

    return result


def build_device_summary(device: Dict[str, Optional[str]]) -> Dict[str, Optional[str]]:
    """Attach basic properties and derived metadata to a device listing."""
    summary = dict(device)
    serial = device.get("serial")
    if not serial:
        return summary

    details = get_basic_properties(serial)
    summary.update(details)
    stats = get_device_stats(serial)
    summary.update(stats)
    return summary


def list_packages(serial: str) -> List[str]:
    """Return package names via ``pm list packages``."""
    completed = run_shell_command(serial, ["pm", "list", "packages"], timeout=15)
    if completed.returncode != 0:
        return []

    packages: List[str] = []
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("package:"):
            packages.append(stripped.split(":", 1)[1].strip())
    return packages


def list_packages_with_versions(
    serial: str,
    *,
    allow_fallbacks: bool = False,
) -> List[Tuple[str, Optional[str], Optional[str]]]:
    """Return package identifiers along with version metadata when available."""

    attempts = [
        ["pm", "list", "packages", "--show-versioncode", "--show-versionname"],
        ["pm", "list", "packages", "--show-versioncode"],
    ]

    for command in attempts:
        try:
            completed = run_shell_command(serial, command, timeout=20)
        except RuntimeError:
            continue

        if completed.returncode != 0:
            continue

        parsed = _parse_package_listing(completed.stdout)
        if parsed:
            return parsed

    # Fallback to basic package names if newer flags are unsupported.
    if not allow_fallbacks:
        log.warning(
            "Inventory fallback blocked: pm --show-version* unsupported.",
            category="inventory",
            extra={
                "event": "inventory.fallback_blocked",
                "reason": "pm_list_versions_unsupported",
                "serial": serial,
            },
        )
        raise RuntimeError(
            "Inventory fallback blocked (pm --show-version* unsupported). "
            "Enable inventory fallbacks in the Device Analysis menu to proceed."
        )
    log.warning(
        "Inventory fallback invoked: pm --show-version* unsupported; "
        "using package-only listing.",
        category="inventory",
        extra={
            "event": "inventory.fallback",
            "reason": "pm_list_versions_unsupported",
            "serial": serial,
        },
    )
    return [(package, None, None) for package in list_packages(serial)]


def get_package_paths(
    serial: str,
    package_name: str,
    refresh: bool = False,
    *,
    allow_fallbacks: bool = False,
) -> List[str]:
    """Return canonical APK paths for a package using ``pm path``."""
    cache_key = (serial, package_name)
    if not refresh and cache_key in _PACKAGE_PATH_CACHE:
        return _PACKAGE_PATH_CACHE[cache_key]

    paths: List[str] = []
    completed = run_shell_command(serial, ["pm", "path", package_name], timeout=15)
    if completed.returncode == 0:
        for line in completed.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("package:"):
                paths.append(stripped.split(":", 1)[1].strip())

    if not paths:
        if not allow_fallbacks:
            log.warning(
                "Inventory fallback blocked: pm path returned no entries.",
                category="inventory",
                extra={
                    "event": "inventory.fallback_blocked",
                    "reason": "pm_path_empty",
                    "serial": serial,
                    "package": package_name,
                },
            )
            raise RuntimeError(
                "Inventory fallback blocked (pm path empty). "
                "Enable inventory fallbacks in the Device Analysis menu to proceed."
            )
        log.warning(
            "Inventory fallback invoked: pm path returned no entries; "
            "using pm list packages -f.",
            category="inventory",
            extra={
                "event": "inventory.fallback",
                "reason": "pm_path_empty",
                "serial": serial,
                "package": package_name,
            },
        )
        fallback = run_shell_command(
            serial,
            ["pm", "list", "packages", "-f", package_name],
            timeout=15,
        )
        if fallback.returncode == 0:
            for line in fallback.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("package:") and "=" in stripped:
                    apk_path, _ = stripped.removeprefix("package:").rsplit("=", 1)
                    paths.append(apk_path.strip())

    _PACKAGE_PATH_CACHE[cache_key] = paths
    return paths


def get_package_metadata(serial: str, package_name: str, refresh: bool = False) -> Dict[str, Optional[str]]:
    """Return metadata for a package via ``pm dump`` (cached)."""
    cache_key = (serial, package_name)
    if not refresh and cache_key in _PACKAGE_META_CACHE:
        return _PACKAGE_META_CACHE[cache_key]

    try:
        completed = run_shell_command(serial, ["pm", "dump", package_name], timeout=25)
    except RuntimeError:
        return {}

    if completed.returncode != 0:
        return {}

    metadata: Dict[str, Optional[str]] = {"package_name": package_name}
    version_code_pattern = re.compile(r"versionCode=(\d+)")
    version_name_pattern = re.compile(r"versionName=([^\s]+)")

    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("application-label:"):
            metadata["app_label"] = stripped.split(":", 1)[1].strip().strip("'")
        elif stripped.startswith("application-label-") and "app_label" not in metadata:
            metadata["app_label"] = stripped.split(":", 1)[1].strip().strip("'")
        elif stripped.startswith("packageName="):
            metadata["package_name"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("userId="):
            metadata["user_id"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("firstInstallTime="):
            metadata["first_install"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("lastUpdateTime="):
            metadata["last_update"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("installerPackageName="):
            metadata["installer"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("versionCode="):
            match = version_code_pattern.search(stripped)
            if match:
                metadata["version_code"] = match.group(1)
        elif stripped.startswith("versionName="):
            match = version_name_pattern.search(stripped)
            if match:
                metadata["version_name"] = match.group(1)

    _PACKAGE_META_CACHE[cache_key] = metadata
    return metadata


def get_device_stats(serial: str) -> Dict[str, Optional[str]]:
    """Collect live telemetry for the provided device."""
    stats: Dict[str, Optional[str]] = {}

    battery = _get_battery_info(serial)
    stats.update(battery)

    wifi_state = _get_wifi_state(serial)
    if wifi_state:
        stats["wifi_state"] = wifi_state

    root_state = _check_root_status(serial)
    if root_state:
        stats["is_rooted"] = root_state

    return stats


def clear_package_caches(serial: Optional[str] = None) -> None:
    """Clear cached package metadata and paths."""
    if serial is None:
        _PACKAGE_PATH_CACHE.clear()
        _PACKAGE_META_CACHE.clear()
        return

    path_keys = [key for key in _PACKAGE_PATH_CACHE if key[0] == serial]
    for key in path_keys:
        _PACKAGE_PATH_CACHE.pop(key, None)

    meta_keys = [key for key in _PACKAGE_META_CACHE if key[0] == serial]
    for key in meta_keys:
        _PACKAGE_META_CACHE.pop(key, None)


def _get_battery_info(serial: str) -> Dict[str, Optional[str]]:
    try:
        completed = run_shell_command(serial, ["dumpsys", "battery"])
    except RuntimeError:
        return {}
    if completed.returncode != 0:
        return {}

    level: Optional[str] = None
    status: Optional[str] = None
    charging: Optional[str] = None

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

    result: Dict[str, Optional[str]] = {}
    if level is not None and level.isdigit():
        result["battery_level"] = f"{level}%"
    if status:
        result["battery_status"] = status

    return result


def _parse_package_listing(output: str) -> List[Tuple[str, Optional[str], Optional[str]]]:
    packages: List[Tuple[str, Optional[str], Optional[str]]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line.startswith("package:"):
            continue

        package_name: Optional[str] = None
        version_code: Optional[str] = None
        version_name: Optional[str] = None

        for token in line.split():
            if token.startswith("package:"):
                package_name = token.split(":", 1)[1].strip()
                # pm list packages --show-version* can include path=package; keep only the package id.
                if "=" in package_name:
                    package_name = package_name.rsplit("=", 1)[-1].strip()
            elif token.startswith("versionCode:"):
                version_code = token.split(":", 1)[1].strip()
            elif token.startswith("versionName:"):
                version_name = token.split(":", 1)[1].strip()

        if package_name:
            packages.append((package_name, version_code or None, version_name or None))

    return packages


def _get_wifi_state(serial: str) -> Optional[str]:
    try:
        completed = run_shell_command(serial, ["settings", "get", "global", "wifi_on"])
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


def _check_root_status(serial: str) -> Optional[str]:
    try:
        completed = run_shell_command(serial, ["id", "-u"])
    except RuntimeError:
        return None
    if completed.returncode == 0:
        user = completed.stdout.strip()
        if user == "0":
            return "Yes"
        return "No"
    return None
