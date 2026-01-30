"""Device discovery and identity helpers."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis import adb_client
from scytaledroid.DeviceAnalysis.adb_shell import ADB_TIMEOUT_DISCOVERY


def scan_devices() -> Tuple[List[Dict[str, Optional[str]]], List[str]]:
    """Return devices and any informational warnings gathered during discovery."""
    adb_bin = adb_client.get_adb_binary()
    warnings: List[str] = []
    if adb_bin is None:
        warnings.append(
            "adb binary not found on PATH. Install Android platform tools or update PATH."
        )
        return [], warnings

    try:
        result = adb_client.run_adb_command(
            ["devices", "-l"],
            timeout=ADB_TIMEOUT_DISCOVERY,
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


def _fetch_all_properties(serial: str) -> Dict[str, str]:
    """Return the full ``getprop`` dictionary for the provided device."""
    try:
        completed = adb_client.run_shell_command(serial, ["getprop"])
    except RuntimeError:
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
    from scytaledroid.DeviceAnalysis.device_status import get_device_stats

    summary = dict(device)
    serial = device.get("serial")
    if not serial:
        return summary

    details = get_basic_properties(serial)
    summary.update(details)
    stats = get_device_stats(serial)
    summary.update(stats)
    return summary
