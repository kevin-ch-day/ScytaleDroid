"""Observer selection helpers for dynamic analysis flows."""

from __future__ import annotations

import os
from scytaledroid.DeviceAnalysis import adb_shell
from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages
from scytaledroid.DynamicAnalysis.observers.pcapdroid_capture import PCAPDROID_PACKAGE

_OBSERVER_PREFS: dict[tuple[str, str], dict[str, bool]] = {}


def select_observers(device_serial: str, *, mode: str) -> list[str]:
    prefs = _OBSERVER_PREFS.get((device_serial, mode), {})
    pcap_available = _device_has_pcapdroid(device_serial)
    default_pcap = prefs.get("pcapdroid", pcap_available)
    default_logs = prefs.get("system_log", True)

    prompt_enabled = os.environ.get("SCYTALEDROID_OBSERVER_PROMPTS") == "1"
    if not prompt_enabled:
        use_pcapdroid = bool(default_pcap) if pcap_available else False
        use_logs = bool(default_logs)
        _OBSERVER_PREFS[(device_serial, mode)] = {
            "pcapdroid": use_pcapdroid,
            "system_log": use_logs,
        }
        selections = []
        selections.append(f"PCAPdroid: {'on' if use_pcapdroid else 'off'}")
        selections.append(f"System log: {'on' if use_logs else 'off'}")
        hint = "Set SCYTALEDROID_OBSERVER_PROMPTS=1 to change."
        print(status_messages.status(" | ".join(selections) + f" ({hint})", level="info"))
        observer_ids: list[str] = []
        if use_pcapdroid:
            observer_ids.append("pcapdroid_capture")
        if use_logs:
            observer_ids.append("system_log_capture")
        return observer_ids

    if pcap_available:
        print(
            status_messages.status(
                "PCAPdroid scope: app-only traffic (UID). If traffic is missing, consider full-device "
                "capture for diagnostics.",
                level="info",
            )
        )
    else:
        print(status_messages.status("PCAPdroid not installed; VPN capture unavailable.", level="warn"))

    use_pcapdroid = False
    if pcap_available:
        use_pcapdroid = prompt_utils.prompt_yes_no(
            "Enable PCAPdroid capture?",
            default=default_pcap,
        )
    use_logs = prompt_utils.prompt_yes_no(
        "Enable system log capture?",
        default=default_logs,
    )

    _OBSERVER_PREFS[(device_serial, mode)] = {
        "pcapdroid": use_pcapdroid,
        "system_log": use_logs,
    }

    observer_ids: list[str] = []
    if use_pcapdroid:
        observer_ids.append("pcapdroid_capture")
    if use_logs:
        observer_ids.append("system_log_capture")
    return observer_ids


def _device_has_pcapdroid(device_serial: str) -> bool:
    try:
        output = adb_shell.run_shell(device_serial, ["pm", "path", PCAPDROID_PACKAGE]).strip()
    except Exception:
        return False
    return output.startswith("package:")


__all__ = ["select_observers"]
