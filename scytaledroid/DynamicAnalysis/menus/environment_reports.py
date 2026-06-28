"""Capture-environment reporting helpers for Dynamic Analysis menus."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages, table_utils


def capture_environment_summary() -> dict[str, object]:
    required_tools = ("adb", "tshark", "capinfos")
    optional_tools = ("tcpdump", "dumpcap", "editcap", "mergecap", "frida", "mitmproxy", "mitmdump")
    tools: dict[str, dict[str, object]] = {}
    for name in (*required_tools, *optional_tools):
        path = shutil.which(name)
        tools[name] = {"path": path, "present": bool(path)}

    adb_devices: list[str] = []
    adb_path = tools.get("adb", {}).get("path")
    if adb_path:
        try:
            completed = subprocess.run(
                [str(adb_path), "devices"],
                check=False,
                capture_output=True,
                text=True,
                timeout=8,
            )
            for line in (completed.stdout or "").splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "device":
                    adb_devices.append(parts[0])
        except Exception:
            adb_devices = []

    evidence_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    nearest_existing = evidence_root
    while not nearest_existing.exists() and nearest_existing != nearest_existing.parent:
        nearest_existing = nearest_existing.parent
    evidence_root_ready = (
        (evidence_root.exists() and os.access(evidence_root, os.R_OK | os.W_OK))
        or (not evidence_root.exists() and nearest_existing.exists() and os.access(nearest_existing, os.W_OK))
    )
    blocking = []
    for name in required_tools:
        if not tools.get(name, {}).get("present"):
            blocking.append(f"missing {name}")
    if not adb_devices:
        blocking.append("no adb device visible")
    if not evidence_root_ready:
        blocking.append("dynamic evidence root is not writable")

    return {
        "required_tools": required_tools,
        "optional_tools": optional_tools,
        "tools": tools,
        "adb_devices": adb_devices,
        "evidence_root": str(evidence_root),
        "evidence_root_exists": bool(evidence_root.exists()),
        "evidence_root_ready": bool(evidence_root_ready),
        "blocking_issues": blocking,
    }


def render_host_pcap_tools() -> None:
    """Render host/device toolchain status required for dynamic capture."""

    print()
    menu_utils.print_header("Capture Environment")
    env = capture_environment_summary()
    tools = env.get("tools") if isinstance(env.get("tools"), dict) else {}
    required = tuple(env.get("required_tools") or ())
    optional = tuple(env.get("optional_tools") or ())
    devices = env.get("adb_devices") if isinstance(env.get("adb_devices"), list) else []
    blocking = env.get("blocking_issues") if isinstance(env.get("blocking_issues"), list) else []
    ui_level = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower()
    verbose = ui_level in {"details", "debug"}

    required_rows = []
    for name in required:
        meta = tools.get(name) if isinstance(tools.get(name), dict) else {}
        present = bool(meta.get("present"))
        value = "present" if present else "missing"
        if verbose and meta.get("path"):
            value = str(meta.get("path"))
        required_rows.append((name, value))
    required_rows.append(("device visible", ", ".join(str(d) for d in devices) if devices else "missing"))
    required_rows.append(("dynamic evidence root writable", "yes" if env.get("evidence_root_ready") else "no"))
    menu_utils.print_header("Required")
    table_utils.render_table(["Check", "Status"], required_rows, compact=False)

    optional_present = []
    optional_missing = []
    for name in optional:
        meta = tools.get(name) if isinstance(tools.get(name), dict) else {}
        if meta.get("present"):
            optional_present.append((name, str(meta.get("path") or "present")))
        else:
            optional_missing.append(name)
    if optional_present:
        print()
        menu_utils.print_header("Optional Present")
        table_utils.render_table(["Tool", "Path"], optional_present, compact=False)
    print()
    menu_utils.print_header("Optional Missing")
    print(", ".join(optional_missing) if optional_missing else "none")

    print()
    menu_utils.print_header("Blocking Issues")
    if blocking:
        for issue in blocking:
            print(status_messages.status(str(issue), level="warn"))
    else:
        print(status_messages.status("required ready", level="success"))
