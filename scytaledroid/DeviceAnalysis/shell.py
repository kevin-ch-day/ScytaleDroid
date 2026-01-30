"""shell.py - Interactive adb shell wrapper."""

from __future__ import annotations

import subprocess
from typing import Optional

from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from . import adb_client


def open_shell(serial: Optional[str]) -> None:
    """Launch an interactive adb shell for the active device."""
    if not serial:
        print(status_messages.status("No active device. Connect first to open a shell.", level="warn"))
        return

    adb_path = adb_client.get_adb_binary()
    if not adb_path:
        print(status_messages.status("adb binary not found on PATH.", level="error"))
        return

    print(status_messages.status("Starting interactive adb shell. Press Ctrl+D or type 'exit' to leave."))
    log.info(f"Opening adb shell for {serial}", category="device")

    command = [adb_path, "-s", serial, "shell"]
    try:
        subprocess.call(command)
    except KeyboardInterrupt:
        print()
        print(status_messages.status("Shell interrupted by user.", level="warn"))
    finally:
        log.info(f"Interactive shell closed for {serial}", category="device")
