"""Lightweight runtime monitor for dynamic runs."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.DeviceAnalysis import adb_shell
from scytaledroid.Utils.DisplayUtils import status_messages


PCAPDROID_PACKAGE = "com.emanuelef.remote_capture"
PCAPDROID_DIR = "/sdcard/Download/PCAPdroid"


@dataclass
class RunMonitorConfig:
    device_serial: str
    run_id: str
    notes_dir: Path
    poll_s: float = 2.0
    interactive: bool = True
    verbose: bool = False


class RunMonitor:
    def __init__(self, config: RunMonitorConfig) -> None:
        self.config = config
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_size: int | None = None
        self._last_print: float = 0.0

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self) -> None:
        notes_path = self.config.notes_dir / "run_monitor.jsonl"
        notes_path.parent.mkdir(parents=True, exist_ok=True)
        pcap_path = f"{PCAPDROID_DIR}/scytaledroid_{self.config.run_id}.pcap"
        while not self._stop_event.is_set():
            snapshot = {
                "ts": time.time(),
                "pcap_size": _device_file_size(self.config.device_serial, pcap_path),
                "pcap_path": pcap_path,
                "pcapdroid_pid": _pidof(self.config.device_serial, PCAPDROID_PACKAGE),
                "net_state": _net_state(self.config.device_serial),
            }
            try:
                with notes_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(snapshot) + "\n")
            except Exception:
                pass

            if self.config.interactive and self.config.verbose:
                self._maybe_print(snapshot)
            time.sleep(max(self.config.poll_s, 0.5))

    def _maybe_print(self, snapshot: dict[str, object]) -> None:
        size = snapshot.get("pcap_size")
        now = time.time()
        if size != self._last_size or (now - self._last_print) > 10:
            self._last_size = size if isinstance(size, int) else None
            self._last_print = now
        size_label = f"{size}B" if isinstance(size, int) else "waiting"
        pid = snapshot.get("pcapdroid_pid") or "n/a"
        net = snapshot.get("net_state") or "unknown"
            print(
                status_messages.status(
                    f"Monitor: pcap={size_label} | pcapdroid={pid} | net={net}",
                    level="info",
                )
            )


def _device_file_size(serial: str, path: str) -> int | None:
    try:
        out = adb_shell.run_shell(serial, ["stat", "-c", "%s", path]).strip()
        return int(out)
    except Exception:
        return None


def _pidof(serial: str, package: str) -> str | None:
    try:
        out = adb_shell.run_shell(serial, ["pidof", "-s", package]).strip()
        return out or None
    except Exception:
        return None


def _net_state(serial: str) -> str | None:
    try:
        status = adb_shell.run_shell(serial, ["dumpsys", "connectivity"]).lower()
    except Exception:
        return None
    if "not connected" in status:
        return "not_connected"
    if "not_vpn" in status or "not vpn" in status:
        return "not_vpn"
    if "validated" in status:
        return "validated"
    return "unknown"


__all__ = ["RunMonitor", "RunMonitorConfig"]
