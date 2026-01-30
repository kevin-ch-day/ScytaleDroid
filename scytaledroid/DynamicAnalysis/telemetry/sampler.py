"""Telemetry sampling for dynamic sessions (DB-first)."""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from scytaledroid.DeviceAnalysis import adb_utils
from scytaledroid.BehaviorAnalysis.telemetry import (
    parse_meminfo_total,
    parse_netstats_detail,
    parse_proc_net_dev,
    parse_top_output,
)


@dataclass
class TelemetryCapture:
    process_rows: list[dict[str, object]]
    network_rows: list[dict[str, object]]
    stats: dict[str, object]


class TelemetrySampler:
    def __init__(
        self,
        *,
        device_serial: str,
        package_name: str,
        sample_rate_s: int = 1,
    ) -> None:
        self.device_serial = device_serial
        self.package_name = package_name
        self.sample_rate_s = max(int(sample_rate_s), 1)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._error: Optional[str] = None
        self._process_rows: list[dict[str, object]] = []
        self._network_rows: list[dict[str, object]] = []
        self._timestamps: list[float] = []
        self._monotonic_timestamps: list[float] = []
        self._uid: Optional[str] = None
        self._pid: Optional[str] = None
        self._start_monotonic: Optional[float] = None
        self._end_monotonic: Optional[float] = None

    def start(self) -> None:
        self._uid, self._pid = _resolve_pid_uid(self.device_serial, self.package_name)
        self._start_monotonic = time.monotonic()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> TelemetryCapture:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._end_monotonic = time.monotonic()
        stats = _compute_stats(
            timestamps=self._timestamps,
            monotonic_timestamps=self._monotonic_timestamps,
            start_monotonic=self._start_monotonic,
            end_monotonic=self._end_monotonic,
            sample_rate_s=self.sample_rate_s,
            error=self._error,
        )
        return TelemetryCapture(self._process_rows, self._network_rows, stats)

    def _run(self) -> None:
        sample_index = 0
        try:
            while not self._stop_event.is_set():
                ts = datetime.now(timezone.utc)
                self._timestamps.append(ts.timestamp())
                self._monotonic_timestamps.append(time.monotonic())
                process_row = _collect_process_sample(
                    self.device_serial,
                    self.package_name,
                    self._uid,
                    self._pid,
                    ts,
                )
                process_row["sample_index"] = sample_index
                process_row["timestamp_utc"] = ts
                self._process_rows.append(process_row)

                network_row = _collect_network_sample(self.device_serial, self._uid, ts)
                network_row["sample_index"] = sample_index
                network_row["timestamp_utc"] = ts
                self._network_rows.append(network_row)

                sample_index += 1
                time.sleep(self.sample_rate_s)
        except Exception as exc:  # pragma: no cover - defensive
            self._error = str(exc)


def _run_shell(serial: str, command: list[str], timeout: float) -> tuple[int, str, bool]:
    try:
        completed = adb_utils.run_shell_command(serial, command, timeout=timeout)
        return completed.returncode, completed.stdout or "", False
    except RuntimeError as exc:
        message = str(exc).lower()
        timed_out = "timed out" in message
        return 1, "", timed_out


def _resolve_pid_uid(serial: str, package: str) -> tuple[Optional[str], Optional[str]]:
    uid = None
    try:
        rc, out, _ = _run_shell(serial, ["dumpsys", "package", package], timeout=5.0)
        if rc != 0:
            out = ""
        match = re.search(r"userId=(\d+)", out)
        if match:
            uid = match.group(1)
    except Exception:
        uid = None

    if uid is None:
        try:
            rc, out_u, _ = _run_shell(serial, ["cmd", "package", "list", "packages", "-U", package], timeout=5.0)
            if rc != 0:
                out_u = ""
            m2 = re.search(r"uid:(\d+)", out_u)
            if m2:
                uid = m2.group(1)
        except Exception:
            uid = None

    pid = None
    try:
        rc, pid_out, _ = _run_shell(serial, ["pidof", "-s", package], timeout=3.0)
        if rc != 0:
            pid_out = ""
        pid = pid_out.strip() or None
    except Exception:
        pid = None

    return uid, pid


def _collect_process_sample(
    serial: str,
    package: str,
    uid: Optional[str],
    pid: Optional[str],
    ts: datetime,
) -> dict[str, object]:
    row: dict[str, object] = {
        "uid": uid or "",
        "pid": pid or "",
        "cpu_pct": "",
        "rss_kb": "",
        "pss_kb": "",
        "threads": "",
        "proc_name": package,
        "best_effort": 1,
        "collector_status": "unavailable",
    }
    if uid is None:
        row["collector_status"] = "unavailable_uid"
        return row

    if not pid:
        try:
            rc, pid_out, _ = _run_shell(serial, ["pidof", "-s", package], timeout=3.0)
            if rc == 0:
                pid = pid_out.strip() or None
        except Exception:
            pid = None
    row["pid"] = pid or ""

    try:
        rc, out, timed_out = _run_shell(serial, ["top", "-b", "-n", "1", "-o", "PID,CPU,RES,NAME"], timeout=5.0)
        if timed_out:
            row["collector_status"] = "timeout"
        elif rc == 0 and pid:
            parsed = parse_top_output(out, pid)
            if parsed:
                row["cpu_pct"] = parsed.get("cpu_pct", "")
                row["rss_kb"] = parsed.get("rss_kb", "")
                row["proc_name"] = parsed.get("proc_name", package)
                row["best_effort"] = 0
                row["collector_status"] = "ok"
            else:
                try:
                    rc2, pid_out, _ = _run_shell(serial, ["pidof", "-s", package], timeout=3.0)
                    if rc2 == 0:
                        pid = pid_out.strip() or None
                        row["pid"] = pid or ""
                except Exception:
                    pid = None
                row["collector_status"] = "pid_missing"
        elif rc == 0 and not pid:
            row["collector_status"] = "pid_missing"
        else:
            row["collector_status"] = "collector_failed"
    except Exception:
        row["collector_status"] = "collector_failed"

    try:
        rc, mem_out, _ = _run_shell(serial, ["dumpsys", "meminfo", "--package", package], timeout=5.0)
        if rc == 0:
            mem_total = parse_meminfo_total(mem_out)
            if mem_total is not None:
                row["pss_kb"] = mem_total
    except Exception:
        pass
    return row


def _collect_network_sample(serial: str, uid: Optional[str], ts: datetime) -> dict[str, object]:
    row: dict[str, object] = {
        "uid": uid or "",
        "bytes_in": "",
        "bytes_out": "",
        "conn_count": "",
        "source": "best_effort",
        "best_effort": 1,
        "collector_status": "unavailable",
    }
    if not uid:
        row["collector_status"] = "unavailable_uid"
        row["source"] = "unavailable"
        return row
    try:
        rc, out, timed_out = _run_shell(serial, ["dumpsys", "netstats", "detail"], timeout=5.0)
        if timed_out:
            row["collector_status"] = "timeout"
        elif rc == 0 and f"uid={uid}" in out:
            bytes_in, bytes_out = parse_netstats_detail(out, uid)
            row["bytes_in"] = bytes_in
            row["bytes_out"] = bytes_out
            row["conn_count"] = ""
            row["source"] = "netstats"
            row["best_effort"] = 0
            row["collector_status"] = "ok"
            return row
    except Exception:
        pass
    try:
        rc, out2, timed_out = _run_shell(serial, ["cat", "/proc/net/dev"], timeout=3.0)
        if timed_out:
            row["collector_status"] = "timeout"
            row["source"] = "unavailable"
        elif rc == 0:
            bytes_in, bytes_out = parse_proc_net_dev(out2)
            row["bytes_in"] = bytes_in
            row["bytes_out"] = bytes_out
            row["conn_count"] = ""
            row["source"] = "fallback_iface"
            row["best_effort"] = 1
            row["collector_status"] = "best_effort"
        else:
            row["collector_status"] = "collector_failed"
    except Exception:
        row["collector_status"] = "collector_failed"
    return row


def _compute_stats(
    *,
    timestamps: list[float],
    monotonic_timestamps: list[float],
    start_monotonic: Optional[float],
    end_monotonic: Optional[float],
    sample_rate_s: int,
    error: Optional[str],
) -> dict[str, object]:
    stats: dict[str, object] = {
        "expected_samples": None,
        "captured_samples": len(timestamps),
        "sample_min_delta_s": None,
        "sample_avg_delta_s": None,
        "sample_max_delta_s": None,
        "sample_max_gap_s": None,
        "error": error,
    }
    if start_monotonic is not None and end_monotonic is not None:
        elapsed = max(end_monotonic - start_monotonic, 0.0)
        stats["expected_samples"] = int(elapsed / sample_rate_s) + 1
    if len(monotonic_timestamps) >= 2:
        deltas = [b - a for a, b in zip(monotonic_timestamps, monotonic_timestamps[1:])]
        stats["sample_min_delta_s"] = min(deltas)
        stats["sample_avg_delta_s"] = sum(deltas) / len(deltas)
        stats["sample_max_delta_s"] = max(deltas)
        stats["sample_max_gap_s"] = max(deltas)
    return stats


__all__ = ["TelemetrySampler", "TelemetryCapture"]
