"""Telemetry sampling for dynamic sessions (DB-first)."""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from scytaledroid.BehaviorAnalysis.telemetry import (
    parse_meminfo_total,
    parse_netstats_detail,
    parse_proc_net_dev,
    parse_top_output,
)
from scytaledroid.DeviceAnalysis import adb_shell


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
        sample_rate_s: int = 2,
        allow_fallback_iface: bool = True,
    ) -> None:
        self.device_serial = device_serial
        self.package_name = package_name
        self.sample_rate_s = max(int(sample_rate_s), 1)
        self._netstats_interval_s = max(self.sample_rate_s * 3, 3)
        self._allow_fallback_iface = allow_fallback_iface
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._error: str | None = None
        self._process_rows: list[dict[str, object]] = []
        self._network_rows: list[dict[str, object]] = []
        self._timestamps: list[float] = []
        self._monotonic_timestamps: list[float] = []
        self._uid: str | None = None
        self._pid: str | None = None
        self._start_monotonic: float | None = None
        self._end_monotonic: float | None = None
        self._last_netstats_monotonic: float | None = None
        self._netstats_samples: int = 0
        self._netstats_skipped: int = 0
        self._last_network_row: dict[str, object] | None = None
        self._meminfo_interval_s = max(self.sample_rate_s * 3, 3)
        self._last_meminfo_monotonic: float | None = None
        self._meminfo_samples: int = 0
        self._meminfo_skipped: int = 0
        self._last_meminfo_pss: int | None = None

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
        stats["netstats_interval_s"] = self._netstats_interval_s
        stats["netstats_samples"] = self._netstats_samples
        stats["netstats_skipped"] = self._netstats_skipped
        stats["netstats_available"] = self._netstats_samples > 0
        netstats_rows = sum(1 for row in self._network_rows if row.get("source") == "netstats")
        netstats_missing_rows = sum(1 for row in self._network_rows if row.get("source") == "netstats_missing")
        stats["netstats_rows"] = netstats_rows
        stats["netstats_missing_rows"] = netstats_missing_rows
        stats["network_signal_quality"] = _network_signal_quality(netstats_rows, netstats_missing_rows)
        stats["meminfo_interval_s"] = self._meminfo_interval_s
        stats["meminfo_samples"] = self._meminfo_samples
        stats["meminfo_skipped"] = self._meminfo_skipped
        return TelemetryCapture(self._process_rows, self._network_rows, stats)

    def _run(self) -> None:
        sample_index = 0
        try:
            next_tick = time.monotonic()
            while not self._stop_event.is_set():
                ts = datetime.now(UTC)
                now_monotonic = time.monotonic()
                self._timestamps.append(ts.timestamp())
                self._monotonic_timestamps.append(now_monotonic)
                process_row = _collect_process_sample(
                    self.device_serial,
                    self.package_name,
                    self._uid,
                    self._pid,
                    ts,
                )
                self._maybe_collect_meminfo(process_row, now_monotonic)
                process_row["sample_index"] = sample_index
                process_row["timestamp_utc"] = ts
                self._process_rows.append(process_row)

                use_netstats = True
                if self._last_netstats_monotonic is not None:
                    use_netstats = (now_monotonic - self._last_netstats_monotonic) >= self._netstats_interval_s
                if use_netstats:
                    self._last_netstats_monotonic = now_monotonic
                    self._netstats_samples += 1
                else:
                    self._netstats_skipped += 1
                network_row = _collect_network_sample(
                    self.device_serial,
                    self._uid,
                    ts,
                    use_netstats=use_netstats,
                    last_netstats=self._last_network_row,
                    allow_fallback_iface=self._allow_fallback_iface,
                )
                network_row["sample_index"] = sample_index
                network_row["timestamp_utc"] = ts
                self._network_rows.append(network_row)
                if network_row.get("source") == "netstats":
                    self._last_network_row = dict(network_row)

                sample_index += 1
                next_tick += self.sample_rate_s
                sleep_for = max(0.0, next_tick - time.monotonic())
                if sleep_for:
                    time.sleep(sleep_for)
        except Exception as exc:  # pragma: no cover - defensive
            self._error = str(exc)

    def _maybe_collect_meminfo(self, row: dict[str, object], now_monotonic: float) -> None:
        if self._uid is None:
            return
        use_meminfo = True
        if self._last_meminfo_monotonic is not None:
            use_meminfo = (now_monotonic - self._last_meminfo_monotonic) >= self._meminfo_interval_s
        if use_meminfo:
            self._last_meminfo_monotonic = now_monotonic
            self._meminfo_samples += 1
            mem_total = _maybe_parse_meminfo(self.device_serial, self.package_name)
            if mem_total is not None:
                self._last_meminfo_pss = mem_total
                _set_pss(row, mem_total)
        else:
            self._meminfo_skipped += 1
            _set_pss(row, self._last_meminfo_pss)


def _run_shell(serial: str, command: list[str], timeout: float) -> tuple[int, str, bool]:
    try:
        completed = adb_shell.run_shell_command(serial, command, timeout=timeout)
        return completed.returncode, completed.stdout or "", False
    except RuntimeError as exc:
        message = str(exc).lower()
        timed_out = "timed out" in message
        return 1, "", timed_out


def _resolve_pid_uid(serial: str, package: str) -> tuple[str | None, str | None]:
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
    uid: str | None,
    pid: str | None,
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

    return row


def _collect_network_sample(
    serial: str,
    uid: str | None,
    ts: datetime,
    *,
    use_netstats: bool = True,
    last_netstats: dict[str, object] | None = None,
    allow_fallback_iface: bool = True,
) -> dict[str, object]:
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
    if use_netstats:
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
        if not allow_fallback_iface:
            row["source"] = "netstats_missing"
            row["collector_status"] = "missing_uid_stats"
            row["best_effort"] = 0
            row["bytes_in"] = None
            row["bytes_out"] = None
            row["conn_count"] = None
            return row
    if last_netstats:
        row["bytes_in"] = last_netstats.get("bytes_in", "")
        row["bytes_out"] = last_netstats.get("bytes_out", "")
        row["conn_count"] = last_netstats.get("conn_count", "")
        row["source"] = "netstats_cached"
        row["best_effort"] = 1
        row["collector_status"] = "cached"
        return row
    row["collector_status"] = "skipped"
    row["source"] = "unavailable"
    return row


def _network_signal_quality(netstats_rows: int, netstats_missing_rows: int) -> str:
    if netstats_rows > 0 and netstats_missing_rows > 0:
        return "netstats_partial"
    if netstats_rows > 0:
        return "netstats_only"
    return "none"


def _maybe_parse_meminfo(serial: str, package: str) -> int | None:
    try:
        rc, mem_out, _ = _run_shell(serial, ["dumpsys", "meminfo", "--package", package], timeout=5.0)
        if rc == 0:
            return parse_meminfo_total(mem_out)
    except Exception:
        return None
    return None


def _set_pss(row: dict[str, object], value: int | None) -> None:
    if value is None:
        return
    row["pss_kb"] = value


def _compute_stats(
    *,
    timestamps: list[float],
    monotonic_timestamps: list[float],
    start_monotonic: float | None,
    end_monotonic: float | None,
    sample_rate_s: int,
    error: str | None,
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
        deltas = [
            b - a for a, b in zip(monotonic_timestamps, monotonic_timestamps[1:], strict=False)
        ]
        stats["sample_min_delta_s"] = min(deltas)
        stats["sample_avg_delta_s"] = sum(deltas) / len(deltas)
        stats["sample_max_delta_s"] = max(deltas)
        stats["sample_max_gap_s"] = max(deltas)
    return stats


__all__ = ["TelemetrySampler", "TelemetryCapture"]
