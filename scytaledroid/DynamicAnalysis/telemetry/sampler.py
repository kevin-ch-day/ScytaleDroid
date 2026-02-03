"""Telemetry sampling for dynamic sessions (DB-first)."""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.DeviceAnalysis import adb_shell
from scytaledroid.Utils.process_parsers import parse_meminfo_total, parse_top_output
from scytaledroid.Utils.netstats_collector import NetstatsCollector
from scytaledroid.Utils.netstats_parser import NetstatsParser
from scytaledroid.Utils.network_quality import evaluate_network_signal_quality


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
        netstats_debug_dir: Path | None = None,
    ) -> None:
        self.device_serial = device_serial
        self.package_name = package_name
        self.sample_rate_s = max(int(sample_rate_s), 1)
        self._netstats_interval_s = max(self.sample_rate_s * 3, 3)
        self._allow_fallback_iface = allow_fallback_iface
        self._netstats_debug_dir = netstats_debug_dir
        self._netstats_debug_captured = False
        self._netstats_collector = NetstatsCollector()
        self._netstats_parser = NetstatsParser()
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
        self._last_netstats_totals: tuple[int, int] | None = None
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
        netstats_rows = sum(1 for row in self._network_rows if row.get("source") == "netstats")
        netstats_delta_init_rows = sum(
            1
            for row in self._network_rows
            if row.get("source") == "netstats_missing" and row.get("collector_status") == "delta_init"
        )
        netstats_missing_rows = sum(
            1
            for row in self._network_rows
            if row.get("source") == "netstats_missing" and row.get("collector_status") != "delta_init"
        )
        netstats_bytes_in, netstats_bytes_out = _sum_netstats_bytes(self._network_rows)
        stats["netstats_available"] = netstats_rows > 0
        stats["netstats_rows"] = netstats_rows
        stats["netstats_missing_rows"] = netstats_missing_rows
        stats["netstats_delta_init_rows"] = netstats_delta_init_rows
        stats["netstats_bytes_in_total"] = netstats_bytes_in
        stats["netstats_bytes_out_total"] = netstats_bytes_out
        stats["network_signal_quality"] = evaluate_network_signal_quality(
            netstats_rows=netstats_rows,
            netstats_missing_rows=netstats_missing_rows,
            sum_bytes_in=netstats_bytes_in,
            sum_bytes_out=netstats_bytes_out,
        )
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
                network_row = None
                netstats_totals = None
                if use_netstats or self._allow_fallback_iface:
                    network_row, netstats_totals = _collect_network_sample(
                        self.device_serial,
                        self._uid,
                        ts,
                        use_netstats=use_netstats,
                        last_netstats=self._last_network_row,
                        allow_fallback_iface=self._allow_fallback_iface,
                        netstats_collector=self._netstats_collector,
                        netstats_parser=self._netstats_parser,
                        debug_dir=self._netstats_debug_dir,
                        debug_captured=self._netstats_debug_captured,
                    )
                if network_row is not None:
                    if netstats_totals is not None:
                        network_row = self._apply_netstats_delta(network_row, netstats_totals)
                    if network_row.get("collector_status") == "debug_captured":
                        self._netstats_debug_captured = True
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

    def _apply_netstats_delta(
        self,
        row: dict[str, object],
        totals: tuple[int, int],
    ) -> dict[str, object]:
        if self._last_netstats_totals is None:
            self._last_netstats_totals = totals
            row["source"] = "netstats_missing"
            row["collector_status"] = "delta_init"
            row["bytes_in"] = None
            row["bytes_out"] = None
            row["conn_count"] = None
            return row
        delta_in = totals[0] - self._last_netstats_totals[0]
        delta_out = totals[1] - self._last_netstats_totals[1]
        self._last_netstats_totals = totals
        if delta_in < 0 or delta_out < 0:
            row["source"] = "netstats_missing"
            row["collector_status"] = "counter_reset"
            row["bytes_in"] = None
            row["bytes_out"] = None
            row["conn_count"] = None
            return row
        row["bytes_in"] = delta_in
        row["bytes_out"] = delta_out
        row["source"] = "netstats"
        row["best_effort"] = 0
        row["collector_status"] = "ok_delta"
        return row


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
    netstats_collector: NetstatsCollector,
    netstats_parser: NetstatsParser,
    debug_dir: Path | None = None,
    debug_captured: bool = False,
) -> tuple[dict[str, object], tuple[int, int] | None]:
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
        return row, None
    if use_netstats:
        uid_output = netstats_collector.collect_uid(serial, uid)
        if uid_output.timed_out:
            row["collector_status"] = "timeout"
        if uid_output.returncode == 0 and uid_output.stdout:
            sample = netstats_parser.parse_uid(uid_output.stdout, uid, ts_utc=ts)
            if sample.rx_bytes is not None and sample.tx_bytes is not None:
                row["bytes_in"] = sample.rx_bytes
                row["bytes_out"] = sample.tx_bytes
                row["conn_count"] = ""
                row["source"] = "netstats"
                row["best_effort"] = 0
                row["collector_status"] = "ok_total"
                return row, (sample.rx_bytes, sample.tx_bytes)
        detail = netstats_collector.collect_detail(serial)
        if detail.timed_out:
            row["collector_status"] = "timeout"
        if detail.returncode == 0 and detail.stdout:
            sample = netstats_parser.parse_detail(detail.stdout, uid, ts_utc=ts)
            if sample.rx_bytes is not None and sample.tx_bytes is not None:
                row["bytes_in"] = sample.rx_bytes
                row["bytes_out"] = sample.tx_bytes
                row["conn_count"] = ""
                row["source"] = "netstats"
                row["best_effort"] = 0
                row["collector_status"] = "ok_total"
                return row, (sample.rx_bytes, sample.tx_bytes)
        row["source"] = "netstats_missing"
        row["collector_status"] = row.get("collector_status") or "missing_uid_stats"
        row["best_effort"] = 0
        row["bytes_in"] = None
        row["bytes_out"] = None
        row["conn_count"] = None
        if debug_dir and not debug_captured:
            output = ""
            if detail.stdout:
                output = detail.stdout
            elif uid_output.stdout:
                output = uid_output.stdout
            if output:
                debug_path = debug_dir / f"netstats_debug_{uid}.txt"
                try:
                    netstats_parser.write_debug_capture(output, uid=uid, destination=debug_path)
                    row["collector_status"] = "debug_captured"
                except Exception:
                    row["collector_status"] = "debug_failed"
        if not allow_fallback_iface:
            row["bytes_in"] = None
            row["bytes_out"] = None
            row["conn_count"] = None
            return row, None
        if row["source"] == "netstats_missing":
            if last_netstats:
                cached_row = dict(row)
                cached_row["bytes_in"] = last_netstats.get("bytes_in", "")
                cached_row["bytes_out"] = last_netstats.get("bytes_out", "")
                cached_row["conn_count"] = last_netstats.get("conn_count", "")
                cached_row["source"] = "netstats_cached"
                cached_row["best_effort"] = 1
                cached_row["collector_status"] = "cached_after_missing"
                return cached_row, None
            return row, None
    if last_netstats:
        row["bytes_in"] = last_netstats.get("bytes_in", "")
        row["bytes_out"] = last_netstats.get("bytes_out", "")
        row["conn_count"] = last_netstats.get("conn_count", "")
        row["source"] = "netstats_cached"
        row["best_effort"] = 1
        row["collector_status"] = "cached"
        return row, None
    row["collector_status"] = "skipped"
    row["source"] = "unavailable"
    return row, None


def _sum_netstats_bytes(rows: list[dict[str, object]]) -> tuple[int, int]:
    total_in = 0
    total_out = 0
    for row in rows:
        if row.get("source") != "netstats":
            continue
        try:
            if row.get("bytes_in") is not None:
                total_in += int(float(row.get("bytes_in") or 0))
            if row.get("bytes_out") is not None:
                total_out += int(float(row.get("bytes_out") or 0))
        except (TypeError, ValueError):
            continue
    return total_in, total_out


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
        "sampling_duration_seconds": None,
        "sample_min_delta_s": None,
        "sample_avg_delta_s": None,
        "sample_max_delta_s": None,
        "sample_max_gap_s": None,
        "sample_first_gap_s": None,
        "sample_max_gap_excluding_first_s": None,
        "error": error,
    }
    elapsed = None
    if start_monotonic is not None and end_monotonic is not None:
        elapsed = max(end_monotonic - start_monotonic, 0.0)
    sampling_duration = None
    if len(monotonic_timestamps) >= 2:
        sampling_duration = max(monotonic_timestamps[-1] - monotonic_timestamps[0], 0.0)
    elif elapsed is not None:
        sampling_duration = elapsed
    if sampling_duration is not None:
        stats["sampling_duration_seconds"] = sampling_duration
        stats["expected_samples"] = int(sampling_duration / sample_rate_s) + 1
    if len(monotonic_timestamps) >= 2:
        deltas = [
            b - a for a, b in zip(monotonic_timestamps, monotonic_timestamps[1:], strict=False)
        ]
        stats["sample_min_delta_s"] = min(deltas)
        stats["sample_avg_delta_s"] = sum(deltas) / len(deltas)
        stats["sample_max_delta_s"] = max(deltas)
        stats["sample_max_gap_s"] = max(deltas)
        stats["sample_first_gap_s"] = deltas[0]
        if len(deltas) > 1:
            stats["sample_max_gap_excluding_first_s"] = max(deltas[1:])
        else:
            stats["sample_max_gap_excluding_first_s"] = deltas[0]
    return stats


__all__ = ["TelemetrySampler", "TelemetryCapture"]
