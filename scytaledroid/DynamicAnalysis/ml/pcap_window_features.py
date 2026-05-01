"""Per-window feature extraction from canonical PCAP (offline, deterministic)."""

from __future__ import annotations

import csv
import subprocess
import tempfile
from bisect import bisect_right
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .telemetry_windowing import WindowSpec, iter_windows


@dataclass(frozen=True)
class PacketRecord:
    t: float  # seconds from capture start (tshark frame.time_relative)
    length: int  # frame length in bytes


def extract_packet_timeline(pcap_path: Path) -> Iterable[PacketRecord]:
    """Stream packet timeline from tshark.

    Uses fields:
    - frame.time_relative
    - frame.len
    """
    # NOTE: Use tshark via PATH. Dataset-tier runs already gate missing tools.
    cmd = [
        "tshark",
        "-n",  # never resolve names; deterministic and avoids slow DNS lookups
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "separator=,",
        "-e",
        "frame.time_relative",
        "-e",
        "frame.len",
    ]
    # Avoid deadlocks if tshark emits lots of warnings to stderr. We direct stderr to a
    # temp file, then check returncode and include a tail snippet on failure.
    err = tempfile.TemporaryFile(mode="w+b")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err, text=True)
    assert proc.stdout is not None
    rc: int | None = None
    err_tail: str = ""
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",", 1)
            if len(parts) != 2:
                continue
            try:
                t = float(parts[0])
                length = int(float(parts[1]))
            except Exception:
                continue
            if t < 0 or length < 0:
                continue
            yield PacketRecord(t=t, length=length)
    finally:
        # Ensure process exits; ignore stderr unless we need it later.
        try:
            proc.stdout.close()  # type: ignore[union-attr]
        except Exception:
            pass
        try:
            proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            # tshark can take a while to shut down after stdout is closed on large PCAPs.
            # Terminate to avoid noisy \"Exception ignored\" warnings at interpreter exit.
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=10)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
        try:
            rc = proc.returncode
            if rc is None:
                rc = -1
            # Best-effort error tail (avoid reading huge stderr into memory).
            err.seek(0, 2)
            size = err.tell()
            err.seek(max(0, size - 4096), 0)
            err_tail = err.read().decode("utf-8", errors="replace").strip()
            err.close()
        except Exception:
            pass

    # Only reached if the generator was exhausted naturally (not closed early).
    if rc is not None and rc != 0:
        raise RuntimeError(f"tshark failed (rc={rc}) for PCAP: {pcap_path} ({err_tail})")


def build_window_features(
    packets: Iterable[PacketRecord],
    *,
    duration_s: float,
    spec: WindowSpec,
) -> tuple[list[dict[str, Any]], int]:
    """Aggregate packet timeline into fixed windows.

    Returns (rows, dropped_partial_windows).
    Each row contains:
    - window_start_s, window_end_s
    - packet_count
    - byte_count
    - avg_packet_size_bytes
    """
    windows, dropped = iter_windows(duration_s, spec)
    if not windows:
        return [], dropped
    # Initialize bins
    counts = [0 for _ in windows]
    bytes_ = [0 for _ in windows]

    # Assignment for overlapping windows: a packet can contribute to multiple
    # windows when stride < window_size.
    starts = [w[0] for w in windows]
    ends = [w[1] for w in windows]
    for pkt in packets:
        # first index where end > t (discard windows ending at/before t)
        lo = bisect_right(ends, pkt.t)
        # last index where start <= t
        hi = bisect_right(starts, pkt.t) - 1
        if lo > hi:
            continue
        for j in range(max(0, lo), min(len(windows) - 1, hi) + 1):
            # Defensive bounds check for floating-point edges.
            start, end = windows[j]
            if pkt.t < start or pkt.t >= end:
                continue
            counts[j] += 1
            bytes_[j] += int(pkt.length)

    rows: list[dict[str, Any]] = []
    for (start, end), c, b in zip(windows, counts, bytes_, strict=True):
        avg = (float(b) / float(c)) if c > 0 else 0.0
        rows.append(
            {
                "window_start_s": float(start),
                "window_end_s": float(end),
                "packet_count": int(c),
                "byte_count": int(b),
                "avg_packet_size_bytes": float(avg),
            }
        )
    return rows, dropped


def write_anomaly_scores_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        # Still write a header-only file for auditability.
        fieldnames = ["window_start_s", "window_end_s", "score", "threshold", "is_anomalous"]
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
        return
    fieldnames = ["window_start_s", "window_end_s", "score", "threshold", "is_anomalous"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in fieldnames})
