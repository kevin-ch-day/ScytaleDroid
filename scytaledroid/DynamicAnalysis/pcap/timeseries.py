"""PCAP time-series scanning helpers (streaming, metadata-only).

These helpers are shared across:
- analysis/pcap_features.json enrichment (per-run summaries)
- derived DB indexing from evidence packs (optional accelerator)

Contract/safety:
- Uses tshark field extraction only; no payload inspection.
- Deterministic computations (discrete percentiles over 0-filled seconds; includes 0-activity seconds).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


def percentile(sorted_values: list[float], p: float) -> float | None:
    if not sorted_values:
        return None
    if p <= 0:
        return float(sorted_values[0])
    if p >= 100:
        return float(sorted_values[-1])
    # Deterministic discrete percentile:
    # index = floor(p/100 * (n-1)) over a sorted series.
    k = int((p / 100.0) * (len(sorted_values) - 1))
    k = max(0, min(k, len(sorted_values) - 1))
    return float(sorted_values[k])


def scan_pcap_timeseries_and_destinations(pcap_path: Path, *, tshark_path: str | None = None) -> dict[str, Any]:
    """Scan PCAP with tshark fields output (streaming) and compute summary stats.

    Returns:
      - bytes_per_second_{p50,p95,max}
      - packets_per_second_{p50,p95,max}
      - burstiness_{bytes,packets}_p95_over_p50
      - unique_dst_ip_count
      - unique_dst_port_count
    """
    tp = tshark_path or shutil.which("tshark")
    if not tp:
        raise RuntimeError("tshark_missing")
    if not pcap_path.exists():
        raise RuntimeError("pcap_missing")

    cmd = [
        tp,
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "frame.time_relative",
        "-e",
        "frame.len",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.dstport",
    ]

    bytes_by_s: dict[int, int] = {}
    pkts_by_s: dict[int, int] = {}
    uniq_ip: set[str] = set()
    uniq_port: set[int] = set()
    max_sec = 0

    # tshark can be verbose on stderr for malformed captures; discard stderr in
    # this streaming path to avoid deadlocks. We only need deterministic stats.
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            t_s = parts[0].strip()
            l_s = parts[1].strip()
            if not t_s or not l_s:
                continue
            try:
                t = float(t_s)
                ln = int(l_s)
            except Exception:
                continue
            sec = int(t) if t >= 0 else 0
            max_sec = max(max_sec, sec)
            bytes_by_s[sec] = bytes_by_s.get(sec, 0) + max(ln, 0)
            pkts_by_s[sec] = pkts_by_s.get(sec, 0) + 1

            if len(parts) >= 3:
                ip = parts[2].strip()
                if ip:
                    uniq_ip.add(ip)

            tcp_p = parts[3].strip() if len(parts) >= 4 else ""
            udp_p = parts[4].strip() if len(parts) >= 5 else ""
            port = tcp_p or udp_p
            if port:
                try:
                    pi = int(port)
                    if 0 <= pi <= 65535:
                        uniq_port.add(pi)
                except Exception:
                    pass
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
    timeout_s = _resolve_tshark_timeout_s()
    try:
        rc = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired as err:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            rc = proc.wait(timeout=10)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                rc = proc.wait(timeout=5)
            except Exception:
                rc = -1
        raise RuntimeError("tshark_timeout") from err
    if rc != 0:
        raise RuntimeError("tshark_failed")

    # Include seconds with 0 activity so percentiles reflect burstiness.
    bytes_series = [float(bytes_by_s.get(i, 0)) for i in range(max_sec + 1)]
    pkts_series = [float(pkts_by_s.get(i, 0)) for i in range(max_sec + 1)]
    bytes_sorted = sorted(bytes_series)
    pkts_sorted = sorted(pkts_series)

    b50 = percentile(bytes_sorted, 50)
    b95 = percentile(bytes_sorted, 95)
    p50 = percentile(pkts_sorted, 50)
    p95 = percentile(pkts_sorted, 95)
    bmax = float(bytes_sorted[-1]) if bytes_sorted else None
    pmax = float(pkts_sorted[-1]) if pkts_sorted else None

    burst_b = (float(b95) / float(b50)) if b50 and b95 is not None and b50 > 0 else None
    burst_p = (float(p95) / float(p50)) if p50 and p95 is not None and p50 > 0 else None

    return {
        "bytes_per_second_p50": b50,
        "bytes_per_second_p95": b95,
        "bytes_per_second_max": bmax,
        "packets_per_second_p50": p50,
        "packets_per_second_p95": p95,
        "packets_per_second_max": pmax,
        "burstiness_bytes_p95_over_p50": burst_b,
        "burstiness_packets_p95_over_p50": burst_p,
        "unique_dst_ip_count": len(uniq_ip) if uniq_ip else 0,
        "unique_dst_port_count": len(uniq_port) if uniq_port else 0,
    }


def _resolve_tshark_timeout_s() -> float:
    raw = os.getenv("SCYTALEDROID_TSHARK_TIMEOUT_S", "120").strip()
    try:
        return max(5.0, float(raw))
    except ValueError:
        return 120.0


__all__ = ["scan_pcap_timeseries_and_destinations", "percentile"]
