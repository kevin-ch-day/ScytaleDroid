"""Feature windowing and CSV writer."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Sequence

FEATURE_HEADERS = [
    "window_start_utc",
    "window_end_utc",
    "uid",
    "cpu_pct_mean",
    "cpu_pct_std",
    "rss_kb_mean",
    "rss_kb_std",
    "bytes_in_rate",
    "bytes_out_rate",
    "conn_count_mean",
    "conn_count_max",
    "threads_mean",
    "threads_max",
    "cpu_slope",
    "rss_slope",
    "net_burstiness",
    "marker_nearest",
    "marker_delta_s",
]


def build_windows(
    process_rows: Sequence[Dict[str, object]],
    network_rows: Sequence[Dict[str, object]],
    markers: Sequence[Dict[str, object]] | None,
    *,
    window_length: float,
    window_step: float,
) -> List[Dict[str, object]]:
    windows: List[Dict[str, object]] = []
    if not process_rows:
        return windows
    # assume process_rows sorted by ts
    timestamps = [parse_ts(row["ts_utc"]) for row in process_rows if row.get("ts_utc")]
    if not timestamps:
        return windows
    start = min(timestamps)
    end = max(timestamps)
    current = start
    while current <= end:
        w_start = current
        w_end = w_start + timedelta_seconds(window_length)
        proc_slice = [row for row in process_rows if w_start <= parse_ts(row["ts_utc"]) <= w_end]
        net_slice = [row for row in network_rows if w_start <= parse_ts(row["ts_utc"]) <= w_end]
        windows.append(_window_features(w_start, w_end, proc_slice, net_slice, markers or []))
        current = current + timedelta_seconds(window_step)
    return windows


def _window_features(
    w_start: datetime,
    w_end: datetime,
    proc_rows: Sequence[Dict[str, object]],
    net_rows: Sequence[Dict[str, object]],
    markers: Sequence[Dict[str, object]],
) -> Dict[str, object]:
    def vals(key: str, rows: Sequence[Dict[str, object]]) -> List[float]:
        out: List[float] = []
        for row in rows:
            val = row.get(key)
            try:
                out.append(float(val))
            except Exception:
                continue
        return out

    cpu_vals = vals("cpu_pct", proc_rows)
    rss_vals = vals("rss_kb", proc_rows)
    bytes_in_vals = vals("bytes_in", net_rows)
    bytes_out_vals = vals("bytes_out", net_rows)
    conn_vals = vals("conn_count", net_rows)
    threads_vals = vals("threads", proc_rows)

    features: Dict[str, object] = {
        "window_start_utc": w_start.isoformat(),
        "window_end_utc": w_end.isoformat(),
        "uid": proc_rows[0].get("uid") if proc_rows else "",
        "cpu_pct_mean": mean(cpu_vals),
        "cpu_pct_std": std(cpu_vals),
        "rss_kb_mean": mean(rss_vals),
        "rss_kb_std": std(rss_vals),
        "bytes_in_rate": rate(bytes_in_vals, w_start, w_end),
        "bytes_out_rate": rate(bytes_out_vals, w_start, w_end),
        "conn_count_mean": mean(conn_vals),
        "conn_count_max": max(conn_vals) if conn_vals else "",
        "threads_mean": mean(threads_vals),
        "threads_max": max(threads_vals) if threads_vals else "",
        "cpu_slope": slope(cpu_vals),
        "rss_slope": slope(rss_vals),
        "net_burstiness": burstiness(bytes_in_vals + bytes_out_vals),
        "marker_nearest": "",
        "marker_delta_s": "",
    }
    if markers:
        features["marker_nearest"], features["marker_delta_s"] = nearest_marker(markers, w_start, w_end)
    return features


def mean(values: List[float]) -> object:
    if not values:
        return ""
    return round(sum(values) / len(values), 4)


def std(values: List[float]) -> object:
    if not values or len(values) < 2:
        return ""
    m = sum(values) / len(values)
    var = sum((v - m) ** 2 for v in values) / (len(values) - 1)
    return round(var**0.5, 4)


def slope(values: List[float]) -> object:
    if not values or len(values) < 2:
        return ""
    return round(values[-1] - values[0], 4)


def burstiness(values: List[float]) -> object:
    if not values:
        return ""
    m = mean(values)
    if not m:
        return ""
    s = std(values)
    if not s:
        return ""
    try:
        return round(s / float(m), 4)
    except Exception:
        return ""


def rate(values: List[float], start: datetime, end: datetime) -> object:
    if not values:
        return ""
    dt = (end - start).total_seconds()
    if dt <= 0:
        return ""
    return round((values[-1] - values[0]) / dt, 4) if len(values) > 1 else round(values[-1] / dt, 4)


def parse_ts(ts: object) -> datetime:
    if isinstance(ts, datetime):
        return ts
    return datetime.fromisoformat(str(ts))


def nearest_marker(markers: Sequence[Dict[str, object]], start: datetime, end: datetime) -> tuple[str, object]:
    nearest_label = ""
    nearest_delta = ""
    mid = start + timedelta(seconds=(end - start).total_seconds() / 2.0)
    best = None
    for marker in markers:
        ts = marker.get("ts_utc")
        label = marker.get("label", "")
        try:
            m_ts = datetime.fromisoformat(str(ts))
        except Exception:
            continue
        delta = abs((m_ts - mid).total_seconds())
        if best is None or delta < best:
            best = delta
            nearest_label = str(label)
            nearest_delta = round(delta, 3)
    return nearest_label, nearest_delta


def timedelta_seconds(seconds: float):
    from datetime import timedelta

    return timedelta(seconds=seconds)


def write_features_csv(path, windows: List[Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(",".join(FEATURE_HEADERS) + "\n")
        for row in windows:
            values = []
            for key in FEATURE_HEADERS:
                val = row.get(key, "")
                values.append(str(val))
            handle.write(",".join(values) + "\n")
