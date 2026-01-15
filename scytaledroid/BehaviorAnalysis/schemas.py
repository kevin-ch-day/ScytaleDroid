"""Schema definitions and CSV helpers for behavior telemetry and outputs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Literal, Sequence


FieldType = Literal["str", "int", "float"]


@dataclass(frozen=True)
class CsvSchema:
    name: str
    headers: List[str]
    types: Dict[str, FieldType]


PROCESS_SCHEMA = CsvSchema(
    name="process",
    headers=["ts_utc", "uid", "pid", "cpu_pct", "rss_kb", "pss_kb", "threads", "proc_name", "best_effort", "collector_status"],
    types={
        "ts_utc": "str",
        "uid": "str",
        "pid": "str",
        "cpu_pct": "float",
        "rss_kb": "float",
        "pss_kb": "float",
        "threads": "int",
        "proc_name": "str",
        "best_effort": "int",
        "collector_status": "str",
    },
)

NETWORK_SCHEMA = CsvSchema(
    name="network",
    headers=["ts_utc", "uid", "bytes_in", "bytes_out", "conn_count", "source", "best_effort", "collector_status"],
    types={
        "ts_utc": "str",
        "uid": "str",
        "bytes_in": "float",
        "bytes_out": "float",
        "conn_count": "float",
        "source": "str",
        "best_effort": "int",
        "collector_status": "str",
    },
)

FEATURE_SCHEMA_HEADERS = [
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

SCORES_SCHEMA = CsvSchema(
    name="scores",
    headers=[
        "window_start_utc",
        "window_end_utc",
        "uid",
        "model_name",
        "model_backend",
        "score",
        "is_anomaly",
        "threshold",
        "score_direction",
        "marker_nearest",
        "marker_delta_s",
    ],
    types={
        "window_start_utc": "str",
        "window_end_utc": "str",
        "uid": "str",
        "model_name": "str",
        "model_backend": "str",
        "score": "float",
        "is_anomaly": "int",
        "threshold": "float",
        "score_direction": "str",
        "marker_nearest": "str",
        "marker_delta_s": "float",
    },
)


def validate_row(schema: CsvSchema, row: Dict[str, object], *, strict: bool = False) -> Dict[str, object]:
    cleaned: Dict[str, object] = {}
    for key in schema.headers:
        value = row.get(key, "")
        expected = schema.types.get(key, "str")
        if value is None or value == "":
            cleaned[key] = ""
            continue
        try:
            if expected == "int":
                cleaned[key] = int(value)
            elif expected == "float":
                cleaned[key] = float(value)
            else:
                cleaned[key] = str(value)
        except Exception:
            cleaned[key] = "" if not strict else None  # None will be handled by caller for strict mode
    return cleaned
