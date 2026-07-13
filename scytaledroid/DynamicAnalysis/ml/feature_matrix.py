"""Shared ML window feature matrix construction.

Freeze/profile and operational query mode must agree on the base feature
semantics. Keep the default feature set stable; add future feature variants
behind explicit mode/version changes.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from .telemetry_windowing import WindowSpec

BASIC_FEATURE_NAMES = ("bytes_per_sec", "packets_per_sec", "avg_packet_size_bytes")


def rows_to_basic_matrix(
    rows: list[dict[str, Any]],
    *,
    window_spec: WindowSpec,
    feature_log1p: bool = False,
) -> tuple[np.ndarray, list[str]]:
    """Return the locked v1 ML feature matrix.

    The input rows are PCAP window dictionaries produced by
    ``pcap_window_features.build_window_features``. The matrix uses only the
    legacy v1 traffic-shape features so existing freeze/query outputs stay
    comparable.
    """

    denom = float(window_spec.window_size_s) if window_spec.window_size_s > 0 else 1.0
    data: list[list[float]] = []

    def _f(value: Any) -> float:
        try:
            return float(value or 0.0)
        except Exception:
            return 0.0

    for row in rows:
        byte_count = _f(row.get("byte_count"))
        pkt_count = _f(row.get("packet_count"))
        avg_pkt = _f(row.get("avg_packet_size_bytes"))
        bytes_per_sec = byte_count / denom
        packets_per_sec = pkt_count / denom
        if feature_log1p:
            bytes_per_sec = float(np.log1p(bytes_per_sec))
            packets_per_sec = float(np.log1p(packets_per_sec))
        data.append([bytes_per_sec, packets_per_sec, avg_pkt])

    if not data:
        return np.zeros((0, len(BASIC_FEATURE_NAMES)), dtype=float), list(BASIC_FEATURE_NAMES)
    return np.asarray(data, dtype=float), list(BASIC_FEATURE_NAMES)


__all__ = ["BASIC_FEATURE_NAMES", "rows_to_basic_matrix"]
