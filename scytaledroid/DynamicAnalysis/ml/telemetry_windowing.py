"""Windowing utilities for deterministic per-window outputs (Paper #2)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WindowSpec:
    window_size_s: float
    stride_s: float


def iter_windows(duration_s: float, spec: WindowSpec) -> tuple[list[tuple[float, float]], int]:
    """Return all full windows and count of dropped partial windows.

    Windows are [start, end) and are dropped if end > duration_s.
    """
    if duration_s <= 0 or spec.window_size_s <= 0 or spec.stride_s <= 0:
        return [], 0
    windows: list[tuple[float, float]] = []
    t = 0.0
    while True:
        end = t + spec.window_size_s
        if end > duration_s + 1e-9:
            break
        windows.append((t, end))
        t += spec.stride_s
    # Count partial windows that would have started but did not fit.
    dropped = 0
    if windows:
        last_start = windows[-1][0] + spec.stride_s
    else:
        last_start = 0.0
    if last_start < duration_s:
        # Compute theoretical count of starts from last_start to duration
        # that would not fit a full window.
        t = last_start
        while t < duration_s:
            if t + spec.window_size_s > duration_s + 1e-9:
                dropped += 1
            t += spec.stride_s
    return windows, dropped

