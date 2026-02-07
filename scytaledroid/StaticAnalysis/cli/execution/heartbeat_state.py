"""Shared heartbeat state for batch static runs.

Batch static runs redirect stdout/stderr for the scan itself to keep console output
quiet and deterministic. Heartbeats are printed from a separate thread, and they
need a low-cost way to answer: "what is it doing right now?"

This module exposes a single process-local state updated by the scan pipeline and
read by the batch heartbeat thread.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class HeartbeatState:
    app_label: str | None = None
    stage: str | None = None
    done: int | None = None
    total: int | None = None
    stage_index: int | None = None
    stage_total: int | None = None
    updated_at_mono: float = 0.0


_LOCK = threading.Lock()
_STATE = HeartbeatState()


def set_app(label: str, *, total: int | None = None) -> None:
    now = time.monotonic()
    with _LOCK:
        _STATE.app_label = label
        _STATE.total = int(total) if isinstance(total, int) else total
        _STATE.done = 0
        _STATE.stage = "starting"
        _STATE.stage_index = None
        _STATE.stage_total = None
        _STATE.updated_at_mono = now


def set_stage(
    stage: str,
    *,
    done: int | None = None,
    total: int | None = None,
    stage_index: int | None = None,
    stage_total: int | None = None,
) -> None:
    now = time.monotonic()
    with _LOCK:
        _STATE.stage = stage
        if done is not None:
            try:
                _STATE.done = int(done)
            except Exception:
                pass
        if total is not None:
            try:
                _STATE.total = int(total)
            except Exception:
                pass
        if stage_index is not None:
            try:
                _STATE.stage_index = int(stage_index)
            except Exception:
                pass
        if stage_total is not None:
            try:
                _STATE.stage_total = int(stage_total)
            except Exception:
                pass
        _STATE.updated_at_mono = now


def snapshot() -> dict[str, object]:
    with _LOCK:
        return {
            "app_label": _STATE.app_label,
            "stage": _STATE.stage,
            "done": _STATE.done,
            "total": _STATE.total,
            "stage_index": _STATE.stage_index,
            "stage_total": _STATE.stage_total,
            "age_s": max(0.0, time.monotonic() - (_STATE.updated_at_mono or 0.0)),
        }


__all__ = ["set_app", "set_stage", "snapshot"]
