"""State model for the Phase A live capture console."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CaptureStatus(str, Enum):
    WAIT_TARGET_FOREGROUND = "WAIT_TARGET_FOREGROUND"
    RUNNING_VALID = "RUNNING_VALID"
    PAUSED_FOREGROUND_DRIFT = "PAUSED_FOREGROUND_DRIFT"
    STOPPING_FINALIZE = "STOPPING_FINALIZE"
    ABORTING_DISCARD = "ABORTING_DISCARD"
    FINALIZED = "FINALIZED"


class CaptureAction(str, Enum):
    FINALIZE = "finalize"
    ABORT = "abort"


@dataclass
class ObserverStatus:
    pcapdroid: str = "unknown"
    logcat: str = "unknown"
    pcap_bytes: int | None = None


@dataclass
class CaptureState:
    app_name: str
    package_name: str
    expected_package: str
    version_code: str | None
    phase: str
    status: CaptureStatus = CaptureStatus.WAIT_TARGET_FOREGROUND
    wall_started_at: float = 0.0
    wall_elapsed_s: float = 0.0
    valid_elapsed_s: float = 0.0
    foreground_package: str | None = None
    foreground_component: str | None = None
    latest_event: str = ""
    latest_warning: str = ""
    observer_status: ObserverStatus = field(default_factory=ObserverStatus)
    finalize_requested: bool = False
    abort_requested: bool = False
    relaunch_requested: bool = False
    drift_seen: bool = False
    drift_count: int = 0
    target_duration_s: int | None = None
    minimum_duration_s: int | None = None
    valid_timing_started: bool = False
    last_tick_at: float | None = None


@dataclass(frozen=True)
class CaptureConsoleResult:
    action: CaptureAction
    ended_at_monotonic: float
    state: CaptureState


__all__ = [
    "CaptureAction",
    "CaptureConsoleResult",
    "CaptureState",
    "CaptureStatus",
    "ObserverStatus",
]
