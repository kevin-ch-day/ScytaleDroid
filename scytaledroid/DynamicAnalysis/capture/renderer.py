"""Pure renderer for the Phase A live capture console."""

from __future__ import annotations

from scytaledroid.DynamicAnalysis.capture.state import CaptureState

_CONTROLS_LINE = (
    "Enter = stop & finalize | A = abort & discard | R = relaunch target | "
    "Ctrl+C = emergency abort"
)
_VALUE_WIDTH = 64
_LATEST_WIDTH = 64
_SUPPRESSED_STATUS_MESSAGES = {
    "Waiting for capture state updates.",
    "Target app is in foreground; valid timing active.",
    "Target reached. Keep collecting if needed; press Enter when finished.",
}


def _format_duration(seconds: float | int | None) -> str:
    total = max(int(seconds or 0), 0)
    mins, secs = divmod(total, 60)
    hours, mins = divmod(mins, 60)
    if hours > 0:
        return f"{hours:02d}:{mins:02d}:{secs:02d}"
    return f"{mins:02d}:{secs:02d}"


def _format_valid_time(state: CaptureState) -> str:
    valid = _format_duration(state.valid_elapsed_s)
    minimum = _format_duration(state.minimum_duration_s)
    target = _format_duration(state.target_duration_s)
    return f"{valid} / {minimum} minimum | {target} target"


def _format_ratio(numerator: float | int, denominator: float | int | None) -> str:
    denom = max(int(denominator or 0), 0)
    if denom <= 0:
        return "n/a"
    pct = min(max(int((float(numerator or 0) / float(denom)) * 100), 0), 999)
    return f"{pct}%"


def _format_pcap_bytes(value: int | None, *, pcapdroid_status: str = "unknown") -> str:
    if not isinstance(value, int):
        if str(pcapdroid_status or "").strip().lower() == "running":
            return "pending"
        return "unknown"
    units = ["B", "KB", "MB", "GB"]
    amount = float(max(value, 0))
    unit = units[0]
    for candidate in units:
        unit = candidate
        if amount < 1024.0 or candidate == units[-1]:
            break
        amount /= 1024.0
    if unit == "B":
        return f"{int(amount)} {unit}"
    return f"{amount:.1f} {unit}"


def _status_detail(state: CaptureState) -> str:
    status_name = str(state.status.value or "").strip()
    return {
        "WAIT_TARGET_FOREGROUND": "waiting for target foreground",
        "RUNNING_VALID": "valid timing active",
        "PAUSED_FOREGROUND_DRIFT": "foreground drift paused",
        "STOPPING_FINALIZE": "finalizing capture",
        "ABORTING_DISCARD": "aborting and discarding",
        "FINALIZED": "capture finalized",
    }.get(status_name, status_name.lower() or "unknown")


def _drift_summary(state: CaptureState) -> str:
    if int(state.drift_count or 0) <= 0:
        return "none"
    event_label = "event" if int(state.drift_count) == 1 else "events"
    return f"{int(state.drift_count)} {event_label}"


def _truncate(text: object, *, width: int) -> str:
    value = str(text or "").strip()
    if width <= 0 or len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return f"{value[: width - 3]}..."


def _status_message_line(state: CaptureState) -> tuple[str, str] | None:
    warning = str(state.latest_warning or "").strip()
    if warning:
        if warning in _SUPPRESSED_STATUS_MESSAGES:
            return None
        return ("Warning", warning)
    event = str(state.latest_event or "").strip()
    if not event or event in _SUPPRESSED_STATUS_MESSAGES:
        return None
    event_lc = event.lower()
    if "checkpoint:" in event_lc or "prompt:" in event_lc:
        return ("Guidance", event)
    if event_lc.startswith("waiting for ") or event_lc.startswith("returning "):
        return ("State", event)
    return ("Latest", event)


def _format_surface(state: CaptureState) -> str:
    label = str(state.foreground_surface_label or "").strip()
    detail = str(state.foreground_surface_detail or "").strip()
    if not label:
        return "unknown"
    if not detail:
        return label
    return f"{label} - {detail}"


def render_capture_dashboard(state: CaptureState) -> str:
    pcap_bytes = state.observer_status.pcap_bytes
    pcap_display = _format_pcap_bytes(
        pcap_bytes,
        pcapdroid_status=state.observer_status.pcapdroid,
    )
    pcap_raw = f"{int(pcap_bytes)} bytes" if isinstance(pcap_bytes, int) else None
    min_progress = _format_ratio(state.valid_elapsed_s, state.minimum_duration_s)
    target_progress = _format_ratio(state.valid_elapsed_s, state.target_duration_s)
    pcap_line = pcap_display if pcap_raw is None else f"{pcap_display} ({pcap_raw})"
    status_message = _status_message_line(state)
    lines = [
        "ScytaleDroid Live Capture",
        "=========================",
        f"App        : {_truncate(state.app_name, width=_VALUE_WIDTH)}",
        f"Package    : {_truncate(state.package_name, width=_VALUE_WIDTH)}",
        f"Phase      : {_truncate(state.phase, width=_VALUE_WIDTH)}",
        f"Build      : {_truncate(state.version_code or 'unknown', width=_VALUE_WIDTH)}",
        f"Status     : {_truncate(f'{state.status.value} ({_status_detail(state)})', width=_VALUE_WIDTH)}",
        "",
        f"Foreground : {_truncate(state.foreground_package or 'unknown', width=_VALUE_WIDTH)}",
        f"Activity   : {_truncate(state.foreground_component or 'unknown', width=_VALUE_WIDTH)}",
        f"Surface    : {_truncate(_format_surface(state), width=_VALUE_WIDTH)}",
        f"Expected   : {_truncate(state.expected_package or 'unknown', width=_VALUE_WIDTH)}",
        f"Timing     : {_truncate(f'wall {_format_duration(state.wall_elapsed_s)} | valid {_format_duration(state.valid_elapsed_s)}', width=_VALUE_WIDTH)}",
        f"Goal       : {_truncate(_format_valid_time(state), width=_VALUE_WIDTH)}",
        f"Progress   : {_truncate(f'minimum {min_progress} | target {target_progress}', width=_VALUE_WIDTH)}",
        f"Drift      : {_truncate(_drift_summary(state), width=_VALUE_WIDTH)}",
        f"PCAP       : {_truncate(pcap_line, width=_VALUE_WIDTH)}",
        (
            "Observers  : "
            f"{_truncate(f'PCAPdroid {state.observer_status.pcapdroid} | logcat {state.observer_status.logcat}', width=_VALUE_WIDTH)}"
        ),
    ]
    if status_message is not None:
        label, text = status_message
        lines.append(f"{label:<11}: {_truncate(text, width=_LATEST_WIDTH)}")
    lines.extend(
        [
            "",
            f"Controls   : {_truncate(_CONTROLS_LINE, width=_LATEST_WIDTH)}",
        ]
    )
    return "\n".join(lines)


__all__ = ["render_capture_dashboard"]
