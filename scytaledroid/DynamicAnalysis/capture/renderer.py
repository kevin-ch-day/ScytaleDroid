"""Pure renderer for the Phase A live capture console."""

from __future__ import annotations

from scytaledroid.DynamicAnalysis.capture.state import CaptureState

_CONTROLS_LINE = (
    "Enter = stop & finalize | A = abort & discard | R = relaunch target | "
    "Ctrl+C = emergency abort"
)


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


def render_capture_dashboard(state: CaptureState) -> str:
    latest = state.latest_warning or state.latest_event or "Waiting for capture state updates."
    pcap_bytes = state.observer_status.pcap_bytes
    pcap_display = f"{int(pcap_bytes)}" if isinstance(pcap_bytes, int) else "unknown"
    lines = [
        "ScytaleDroid Live Capture",
        f"App        : {state.app_name}",
        f"Package    : {state.package_name}",
        f"Phase      : {state.phase}",
        f"Build      : {state.version_code or 'unknown'}",
        f"Status     : {state.status.value}",
        "",
        f"Foreground : {state.foreground_package or 'unknown'}",
        f"Expected   : {state.expected_package or 'unknown'}",
        f"Wall time  : {_format_duration(state.wall_elapsed_s)}",
        f"Valid time : {_format_valid_time(state)}",
        f"PCAP bytes : {pcap_display}",
        (
            "Observers  : "
            f"PCAPdroid={state.observer_status.pcapdroid} | "
            f"logcat={state.observer_status.logcat}"
        ),
        f"Latest     : {latest}",
        "",
        f"Controls   : {_CONTROLS_LINE}",
    ]
    return "\n".join(lines)


__all__ = ["render_capture_dashboard"]
