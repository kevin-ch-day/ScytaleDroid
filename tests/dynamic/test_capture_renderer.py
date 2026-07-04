from __future__ import annotations

from scytaledroid.DynamicAnalysis.capture.renderer import render_capture_dashboard
from scytaledroid.DynamicAnalysis.capture.state import CaptureState, CaptureStatus, ObserverStatus


def test_render_capture_dashboard_is_deterministic() -> None:
    state = CaptureState(
        app_name="WhatsApp",
        package_name="com.whatsapp",
        expected_package="com.whatsapp",
        version_code="262508000",
        phase="Baseline connected-idle",
        status=CaptureStatus.PAUSED_FOREGROUND_DRIFT,
        wall_started_at=0.0,
        wall_elapsed_s=42.0,
        valid_elapsed_s=0.0,
        foreground_package="com.emanuelef.remote_capture",
        latest_warning="Foreground drift active; return to WhatsApp.",
        observer_status=ObserverStatus(pcapdroid="running", logcat="running", pcap_bytes=18420),
        target_duration_s=240,
        minimum_duration_s=180,
    )

    first = render_capture_dashboard(state)
    second = render_capture_dashboard(state)

    assert first == second
    assert "ScytaleDroid Live Capture" in first
    assert "WhatsApp" in first
    assert "com.emanuelef.remote_capture" in first
    assert "PCAP bytes : 18420" in first
