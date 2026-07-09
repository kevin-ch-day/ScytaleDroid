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
    assert "=========================" in first
    assert "WhatsApp" in first
    assert "com.emanuelef.remote_capture" in first
    assert "Activity   : unknown" in first
    assert "Surface    : unknown" in first
    assert "PAUSED_FOREGROUND_DRIFT (foreground drift paused)" in first
    assert "Timing     : wall 00:42 | valid 00:00" in first
    assert "Goal       : 00:00 / 03:00 minimum | 04:00 target" in first
    assert "Progress   : minimum 0% | target 0%" in first
    assert "Drift      : none" in first
    assert "PCAP       : 18.0 KB (18420 bytes)" in first
    assert "Warning    : Foreground drift active; return to WhatsApp." in first
    assert "A = discard run (not countable)" in first


def test_render_capture_dashboard_truncates_long_status_fields() -> None:
    state = CaptureState(
        app_name="WhatsApp",
        package_name="com.whatsapp",
        expected_package="com.whatsapp",
        version_code="262508000",
        phase="Baseline connected-idle with a very long prompt string that should not wrap across the whole terminal window",
        status=CaptureStatus.RUNNING_VALID,
        wall_started_at=0.0,
        wall_elapsed_s=42.0,
        valid_elapsed_s=42.0,
        foreground_package="com.whatsapp",
        foreground_component="com.whatsapp.calling.ui.VoipActivityV2",
        latest_event=(
            "Baseline-connected prompt: perform the single refresh/check action now, "
            "then return to thread and hold foreground while the capture remains valid."
        ),
        observer_status=ObserverStatus(pcapdroid="running", logcat="running", pcap_bytes=None),
        target_duration_s=240,
        minimum_duration_s=180,
    )

    rendered = render_capture_dashboard(state)

    assert "Phase      : Baseline connected-idle with a very long prompt string" in rendered
    assert "while the capture remains valid." not in rendered
    assert "Guidance   : Baseline-connected prompt: perform the single refresh/check a..." in rendered
    assert "PCAP       : pending" in rendered
    assert "PCAP       : unknown (unknown)" not in rendered


def test_render_capture_dashboard_shows_surface_label() -> None:
    state = CaptureState(
        app_name="Guardian",
        package_name="com.guardian",
        expected_package="com.guardian",
        version_code="23011",
        phase="Manual interactive",
        status=CaptureStatus.RUNNING_VALID,
        wall_started_at=0.0,
        wall_elapsed_s=105.0,
        valid_elapsed_s=105.0,
        foreground_package="com.guardian",
        foreground_component="com.guardian.feature.stream.HomeActivity",
        foreground_surface_label="my_guardian",
        foreground_surface_detail="personalized guardian lane",
        latest_event="Foreground surface changed to my_guardian.",
        observer_status=ObserverStatus(pcapdroid="running", logcat="running", pcap_bytes=98304),
        target_duration_s=240,
        minimum_duration_s=180,
    )

    rendered = render_capture_dashboard(state)

    assert "Surface    : my_guardian - personalized guardian lane" in rendered


def test_render_capture_dashboard_suppresses_generic_target_reached_message() -> None:
    state = CaptureState(
        app_name="Instagram",
        package_name="com.instagram.android",
        expected_package="com.instagram.android",
        version_code="384209456",
        phase="Baseline idle",
        status=CaptureStatus.RUNNING_VALID,
        wall_started_at=0.0,
        wall_elapsed_s=258.0,
        valid_elapsed_s=258.0,
        foreground_package="com.instagram.android",
        latest_event="Target reached. Keep collecting if needed; press Enter when finished.",
        observer_status=ObserverStatus(pcapdroid="running", logcat="running", pcap_bytes=None),
        target_duration_s=240,
        minimum_duration_s=180,
    )

    rendered = render_capture_dashboard(state)

    assert "Target reached. Keep collecting if needed; press Enter when finished." not in rendered
    assert "Latest     :" not in rendered
    assert "Guidance   :" not in rendered
    assert "Warning    :" not in rendered
    assert "Controls   :" in rendered
    assert "A = discard run (not countable)" in rendered
