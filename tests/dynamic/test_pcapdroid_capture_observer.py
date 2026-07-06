from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.observers.pcapdroid_capture import (
    PcapdroidCaptureObserver,
    _effective_min_pcap_bytes,
    estimate_device_capture_size_bytes,
    _pull_with_retries,
)
from scytaledroid.DynamicAnalysis.pcap.naming import make_pcap_capture_name


def _ctx(tmp_path: Path) -> RunContext:
    run_dir = tmp_path / "run"
    return RunContext(
        dynamic_run_id="run-1",
        package_name="com.example.app",
        duration_seconds=180,
        scenario_id="basic_usage",
        run_dir=run_dir,
        artifacts_dir=run_dir / "artifacts",
        analysis_dir=run_dir / "analysis",
        notes_dir=run_dir / "notes",
        interactive=True,
        run_profile="baseline_idle",
        device_serial="SERIAL123",
    )


def test_effective_min_pcap_bytes_uses_connected_floor_for_manual_messaging_text(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    ctx = RunContext(
        dynamic_run_id="run-1",
        package_name="com.whatsapp",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=run_dir,
        artifacts_dir=run_dir / "artifacts",
        analysis_dir=run_dir / "analysis",
        notes_dir=run_dir / "notes",
        interactive=True,
        run_profile="interaction_manual",
        messaging_activity="text_only",
        device_serial="SERIAL123",
    )

    assert _effective_min_pcap_bytes(ctx) == 10_000


def test_effective_min_pcap_bytes_keeps_strict_floor_for_manual_messaging_call(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    ctx = RunContext(
        dynamic_run_id="run-1",
        package_name="com.whatsapp",
        duration_seconds=240,
        scenario_id="basic_usage",
        run_dir=run_dir,
        artifacts_dir=run_dir / "artifacts",
        analysis_dir=run_dir / "analysis",
        notes_dir=run_dir / "notes",
        interactive=True,
        run_profile="interaction_manual",
        messaging_activity="voice_call",
        device_serial="SERIAL123",
    )

    assert _effective_min_pcap_bytes(ctx) == 50_000


def test_start_clears_status_error_when_fallback_probe_confirms_capture(
    monkeypatch, tmp_path: Path
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture.adb_client.is_available",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._pcapdroid_installed",
        lambda _serial: True,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture.adb_shell.run_shell",
        lambda _serial, _args: "",
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._pcapdroid_status_ok",
        lambda _serial, _api_key: (None, "PCAPdroid status unavailable"),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._peek_latest_pcapdroid",
        lambda _serial, min_epoch=None: {"latest_path": None, "latest_mtime": None},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._poll_latest_pcapdroid",
        lambda _serial, min_epoch=None, timeout_s=2.0: {
            "latest_path": "/sdcard/Download/PCAPdroid/scytaledroid_run-1.pcap",
            "latest_mtime": 1_717_000_000.0,
        },
    )

    handle = PcapdroidCaptureObserver().start(ctx)

    assert handle.payload is not None
    meta_path = Path(handle.payload["meta_path"])
    payload = json.loads(meta_path.read_text(encoding="utf-8"))
    assert payload["pcap_name"] == make_pcap_capture_name("com.example.app", "run-1")
    assert payload["package_name"] == "com.example.app"
    assert payload["package_slug"] == "com_example_app"
    assert payload["status_check"] == {
        "ok": True,
        "error": None,
        "source": "fallback_probe",
    }


def test_estimate_device_capture_size_bytes_uses_deterministic_capture_name(monkeypatch) -> None:
    seen: list[tuple[str, str]] = []

    def _fake_size(serial: str, path: str) -> int:
        seen.append((serial, path))
        return 54321

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._device_file_size",
        _fake_size,
    )

    size = estimate_device_capture_size_bytes(
        device_serial="SERIAL123",
        package_name="com.whatsapp",
        dynamic_run_id="run-123",
    )

    assert size == 54321
    assert seen == [
        (
            "SERIAL123",
            "/sdcard/Download/PCAPdroid/scytaledroid_com_whatsapp_run-123.pcap",
        )
    ]


def test_start_marks_direct_probe_status_when_available(monkeypatch, tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture.adb_client.is_available",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._pcapdroid_installed",
        lambda _serial: True,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture.adb_shell.run_shell",
        lambda _serial, _args: "",
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._pcapdroid_status_ok",
        lambda _serial, _api_key: (True, None),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._peek_latest_pcapdroid",
        lambda _serial, min_epoch=None: {"latest_path": None, "latest_mtime": None},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._poll_latest_pcapdroid",
        lambda _serial, min_epoch=None, timeout_s=2.0: {
            "latest_path": None,
            "latest_mtime": None,
        },
    )

    handle = PcapdroidCaptureObserver().start(ctx)

    assert handle.payload is not None
    meta_path = Path(handle.payload["meta_path"])
    payload = json.loads(meta_path.read_text(encoding="utf-8"))
    assert payload["pcap_name"] == make_pcap_capture_name("com.example.app", "run-1")
    assert payload["status_check"] == {
        "ok": True,
        "error": None,
        "source": "direct_probe",
    }


def test_start_records_unavailable_source_without_error(monkeypatch, tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture.adb_client.is_available",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._pcapdroid_installed",
        lambda _serial: True,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture.adb_shell.run_shell",
        lambda _serial, _args: "",
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._pcapdroid_status_ok",
        lambda _serial, _api_key: (None, "PCAPdroid status unavailable"),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._peek_latest_pcapdroid",
        lambda _serial, min_epoch=None: {"latest_path": None, "latest_mtime": None},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._poll_latest_pcapdroid",
        lambda _serial, min_epoch=None, timeout_s=2.0: {
            "latest_path": None,
            "latest_mtime": None,
        },
    )

    handle = PcapdroidCaptureObserver().start(ctx)

    assert handle.payload is not None
    meta_path = Path(handle.payload["meta_path"])
    payload = json.loads(meta_path.read_text(encoding="utf-8"))
    assert payload["pcap_name_scheme"] == "scytaledroid_{package_slug}_{dynamic_run_id}.pcap"
    assert payload["status_check"] == {
        "ok": None,
        "error": None,
        "source": "unavailable",
    }


def test_make_pcap_capture_name_uses_package_slug_and_run_id() -> None:
    assert (
        make_pcap_capture_name("com.cnn.mobile.android.phone", "run-42")
        == "scytaledroid_com_cnn_mobile_android_phone_run-42.pcap"
    )


def test_pull_with_retries_times_out_instead_of_hanging(monkeypatch, tmp_path: Path) -> None:
    local_path = tmp_path / "capture.pcap"
    calls: list[float] = []

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._device_file_exists",
        lambda _serial, _path: True,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._device_file_size",
        lambda _serial, _path: 123456,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture.time.sleep",
        lambda _seconds: None,
    )

    def _timeout(*_args, **kwargs):
        calls.append(float(kwargs.get("timeout")))
        raise RuntimeError("adb pull timed out")

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture.adb_client.run_adb_command",
        _timeout,
    )

    ok = _pull_with_retries(
        "SERIAL123",
        "/sdcard/Download/PCAPdroid/capture.pcap",
        local_path,
        retries=2,
        pull_timeout_s=7.0,
    )

    assert ok is False
    assert calls == [7.0, 7.0]
    assert not local_path.exists()


def test_stop_keeps_pcap_artifact_when_file_exists_but_is_too_small(
    monkeypatch, tmp_path: Path
) -> None:
    ctx = _ctx(tmp_path)
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    ctx.artifacts_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture.adb_client.is_available",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._pcapdroid_installed",
        lambda _serial: True,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture.adb_shell.run_shell",
        lambda _serial, _args: "",
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._pcapdroid_status_ok",
        lambda _serial, _api_key: (True, None),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._peek_latest_pcapdroid",
        lambda _serial, min_epoch=None: {"latest_path": None, "latest_mtime": None},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._poll_latest_pcapdroid",
        lambda _serial, min_epoch=None, timeout_s=2.0: {"latest_path": None, "latest_mtime": None},
    )
    observer = PcapdroidCaptureObserver()
    handle = observer.start(ctx)
    assert handle.payload is not None

    meta_path = Path(handle.payload["meta_path"])
    local_path = ctx.artifacts_dir / "pcapdroid_capture" / make_pcap_capture_name("com.example.app", "run-1")
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(b"x" * 1024)

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture.adb_client.run_adb_command",
        lambda *_args, **_kwargs: "",
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.observers.pcapdroid_capture._sha256_stream",
        lambda _path: "a" * 64,
    )

    result = observer.stop(handle, ctx)

    assert result.status == "failed"
    assert "too small" in str(result.error).lower()
    artifact_types = [artifact.type for artifact in result.artifacts]
    assert "pcapdroid_capture" in artifact_types
    assert "pcapdroid_capture_meta" in artifact_types
    payload = json.loads(meta_path.read_text(encoding="utf-8"))
    assert payload["pcap_size_bytes"] == 1024
    assert payload["pcap_valid"] is False
