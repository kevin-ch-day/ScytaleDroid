from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.observers.pcapdroid_capture import PcapdroidCaptureObserver


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


def test_start_clears_status_error_when_fallback_probe_confirms_capture(monkeypatch, tmp_path: Path) -> None:
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
    assert payload["status_check"] == {
        "ok": True,
        "error": None,
        "source": "fallback_probe",
    }


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
    assert payload["status_check"] == {
        "ok": None,
        "error": None,
        "source": "unavailable",
    }
