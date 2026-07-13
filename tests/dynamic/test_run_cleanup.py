from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.utils import run_cleanup


def _write_capture_meta(run_dir: Path, diagnostics: dict[str, object]) -> None:
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    capture_dir.mkdir(parents=True, exist_ok=True)
    (capture_dir / "pcapdroid_capture_meta.json").write_text(
        json.dumps({"failure_diagnostics": diagnostics}),
        encoding="utf-8",
    )


def test_recent_tracker_runs_derives_missing_pcap_detail_from_local_evidence(
    monkeypatch,
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(output_root))

    run_id = "4d3def16-83a9-43f6-8dad-0d1dd295d795"
    run_dir = output_root / "evidence" / "dynamic" / run_id
    _write_capture_meta(
        run_dir,
        {
            "expected_device_path_exists": False,
            "latest_fallback_path": "",
        },
    )

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.load_dataset_tracker",
        lambda: {
            "apps": {
                "com.cnn.mobile.android.phone": {
                    "runs": [
                        {
                            "run_id": run_id,
                            "ended_at": "2026-06-16T02:18:37.062401+00:00",
                            "run_profile": "interaction_scripted",
                            "valid_dataset_run": False,
                            "invalid_reason_code": "PCAP_MISSING",
                        }
                    ]
                }
            }
        },
    )

    recent = run_cleanup.recent_tracker_runs("com.cnn.mobile.android.phone", limit=1)

    assert len(recent) == 1
    assert recent[0].invalid_reason_code == "PCAP_MISSING"
    assert recent[0].pcap_failure_detail == "PCAP_DEVICE_FILE_MISSING"


def test_recent_tracker_runs_preserves_existing_pcap_detail(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(tmp_path / "output"))

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.load_dataset_tracker",
        lambda: {
            "apps": {
                "com.cnn.mobile.android.phone": {
                    "runs": [
                        {
                            "run_id": "cnn-run-1",
                            "ended_at": "2026-06-16T02:18:37.062401+00:00",
                            "run_profile": "interaction_scripted",
                            "valid_dataset_run": False,
                            "invalid_reason_code": "PCAP_MISSING",
                            "pcap_failure_detail": "PCAP_LOCAL_FILE_EMPTY",
                        }
                    ]
                }
            }
        },
    )

    recent = run_cleanup.recent_tracker_runs("com.cnn.mobile.android.phone", limit=1)

    assert len(recent) == 1
    assert recent[0].pcap_failure_detail == "PCAP_LOCAL_FILE_EMPTY"


def test_recent_tracker_runs_from_payload_uses_existing_tracker_data(
    monkeypatch,
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(output_root))

    payload = {
        "apps": {
            "com.instagram.android": {
                "runs": [
                    {
                        "run_id": "older",
                        "ended_at": "2026-07-01T12:00:00+00:00",
                        "run_profile": "baseline_idle",
                        "valid_dataset_run": True,
                    },
                    {
                        "run_id": "newer",
                        "ended_at": "2026-07-02T12:00:00+00:00",
                        "run_profile": "interaction_manual",
                        "interaction_level": "interactive",
                        "messaging_activity": "mixed",
                        "valid_dataset_run": False,
                        "invalid_reason_code": "PCAP_MISSING",
                        "pcap_failure_detail": "PCAP_LOCAL_FILE_EMPTY",
                    },
                ]
            }
        }
    }

    recent = run_cleanup.recent_tracker_runs_from_payload(
        payload,
        "com.instagram.android",
        limit=2,
    )

    assert [row.run_id for row in recent] == ["newer", "older"]
    assert recent[0].valid is False
    assert recent[0].invalid_reason_code == "PCAP_MISSING"
    assert recent[0].pcap_failure_detail == "PCAP_LOCAL_FILE_EMPTY"
    assert recent[0].interaction_level == "interactive"
    assert recent[0].messaging_activity == "mixed"
    assert recent[1].valid is True


def test_find_incomplete_dynamic_run_dirs_skips_active_pid_marker(
    monkeypatch,
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(output_root))
    run_dir = output_root / "evidence" / "dynamic" / "active-run"
    marker_path = run_dir / "notes" / ".scytaledroid_in_progress"
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.write_text(
        json.dumps(
            {
                "dynamic_run_id": "active-run",
                "started_at_utc": "2026-07-05T00:00:00+00:00",
                "host_pid": 4242,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(run_cleanup, "_process_is_alive", lambda pid: pid == 4242)

    assert run_cleanup.find_incomplete_dynamic_run_dirs() == []


def test_find_incomplete_dynamic_run_dirs_includes_dead_pid_marker(
    monkeypatch,
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(output_root))
    run_dir = output_root / "evidence" / "dynamic" / "dead-run"
    marker_path = run_dir / "notes" / ".scytaledroid_in_progress"
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.write_text(
        json.dumps(
            {
                "dynamic_run_id": "dead-run",
                "started_at_utc": "2026-07-05T00:00:00+00:00",
                "host_pid": 99999,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(run_cleanup, "_process_is_alive", lambda _pid: False)

    assert run_cleanup.find_incomplete_dynamic_run_dirs() == [run_dir]


def test_find_incomplete_dynamic_run_dirs_includes_stale_legacy_marker(
    monkeypatch,
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(output_root))
    run_dir = output_root / "evidence" / "dynamic" / "legacy-run"
    marker_path = run_dir / "notes" / ".scytaledroid_in_progress"
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.write_text(
        json.dumps(
            {
                "dynamic_run_id": "legacy-run",
                "started_at_utc": "2026-07-05T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(run_cleanup, "_now_epoch_s", lambda: 1_783_872_001.0)

    assert run_cleanup.find_incomplete_dynamic_run_dirs() == [run_dir]
