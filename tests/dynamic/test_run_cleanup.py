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
