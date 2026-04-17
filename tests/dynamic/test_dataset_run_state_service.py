from __future__ import annotations

import json
from pathlib import Path

import pytest

from scytaledroid.DynamicAnalysis.services import dataset_run_state as state_service


pytestmark = [pytest.mark.contract, pytest.mark.state_contract]


def _tracker_path(tmp_path: Path) -> Path:
    return tmp_path / "archive" / "dataset_plan.json"


def _write_tracker(tmp_path: Path, payload: dict) -> None:
    path = _tracker_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_manifest(output_root: Path, run_id: str, package_name: str) -> None:
    run_dir = output_root / "evidence" / "dynamic" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps({"target": {"package_name": package_name}}),
        encoding="utf-8",
    )


def test_load_dataset_run_state_clean_state_when_tracker_and_evidence_missing(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(state_service.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(state_service.app_config, "OUTPUT_DIR", str(tmp_path / "output"))

    state = state_service.load_dataset_run_state("com.example.app")

    assert state.tracker_status == "missing"
    assert state.evidence_status == "missing"
    assert state.state_status == "ok"
    assert state.counts.total_runs == 0
    assert state.local_evidence_dir_count == 0
    assert state.reset_available is False


def test_load_dataset_run_state_marks_invalid_tracker_explicitly(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(state_service.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(state_service.app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    path = _tracker_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{invalid", encoding="utf-8")

    state = state_service.load_dataset_run_state("com.example.app")

    assert state.tracker_status == "invalid"
    assert state.state_status == "degraded"
    assert state.counts.total_runs == 0


def test_load_dataset_run_state_preserves_quota_and_exclusion_rollups(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(state_service.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(state_service.app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setattr(state_service.app_config, "DYNAMIC_DATASET_BASELINE_RUNS", 1)
    monkeypatch.setattr(state_service.app_config, "DYNAMIC_DATASET_INTERACTIVE_RUNS", 2)
    package = "com.example.app"
    _write_tracker(
        tmp_path,
        {
            "apps": {
                package: {
                    "runs": [
                        {
                            "run_id": "r1",
                            "ended_at": "2026-04-16T10:00:00Z",
                            "valid_dataset_run": True,
                            "run_profile": "baseline_idle",
                            "counts_toward_quota": True,
                            "paper_eligible": True,
                        },
                        {
                            "run_id": "r2",
                            "ended_at": "2026-04-16T11:00:00Z",
                            "valid_dataset_run": True,
                            "run_profile": "interaction_scripted",
                            "counts_toward_quota": True,
                            "paper_eligible": False,
                            "paper_exclusion_primary_reason_code": "EXCLUDED_LOW_SIGNAL",
                        },
                    ],
                    "valid_runs": 2,
                    "baseline_valid_runs": 1,
                    "interactive_valid_runs": 1,
                    "quota_met": False,
                    "extra_valid_runs": 0,
                }
            }
        },
    )
    _write_manifest(tmp_path / "output", "r1", package)
    _write_manifest(tmp_path / "output", "r2", package)

    state = state_service.load_dataset_run_state(package)

    assert state.tracker_status == "ok"
    assert state.evidence_status == "ok"
    assert state.counts.valid_runs == 1
    assert state.counts.interactive_valid_runs == 0
    assert state.paper_eligible_local == 1
    assert state.quota_counted_local == 1
    assert state.exclusion_reason_top == (("EXCLUDED_LOW_SIGNAL", 1),)
    assert state.local_evidence_dir_count == 2
    assert state.reset_available is True


def test_load_dataset_run_state_applies_recent_run_streak_override(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(state_service.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(state_service.app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    package = "org.telegram.messenger"
    _write_tracker(
        tmp_path,
        {
            "apps": {
                package: {
                    "runs": [
                        {
                            "run_id": "r2",
                            "ended_at": "2026-04-16T12:00:00Z",
                            "valid_dataset_run": False,
                            "run_profile": "baseline_connected",
                            "invalid_reason_code": "INSUFFICIENT_DURATION",
                        },
                        {
                            "run_id": "r1",
                            "ended_at": "2026-04-16T11:00:00Z",
                            "valid_dataset_run": False,
                            "run_profile": "baseline_connected",
                            "invalid_reason_code": "INSUFFICIENT_DURATION",
                        },
                    ],
                    "valid_runs": 0,
                    "baseline_valid_runs": 0,
                    "interactive_valid_runs": 0,
                    "quota_met": False,
                    "extra_valid_runs": 0,
                }
            }
        },
    )

    state = state_service.load_dataset_run_state(package)

    assert state.suggested_profile_from_tracker == "baseline_connected"
    assert state.baseline_connected_insufficient_duration_streak == 2
    assert state.effective_suggested_profile == "interaction_scripted"


def test_load_dataset_run_state_distinguishes_tracker_and_evidence_presence(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(state_service.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(state_service.app_config, "OUTPUT_DIR", str(tmp_path / "output"))

    package = "com.example.app"
    _write_manifest(tmp_path / "output", "r1", package)
    state = state_service.load_dataset_run_state(package)
    assert state.tracker_status == "missing"
    assert state.evidence_status == "ok"
    assert state.state_status == "degraded"

    other_package = "com.other.app"
    _write_tracker(
        tmp_path,
        {
            "apps": {
                other_package: {
                    "runs": [{"run_id": "r2", "valid_dataset_run": True, "run_profile": "baseline_idle"}],
                    "valid_runs": 1,
                    "baseline_valid_runs": 1,
                    "interactive_valid_runs": 0,
                    "quota_met": False,
                    "extra_valid_runs": 0,
                }
            }
        },
    )
    state = state_service.load_dataset_run_state(other_package)
    assert state.tracker_status == "ok"
    assert state.evidence_status == "ok"
    assert state.local_evidence_dir_count == 0
    assert state.state_status == "ok"


def test_load_dataset_run_state_tracks_low_signal_idle_and_pcap_missing_streaks(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(state_service.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(state_service.app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    package = "com.example.app"
    _write_tracker(
        tmp_path,
        {
            "apps": {
                package: {
                    "runs": [
                        {
                            "run_id": "r2",
                            "ended_at": "2026-04-16T12:00:00Z",
                            "valid_dataset_run": False,
                            "run_profile": "baseline_idle",
                            "invalid_reason_code": "PCAP_MISSING",
                            "messaging_activity": "none",
                        },
                        {
                            "run_id": "r1",
                            "ended_at": "2026-04-16T11:00:00Z",
                            "valid_dataset_run": False,
                            "run_profile": "baseline_idle",
                            "invalid_reason_code": "PCAP_MISSING",
                            "messaging_activity": "none",
                        },
                    ]
                }
            }
        },
    )

    state = state_service.load_dataset_run_state(package)
    assert state.baseline_idle_pcap_missing_streak == 2
    assert state.recent_runs[0].status_label == "INVALID:PCAP_MISSING (LOW_SIGNAL_IDLE)"


def test_load_dataset_run_state_tracks_low_signal_idle_streak(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(state_service.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(state_service.app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    package = "com.example.app"
    _write_tracker(
        tmp_path,
        {
            "apps": {
                package: {
                    "runs": [
                        {
                            "run_id": "r2",
                            "ended_at": "2026-04-16T12:00:00Z",
                            "valid_dataset_run": True,
                            "run_profile": "baseline_idle",
                            "low_signal": True,
                        },
                        {
                            "run_id": "r1",
                            "ended_at": "2026-04-16T11:00:00Z",
                            "valid_dataset_run": True,
                            "run_profile": "baseline_idle",
                            "low_signal": True,
                        },
                    ]
                }
            }
        },
    )

    state = state_service.load_dataset_run_state(package)
    assert state.baseline_idle_low_signal_streak == 2
    assert state.recent_runs[0].status_label == "VALID (LOW_SIGNAL_IDLE)"
