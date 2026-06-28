from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_pcap_observer_audit as report


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_pcap_observer_audit.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "").lower()
    assert out.startswith("usage:")
    assert "pcap observer audit" in out


def test_generate_report_classifies_valid_and_late_empty_runs(tmp_path: Path) -> None:
    dynamic_root = tmp_path / "output" / "evidence" / "dynamic"

    valid_run = dynamic_root / "run-valid"
    _write_json(
        valid_run / "run_manifest.json",
        {
            "dynamic_run_id": "run-valid",
            "ended_at": "2026-06-27T01:00:00Z",
            "target": {"package_name": "bbc.mobile.news.ww", "display_name": "BBC News"},
            "operator": {"run_profile": "baseline_idle"},
            "dataset": {
                "valid_dataset_run": True,
                "invalid_reason_code": "",
                "pcap_size_bytes": 123456,
            },
        },
    )
    _write_json(
        valid_run / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json",
        {
            "pcap_valid": True,
            "status_check": {"ok": True, "source": "direct_probe"},
            "failure_diagnostics": {
                "expected_device_path": "/sdcard/Download/PCAPdroid/scytaledroid_run-valid.pcap",
                "expected_device_path_exists": True,
                "expected_device_path_size_bytes": 123456,
            },
        },
    )
    (valid_run / "artifacts" / "pcapdroid_capture").mkdir(parents=True, exist_ok=True)
    (valid_run / "artifacts" / "pcapdroid_capture" / "capture.pcap").write_bytes(b"pcap")

    late_empty_run = dynamic_root / "run-late-empty"
    _write_json(
        late_empty_run / "run_manifest.json",
        {
            "dynamic_run_id": "run-late-empty",
            "ended_at": "2026-06-27T02:00:00Z",
            "target": {"package_name": "com.cnn.mobile.android.phone", "display_name": "CNN"},
            "operator": {"run_profile": "interaction_scripted"},
            "dataset": {
                "valid_dataset_run": False,
                "invalid_reason_code": "PCAP_MISSING",
                "pcap_size_bytes": 0,
                "pcap_failure_detail": "PCAP_DEVICE_FILE_EMPTY",
            },
        },
    )
    _write_json(
        late_empty_run / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json",
        {
            "pcap_valid": False,
            "status_check": {
                "ok": None,
                "error": None,
                "source": "unavailable",
            },
            "failure_diagnostics": {
                "expected_device_path": "/sdcard/Download/PCAPdroid/scytaledroid_run-late-empty.pcap",
                "expected_device_path_exists": False,
                "expected_device_path_size_bytes": None,
                "delayed_expected_device_path_exists": True,
                "delayed_expected_device_path_size_bytes": 0,
            },
        },
    )

    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir, dynamic_root=dynamic_root)

    assert summary["runs_scanned"] == 2
    assert summary["run_dir_counts"] == {
        "completed": 2,
        "in_progress": 0,
        "ghost": 0,
        "all_dirs_seen": 2,
    }
    assert summary["invalid_pcap_runs"] == 1
    assert summary["observer_case_counts"] == {"late_empty_named_file": 1}
    assert summary["pcap_failure_detail_counts"] == {"PCAP_DEVICE_FILE_EMPTY": 1}
    assert summary["status_error_counts"] == {}
    assert summary["status_source_counts"] == {"direct_probe": 1, "unavailable": 1}

    with (out_dir / "pcap_observer_audit.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    valid_row = next(row for row in rows if row["run_id"] == "run-valid")
    assert valid_row["observer_case"] == "valid_capture"
    assert valid_row["valid_dataset_run"] == "True"
    assert valid_row["status_check_source"] == "direct_probe"
    late_empty_row = next(row for row in rows if row["run_id"] == "run-late-empty")
    assert late_empty_row["observer_case"] == "late_empty_named_file"
    assert late_empty_row["status_check_source"] == "unavailable"
    assert "status_probe_unavailable" in late_empty_row["observer_notes"]
    assert "named_file_appeared_late_empty" in late_empty_row["observer_notes"]


def test_generate_report_skips_in_progress_and_ghost_dirs(tmp_path: Path) -> None:
    dynamic_root = tmp_path / "output" / "evidence" / "dynamic"
    valid_run = dynamic_root / "run-valid"
    _write_json(
        valid_run / "run_manifest.json",
        {
            "dynamic_run_id": "run-valid",
            "target": {"package_name": "bbc.mobile.news.ww"},
            "operator": {"run_profile": "baseline_idle"},
            "dataset": {"valid_dataset_run": True, "invalid_reason_code": "", "pcap_size_bytes": 1234},
        },
    )
    _write_json(
        valid_run / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json",
        {"pcap_valid": True, "status_check": {"ok": True, "source": "direct_probe"}, "failure_diagnostics": {}},
    )

    in_progress = dynamic_root / "run-in-progress"
    (in_progress / "notes").mkdir(parents=True, exist_ok=True)
    (in_progress / "notes" / ".scytaledroid_in_progress").write_text("", encoding="utf-8")

    ghost = dynamic_root / "run-ghost"
    (ghost / "notes").mkdir(parents=True, exist_ok=True)
    (ghost / "notes" / "run_events.jsonl").write_text("", encoding="utf-8")

    summary = report.generate_report(output_dir=tmp_path / "audit", dynamic_root=dynamic_root)

    assert summary["runs_scanned"] == 1
    assert summary["run_dir_counts"] == {
        "completed": 1,
        "in_progress": 1,
        "ghost": 1,
        "all_dirs_seen": 3,
    }
    assert summary["notes"]["in_progress_run_dirs_skipped"] == ["run-in-progress"]
    assert summary["notes"]["ghost_run_dirs_skipped"] == ["run-ghost"]
