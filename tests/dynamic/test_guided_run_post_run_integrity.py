from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.controllers.guided_run import _post_run_integrity_check


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_post_run_integrity_fails_when_window_count_missing(capsys, tmp_path: Path) -> None:
    run_dir = tmp_path / "evidence" / "dynamic" / "run-1"
    _write(
        run_dir / "run_manifest.json",
        {
            "dataset": {
                "valid_dataset_run": True,
                "invalid_reason_code": None,
                "pcap_size_bytes": 250000,
            }
        },
    )
    _write(
        run_dir / "analysis" / "pcap_report.json",
        {
            "report_status": "ok",
            "pcap_size_bytes": 250000,
            "capinfos": {"parsed": {"packet_count": 10}},
        },
    )
    _write(
        run_dir / "analysis" / "pcap_features.json",
        {"metrics": {}, "proxies": {}, "timeseries": {"windowing": {}}},
    )

    _post_run_integrity_check(
        SimpleNamespace(dynamic_run_id="run-1", evidence_path=str(run_dir))
    )
    out = capsys.readouterr().out
    assert "Window count" in out
    assert "unavailable (min 20)" in out
    assert "Run verdict" in out
    assert "INVALID" in out


def test_post_run_integrity_marks_skipped_feature_extraction_as_fail(capsys, tmp_path: Path) -> None:
    run_dir = tmp_path / "evidence" / "dynamic" / "run-2"
    _write(
        run_dir / "run_manifest.json",
        {
            "dataset": {
                "valid_dataset_run": False,
                "invalid_reason_code": "PCAP_MISSING",
                "pcap_size_bytes": 0,
            }
        },
    )
    _write(
        run_dir / "analysis" / "pcap_report.json",
        {
            "report_status": "skip",
            "pcap_size_bytes": 0,
            "capinfos": {"parsed": {}},
        },
    )
    _write(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {},
            "proxies": {},
            "quality": {
                "report_status": "skip",
                "pcap_enrichment": {
                    "status": "skipped",
                    "reason": "pcap_path_missing",
                },
            },
        },
    )

    _post_run_integrity_check(
        SimpleNamespace(dynamic_run_id="run-2", evidence_path=str(run_dir))
    )
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "pcap_features.json" in out
    assert "report=skip" in out
    assert "enrichment=skipped" in out


def test_post_run_integrity_explains_netstats_seen_but_pcap_missing(capsys, tmp_path: Path) -> None:
    run_dir = tmp_path / "evidence" / "dynamic" / "run-3"
    _write(
        run_dir / "run_manifest.json",
        {
            "dataset": {
                "valid_dataset_run": False,
                "invalid_reason_code": "PCAP_MISSING",
                "pcap_size_bytes": 0,
                "netstats_observed_bytes": 26437836,
                "pcap_available": False,
                "pcap_failure_detail": "PCAP_DEVICE_FILE_EMPTY",
                "pcap_failure_summary": "Network traffic was observed by Android netstats, but the PCAP capture artifact is empty or unavailable. Scripted interaction timeline is still available for protocol validation.",
                "timeline_available": True,
                "timeline_complete": True,
            }
        },
    )
    _write(
        run_dir / "analysis" / "pcap_report.json",
        {
            "report_status": "skip",
            "pcap_size_bytes": 0,
            "capinfos": {"parsed": {}},
        },
    )
    _write(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {},
            "proxies": {},
            "quality": {
                "report_status": "skip",
                "pcap_enrichment": {
                    "status": "skipped",
                    "reason": "pcap_path_missing",
                },
            },
        },
    )

    _post_run_integrity_check(
        SimpleNamespace(dynamic_run_id="run-3", evidence_path=str(run_dir))
    )
    out = capsys.readouterr().out
    assert "Dataset validity: INVALID (PCAP_MISSING)" in out
    assert "Network traffic was observed by Android netstats" in out
    assert "excluded from dataset quota" in out
    assert "verify PCAPdroid capture/export and recollect" in out
    assert "PCAP failure detail: PCAP_DEVICE_FILE_EMPTY" in out


def test_post_run_integrity_derives_pcap_failure_summary_for_historical_run(capsys, tmp_path: Path) -> None:
    run_dir = tmp_path / "evidence" / "dynamic" / "run-4"
    _write(
        run_dir / "run_manifest.json",
        {
            "dataset": {
                "valid_dataset_run": False,
                "invalid_reason_code": "PCAP_MISSING",
                "pcap_size_bytes": 0,
            }
        },
    )
    _write(
        run_dir / "analysis" / "summary.json",
        {
            "telemetry": {
                "stats": {
                    "netstats_bytes_in_total": 24942882,
                    "netstats_bytes_out_total": 1494954,
                }
            }
        },
    )
    _write(
        run_dir / "analysis" / "interaction_timeline.json",
        {
            "timeline_complete": True,
            "planned_step_count": 6,
            "completed_step_count": 6,
        },
    )
    _write(
        run_dir / "analysis" / "pcap_report.json",
        {
            "report_status": "skip",
            "pcap_size_bytes": 0,
            "capinfos": {"parsed": {}},
        },
    )
    _write(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {},
            "proxies": {},
            "quality": {
                "report_status": "skip",
                "pcap_enrichment": {
                    "status": "skipped",
                    "reason": "pcap_path_missing",
                },
            },
        },
    )
    _write(
        run_dir / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json",
        {
            "pcap_size_bytes": 0,
            "pcap_valid": False,
            "failure_diagnostics": {
                "expected_device_path_exists": False,
                "expected_device_path_size_bytes": None,
                "latest_fallback_path": None,
            },
        },
    )

    _post_run_integrity_check(
        SimpleNamespace(dynamic_run_id="run-4", evidence_path=str(run_dir))
    )
    out = capsys.readouterr().out
    assert "Dataset validity: INVALID (PCAP_MISSING)" in out
    assert "Network traffic was observed by Android netstats" in out
    assert "Scripted interaction timeline is still available for protocol validation" in out
    assert "PCAP failure detail: PCAP_DEVICE_FILE_MISSING" in out
