from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.controllers.guided_run import _post_run_integrity_check
from tests.dynamic._post_run_integrity_support import write_json


def test_post_run_integrity_end_to_end_valid_row(capsys, tmp_path: Path) -> None:
    run_dir = tmp_path / "evidence" / "dynamic" / "run-smoke"
    write_json(
        run_dir / "run_manifest.json",
        {
            "dataset": {
                "valid_dataset_run": True,
                "invalid_reason_code": None,
                "pcap_size_bytes": 250000,
                "window_count": 25,
            }
        },
    )
    write_json(
        run_dir / "analysis" / "pcap_report.json",
        {
            "report_status": "ok",
            "pcap_size_bytes": 250000,
            "capinfos": {"parsed": {"packet_count": 10, "capture_duration_s": 60.0}},
        },
    )
    write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {},
            "proxies": {},
            "quality": {"report_status": "ok", "pcap_enrichment": {"status": "ok"}},
            "timeseries": {"windowing": {"window_count": 25}},
        },
    )

    _post_run_integrity_check(
        SimpleNamespace(dynamic_run_id="run-smoke", evidence_path=str(run_dir))
    )
    out = capsys.readouterr().out
    assert "Post-Run Integrity" in out
    assert "VALID" in out
