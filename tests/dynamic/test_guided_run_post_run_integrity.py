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

