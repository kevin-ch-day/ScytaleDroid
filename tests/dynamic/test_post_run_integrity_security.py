from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.controllers.guided_run import _post_run_integrity_check
from tests.dynamic._post_run_integrity_support import write_json


def test_post_run_integrity_surfaces_security_surface_row(capsys, tmp_path: Path) -> None:
    run_dir = tmp_path / "evidence" / "dynamic" / "run-7"
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
            "security_surface": {
                "status": "ok",
                "finding_count": 2,
                "risk_flags": ["http_metadata_observed"],
                "cleartext": {
                    "http_observed": True,
                    "visibility_class": "cleartext_surface_present",
                },
                "findings": [],
            },
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

    _post_run_integrity_check(SimpleNamespace(dynamic_run_id="run-7", evidence_path=str(run_dir)))
    out = capsys.readouterr().out
    assert "Security surface:" in out
    assert "findings=2" in out
    assert "cleartext_surface_present" in out


def test_post_run_integrity_warns_on_cleartext_policy_mismatch(capsys, tmp_path: Path) -> None:
    run_dir = tmp_path / "evidence" / "dynamic" / "run-8"
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
            "security_surface": {
                "status": "ok",
                "finding_count": 1,
                "risk_flags": ["http_metadata_observed"],
                "cleartext": {
                    "http_observed": True,
                    "visibility_class": "cleartext_surface_present",
                },
                "findings": [],
            },
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
    write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {
            "static_features": {"uses_cleartext_traffic": False},
            "network_targets": {"cleartext_domains": []},
        },
    )
    write_json(
        run_dir / "analysis" / "static_dynamic_overlap.json",
        {
            "cleartext_posture": {
                "mismatch_class": "denied_but_observed",
                "mismatch_summary": "Static posture denies cleartext, but HTTP/cleartext metadata was observed dynamically.",
            }
        },
    )

    _post_run_integrity_check(SimpleNamespace(dynamic_run_id="run-8", evidence_path=str(run_dir)))
    out = capsys.readouterr().out
    assert "Cleartext policy mismatch:" in out
    assert "denies cleartext" in out
