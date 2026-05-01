from __future__ import annotations

import json
from pathlib import Path


def _write_json(p: Path, obj: object) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_network_audit_report_smoke(tmp_path, monkeypatch):
    from scytaledroid.Config import app_config
    from scytaledroid.DynamicAnalysis.tools.evidence.audit_report import (
        run_dynamic_evidence_network_audit,
    )

    # app_config is loaded at import time, so patch it directly for isolation.
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(tmp_path / "output"), raising=False)

    root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic" / "run123"
    _write_json(
        root / "run_manifest.json",
        {
            "dynamic_run_id": "run123",
            "ended_at": "2026-02-07T00:00:00Z",
            "target": {"package_name": "com.example.app"},
            "operator": {"run_profile": "baseline_idle", "interaction_level": "minimal"},
            "dataset": {
                "valid_dataset_run": True,
                "invalid_reason_code": None,
                "countable": True,
                "sampling_duration_seconds": 200,
                "pcap_size_bytes": 2000000,
            },
        },
    )
    _write_json(
        root / "analysis" / "pcap_features.json",
        {
            "quality": {"pcap_valid": True, "missing_tools": []},
            "metrics": {"bytes_per_sec": 1000.0, "packets_per_sec": 10.0},
            "proxies": {"tls_ratio": 1.0, "quic_ratio": 0.5, "tcp_ratio": 0.9, "udp_ratio": 0.1},
        },
    )
    _write_json(
        root / "analysis" / "pcap_report.json",
        {
            "report_status": "ok",
            "missing_tools": [],
            "protocol_hierarchy": [{"protocol": "tcp", "bytes": 10, "frames": 1}],
            "top_dns": [{"value": "example.com", "count": 3}],
            "top_sni": [{"value": "sni.example.com", "count": 2}],
        },
    )

    report = run_dynamic_evidence_network_audit(enrich_db_labels=False, write_outputs=True)
    assert report["packs_total"] == 1
    assert report["apps_total"] == 1
    app = report["apps"][0]
    assert app["package_name"] == "com.example.app"
    assert app["runs_total"] == 1
    assert "report_paths" in report
