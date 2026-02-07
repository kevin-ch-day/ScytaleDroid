from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.aggregate import _build_run_summary_row


def test_dynamic_summary_derives_static_tags_from_embedded_plan(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)

    plan = {
        "permissions": {"declared": ["a"], "dangerous": ["b"], "high_value": ["CAMERA"]},
        "exported_components": {"total": 25},
        "risk_flags": {"uses_cleartext_traffic": True},
        "network_targets": {"domains": ["example.com"], "cleartext_domains": [], "domain_sources": []},
    }
    (run_dir / "inputs" / "static_dynamic_plan.json").write_text(json.dumps(plan), encoding="utf-8")

    manifest = {
        "dynamic_run_id": "run-1",
        "target": {"package_name": "com.example.app", "static_run_id": 1},
        "operator": {"run_profile": "interactive_use", "run_sequence": 2, "interaction_level": "normal"},
    }
    summary = {"telemetry": {"stats": {"sampling_duration_seconds": 180}}, "capture": {"pcap_valid": True}}
    report = {"protocol_hierarchy": [], "top_sni": [], "top_dns": []}
    features = {"metrics": {"data_byte_rate_bps": 1.0, "avg_packet_rate_pps": 2.0}}

    row = _build_run_summary_row(run_dir, manifest, summary, report, None, features)
    assert row
    assert row["static_run_id"] == 1
    assert row["static_tags"] is not None
    assert "PRIVACY_SENSITIVE" in json.loads(row["static_tags"])
    assert row["exported_components_total"] == 25

