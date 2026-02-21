from __future__ import annotations

import csv
import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.aggregate import (
    export_dynamic_run_summary_csv,
    export_pcap_features_csv,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _seed_run(root: Path) -> None:
    run_dir = root / "r1"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": "r1",
            "target": {"package_name": "com.example.app", "version_code": "123"},
            "dataset": {"tier": "dataset", "valid_dataset_run": True, "countable": True},
            "operator": {"run_profile": "baseline_idle"},
        },
    )
    _write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {
            "package_name": "com.example.app",
            "version_name": "1.2.3",
            "version_code": "123",
            "run_identity": {
                "package_name_lc": "com.example.app",
                "version_name": "1.2.3",
                "version_code": "123",
                "signer_digest": "deadbeef",
                "base_apk_sha256": "a" * 64,
                "static_handoff_hash": "b" * 64,
            },
            "static_features": {
                "schema_version": "v1",
                "perm_dangerous_n": 5,
                "nsc_cleartext_permitted": False,
                "masvs_total_score": 21.5,
                "static_risk_score": 34.2,
                "static_risk_band": "MEDIUM",
            },
        },
    )
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {
                "data_byte_rate_bps": 12.0,
                "avg_packet_rate_pps": 1.2,
                "avg_packet_size_bytes": 100.0,
            },
            "proxies": {"quic_ratio": 0.1, "tls_ratio": 0.9, "tcp_ratio": 0.8, "udp_ratio": 0.2},
            "quality": {},
        },
    )
    _write_json(
        run_dir / "analysis" / "summary.json",
        {
            "telemetry": {"stats": {"sampling_duration_seconds": 180}},
            "capture": {"pcap_valid": True},
        },
    )
    _write_json(
        run_dir / "analysis" / "pcap_report.json",
        {
            "top_sni": [{"value": "api.example.com"}],
            "top_dns": [{"value": "cdn.example.com"}],
        },
    )


def _header(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        return next(reader)


def test_export_dynamic_run_summary_includes_static_columns(tmp_path: Path, monkeypatch) -> None:
    output_root = tmp_path / "output"
    data_root = tmp_path / "data"
    evidence_root = output_root / "evidence" / "dynamic"
    _seed_run(evidence_root)
    monkeypatch.setattr("scytaledroid.Config.app_config.OUTPUT_DIR", str(output_root))
    monkeypatch.setattr("scytaledroid.Config.app_config.DATA_DIR", str(data_root))

    out = export_dynamic_run_summary_csv()
    assert out is not None
    header = _header(out)
    for required in (
        "package_name_lc",
        "version_code",
        "base_apk_sha256",
        "static_risk_score",
        "static_risk_band",
        "masvs_total_score",
        "perm_dangerous_n",
        "nsc_cleartext_permitted",
    ):
        assert required in header


def test_export_pcap_features_includes_static_columns(tmp_path: Path, monkeypatch) -> None:
    output_root = tmp_path / "output"
    data_root = tmp_path / "data"
    evidence_root = output_root / "evidence" / "dynamic"
    _seed_run(evidence_root)
    monkeypatch.setattr("scytaledroid.Config.app_config.OUTPUT_DIR", str(output_root))
    monkeypatch.setattr("scytaledroid.Config.app_config.DATA_DIR", str(data_root))

    out = export_pcap_features_csv()
    assert out is not None
    header = _header(out)
    for required in (
        "package_name_lc",
        "version_code",
        "base_apk_sha256",
        "static_risk_score",
        "static_risk_band",
        "masvs_total_score",
        "perm_dangerous_n",
        "nsc_cleartext_permitted",
    ):
        assert required in header
