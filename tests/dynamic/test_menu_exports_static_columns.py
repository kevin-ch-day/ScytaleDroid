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


def _seed_run(root: Path, *, run_id: str = "r1") -> None:
    run_dir = root / run_id
    _write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": run_id,
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


def _contract_headers(name: str) -> list[str]:
    contract_path = Path("docs/contracts/paper_export_schema_v1.json")
    payload = json.loads(contract_path.read_text(encoding="utf-8"))
    return list(payload["files"][name]["ordered_columns"])


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
    assert header == _contract_headers("dynamic_run_summary.csv")


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
    assert header == _contract_headers("pcap_features.csv")


def test_exports_can_be_freeze_anchored(tmp_path: Path, monkeypatch) -> None:
    output_root = tmp_path / "output"
    data_root = tmp_path / "data"
    evidence_root = output_root / "evidence" / "dynamic"
    _seed_run(evidence_root, run_id="r1")
    # Second run not included by freeze.
    _seed_run(evidence_root, run_id="r2")
    monkeypatch.setattr("scytaledroid.Config.app_config.OUTPUT_DIR", str(output_root))
    monkeypatch.setattr("scytaledroid.Config.app_config.DATA_DIR", str(data_root))
    freeze_path = data_root / "archive" / "dataset_freeze.json"
    _write_json(
        freeze_path,
        {
            "included_run_ids": ["r1"],
            "paper_contract_hash": "a" * 64,
            "freeze_role": "canonical",
        },
    )

    out_summary = export_dynamic_run_summary_csv(freeze_path=freeze_path)
    out_features = export_pcap_features_csv(freeze_path=freeze_path)
    assert out_summary is not None and out_features is not None
    with out_summary.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
        assert len(rows) == 1
        assert rows[0]["dynamic_run_id"] == "r1"


def test_exports_fail_closed_when_freeze_required(tmp_path: Path, monkeypatch) -> None:
    output_root = tmp_path / "output"
    data_root = tmp_path / "data"
    evidence_root = output_root / "evidence" / "dynamic"
    _seed_run(evidence_root, run_id="r1")
    monkeypatch.setattr("scytaledroid.Config.app_config.OUTPUT_DIR", str(output_root))
    monkeypatch.setattr("scytaledroid.Config.app_config.DATA_DIR", str(data_root))
    missing_freeze = data_root / "archive" / "dataset_freeze.json"

    try:
        export_dynamic_run_summary_csv(freeze_path=missing_freeze, require_freeze=True)
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "EXPORT_BLOCKED_MISSING_FREEZE" in str(exc)


def test_exports_fail_closed_when_freeze_ids_missing_locally(tmp_path: Path, monkeypatch) -> None:
    output_root = tmp_path / "output"
    data_root = tmp_path / "data"
    evidence_root = output_root / "evidence" / "dynamic"
    _seed_run(evidence_root, run_id="r1")
    monkeypatch.setattr("scytaledroid.Config.app_config.OUTPUT_DIR", str(output_root))
    monkeypatch.setattr("scytaledroid.Config.app_config.DATA_DIR", str(data_root))
    freeze_path = data_root / "archive" / "dataset_freeze.json"
    _write_json(
        freeze_path,
        {
            "included_run_ids": ["missing-run-id"],
            "paper_contract_hash": "a" * 64,
            "freeze_role": "canonical",
        },
    )

    try:
        export_dynamic_run_summary_csv(freeze_path=freeze_path, require_freeze=True)
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "EXPORT_BLOCKED_STALE_FREEZE" in str(exc)
    assert list((data_root / "archive").glob("legacy_freeze_*.json"))
    assert not freeze_path.exists()

    try:
        export_pcap_features_csv(freeze_path=freeze_path, require_freeze=True)
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "EXPORT_BLOCKED_MISSING_FREEZE" in str(exc)


def test_exports_fail_closed_when_contract_hash_missing(tmp_path: Path, monkeypatch) -> None:
    output_root = tmp_path / "output"
    data_root = tmp_path / "data"
    evidence_root = output_root / "evidence" / "dynamic"
    _seed_run(evidence_root, run_id="r1")
    monkeypatch.setattr("scytaledroid.Config.app_config.OUTPUT_DIR", str(output_root))
    monkeypatch.setattr("scytaledroid.Config.app_config.DATA_DIR", str(data_root))
    freeze_path = data_root / "archive" / "dataset_freeze.json"
    _write_json(freeze_path, {"included_run_ids": ["r1"], "freeze_role": "canonical"})

    try:
        export_dynamic_run_summary_csv(freeze_path=freeze_path, require_freeze=True)
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "EXPORT_BLOCKED_MISSING_CONTRACT_HASH" in str(exc)
    assert list((data_root / "archive").glob("legacy_freeze_*.json"))
    assert not freeze_path.exists()


def test_exports_auto_demote_noncanonical_canonical_freeze(tmp_path: Path, monkeypatch) -> None:
    output_root = tmp_path / "output"
    data_root = tmp_path / "data"
    evidence_root = output_root / "evidence" / "dynamic"
    _seed_run(evidence_root, run_id="r1")
    monkeypatch.setattr("scytaledroid.Config.app_config.OUTPUT_DIR", str(output_root))
    monkeypatch.setattr("scytaledroid.Config.app_config.DATA_DIR", str(data_root))
    freeze_path = data_root / "archive" / "dataset_freeze.json"
    _write_json(
        freeze_path,
        {
            "included_run_ids": ["r1"],
            "paper_contract_hash": "a" * 64,
            "freeze_role": "legacy",
        },
    )

    try:
        export_dynamic_run_summary_csv(freeze_path=freeze_path, require_freeze=True)
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "EXPORT_BLOCKED_NONCANONICAL_FREEZE" in str(exc)
    legacy = list((data_root / "archive").glob("legacy_freeze_*.json"))
    assert legacy
    assert not freeze_path.exists()

    try:
        export_pcap_features_csv(freeze_path=freeze_path, require_freeze=True)
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "EXPORT_BLOCKED_MISSING_FREEZE" in str(exc)
