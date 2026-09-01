from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.tools.evidence.verify_core import (
    verify_dynamic_evidence_packs,
)


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _base_run(root: Path) -> Path:
    run_dir = root / "run-1"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": "run-1",
            "operator": {"tier": "dataset"},
            "dataset": {"tier": "dataset", "valid_dataset_run": True},
            "target": {"package_name": "com.example.app"},
            "artifacts": [],
        },
    )
    _write_json(run_dir / "inputs/static_dynamic_plan.json", {"run_identity": {}})
    _write_json(run_dir / "analysis/summary.json", {})
    _write_json(run_dir / "analysis/pcap_features.json", {"proxies": {}})
    return run_dir


def _issue_codes(report: dict[str, object]) -> list[str]:
    runs = report["runs"]
    assert isinstance(runs, list) and runs
    issues = runs[0]["issues"]
    return [str(issue["code"]) for issue in issues]


def test_verify_core_does_not_crash_when_report_is_missing_but_features_exist(
    tmp_path: Path,
) -> None:
    _base_run(tmp_path)

    report = verify_dynamic_evidence_packs(tmp_path)

    assert report["scanned"] == 1
    assert "missing_frozen_input" in _issue_codes(report)


def test_verify_core_rejects_unsafe_pcap_and_nonfinite_ratios(tmp_path: Path) -> None:
    run_dir = _base_run(tmp_path)
    manifest_path = run_dir / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"] = [
        {"type": "pcapdroid_capture", "relative_path": "../../outside.pcap"}
    ]
    _write_json(manifest_path, manifest)
    (tmp_path.parent / "outside.pcap").write_bytes(b"outside")
    _write_json(
        run_dir / "analysis/pcap_report.json",
        {
            "protocol_hierarchy": [],
            "no_traffic_observed": [],
            "protocol_ratios": {"tls_ratio": float("nan")},
        },
    )
    _write_json(
        run_dir / "analysis/pcap_features.json",
        {"proxies": {"udp_ratio": float("inf")}},
    )

    report = verify_dynamic_evidence_packs(tmp_path)
    codes = _issue_codes(report)

    assert "pcap_path_unsafe" in codes
    assert "protocol_empty_no_reason" in codes
    assert codes.count("ratio_invalid") == 2


def test_verify_core_does_not_accept_directory_as_required_file(tmp_path: Path) -> None:
    run_dir = _base_run(tmp_path)
    report_path = run_dir / "analysis/pcap_report.json"
    report_path.mkdir()

    report = verify_dynamic_evidence_packs(tmp_path)

    assert "missing_frozen_input" in _issue_codes(report)


def test_verify_core_reports_manifest_run_id_mismatch(tmp_path: Path) -> None:
    run_dir = _base_run(tmp_path)
    manifest_path = run_dir / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["dynamic_run_id"] = "different-run"
    _write_json(manifest_path, manifest)

    report = verify_dynamic_evidence_packs(tmp_path)

    assert "manifest_run_id_mismatch" in _issue_codes(report)
