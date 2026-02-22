from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.aggregate import (
    export_dynamic_run_summary_csv,
    export_pcap_features_csv,
)
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import recompute_dataset_tracker
from scytaledroid.DynamicAnalysis.tools.evidence.freeze_manifest import (
    build_dataset_freeze_manifest,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _seed_dataset_plan(path: Path) -> None:
    _write_json(path, {"apps": {"com.example.app": {}}})


def _seed_run(root: Path, run_id: str, *, run_profile: str) -> None:
    run_dir = root / run_id
    idx = int(run_id[-1]) if run_id[-1].isdigit() else 0
    version_code = "123"
    base_sha = "a" * 64
    artifact_set_hash = "b" * 64
    signer_set_hash = "c" * 64
    static_handoff_hash = "d" * 64
    pcap_rel = "artifacts/pcap/capture.pcap"
    (run_dir / pcap_rel).parent.mkdir(parents=True, exist_ok=True)
    (run_dir / pcap_rel).write_bytes(b"\x00\x01")

    operator = {
        "tier": "dataset",
        "run_profile": run_profile,
        "capture_policy_version": 1,
        "run_sequence": 1 + idx,
        "interaction_level": "minimal" if "baseline" in run_profile else "scripted",
    }
    if run_profile.startswith("interaction_scripted"):
        operator.update(
            {
                "script_hash": ("e" * 63) + str(idx),
                "script_exit_code": 0,
                "script_end_marker": True,
                "step_count_planned": 3,
                "step_count_completed": 3,
                "script_timing_within_tolerance": True,
            }
        )

    _write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": run_id,
            "started_at": f"2026-02-22T08:0{idx}:00Z",
            "operator": operator,
            "target": {
                "package_name": "com.example.app",
                "version_code": version_code,
                "base_apk_sha256": base_sha,
                "artifact_set_hash": artifact_set_hash,
                "signer_set_hash": signer_set_hash,
                "static_handoff_hash": static_handoff_hash,
                "run_identity": {
                    "version_code": version_code,
                    "base_apk_sha256": base_sha,
                    "artifact_set_hash": artifact_set_hash,
                    "signer_set_hash": signer_set_hash,
                },
            },
            "dataset": {
                "tier": "dataset",
                "valid_dataset_run": True,
                "window_count": 30 + idx,
                "pcap_size_bytes": 70000 + idx,
                "sampling_duration_seconds": 180,
            },
            "artifacts": [{"type": "pcapdroid_capture", "relative_path": pcap_rel}],
            "scenario": {"id": "basic_usage"},
        },
    )
    _write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {
            "plan_schema_version": "v1",
            "paper_contract_version": 1,
            "package_name": "com.example.app",
            "version_code": version_code,
            "run_identity": {
                "package_name_lc": "com.example.app",
                "version_code": version_code,
                "base_apk_sha256": base_sha,
                "artifact_set_hash": artifact_set_hash,
                "signer_set_hash": signer_set_hash,
                "static_handoff_hash": static_handoff_hash,
            },
            "static_features": {
                "masvs_total_score": 0.71,
                "perm_dangerous_n": 5,
                "nsc_cleartext_permitted": False,
            },
        },
    )
    _write_json(run_dir / "analysis" / "summary.json", {"telemetry": {"stats": {"sampling_duration_seconds": 180}}})
    _write_json(
        run_dir / "analysis" / "pcap_report.json",
        {"report_status": "ok", "pcap_size_bytes": 70000 + idx, "capinfos": {"parsed": {"capture_duration_s": 180}}},
    )
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {"metrics": {"data_byte_rate_bps": 42.0}, "proxies": {"quic_ratio": 0.2}, "quality": {}},
    )


def test_freeze_and_exports_are_reproducible_independent_of_tracker(tmp_path: Path, monkeypatch) -> None:
    output_root = tmp_path / "output"
    data_root = tmp_path / "data"
    evidence_root = output_root / "evidence" / "dynamic"
    dataset_plan_path = data_root / "archive" / "dataset_plan.json"
    _seed_dataset_plan(dataset_plan_path)
    _seed_run(evidence_root, "r1", run_profile="baseline_idle")
    _seed_run(evidence_root, "r2", run_profile="interaction_scripted")
    _seed_run(evidence_root, "r3", run_profile="interaction_scripted")

    monkeypatch.setattr("scytaledroid.Config.app_config.OUTPUT_DIR", str(output_root))
    monkeypatch.setattr("scytaledroid.Config.app_config.DATA_DIR", str(data_root))

    # Build freeze and exports once.
    freeze1 = build_dataset_freeze_manifest(dataset_plan_path=dataset_plan_path, evidence_root=evidence_root)
    freeze_path = data_root / "archive" / "dataset_freeze.json"
    _write_json(freeze_path, freeze1)
    sum_csv_1 = export_dynamic_run_summary_csv(freeze_path=freeze_path, require_freeze=True)
    feat_csv_1 = export_pcap_features_csv(freeze_path=freeze_path, require_freeze=True)
    assert sum_csv_1 is not None and feat_csv_1 is not None
    hash_sum_1 = _sha256(sum_csv_1)
    hash_feat_1 = _sha256(feat_csv_1)
    include_1 = sorted(freeze1["included_run_ids"])

    # Corrupt tracker state, then recompute tracker from evidence.
    tracker_path = data_root / "archive" / "dataset_plan.json"
    _write_json(
        tracker_path,
        {
            "apps": {
                "com.example.app": {
                    "runs": [{"run_id": "stale", "valid_dataset_run": True, "counts_toward_quota": True}]
                }
            }
        },
    )
    recompute_dataset_tracker()

    # Rebuild freeze and exports again; outputs must be identical.
    freeze2 = build_dataset_freeze_manifest(dataset_plan_path=dataset_plan_path, evidence_root=evidence_root)
    _write_json(freeze_path, freeze2)
    sum_csv_2 = export_dynamic_run_summary_csv(freeze_path=freeze_path, require_freeze=True)
    feat_csv_2 = export_pcap_features_csv(freeze_path=freeze_path, require_freeze=True)
    assert sum_csv_2 is not None and feat_csv_2 is not None
    hash_sum_2 = _sha256(sum_csv_2)
    hash_feat_2 = _sha256(feat_csv_2)
    include_2 = sorted(freeze2["included_run_ids"])

    assert include_1 == include_2
    assert hash_sum_1 == hash_sum_2
    assert hash_feat_1 == hash_feat_2

    with sum_csv_2.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert sorted(row["dynamic_run_id"] for row in rows) == include_2
