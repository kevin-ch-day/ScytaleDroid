from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.tools.paper_gate import run_paper_gate


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def test_paper_gate_passes_minimal_contract(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.tools.paper_gate._verify_static_link", lambda **_k: True)
    freeze_path = tmp_path / "freeze.json"
    evidence_root = tmp_path / "evidence"
    run_id = "r1"
    run_dir = evidence_root / run_id
    ml_dir = run_dir / "analysis" / "ml" / "v1"

    _write_json(freeze_path, {"included_run_ids": [run_id]})
    freeze_sha = __import__("hashlib").sha256(freeze_path.read_bytes()).hexdigest()

    _write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {
            "run_identity": {
                "static_handoff_hash": "a" * 64,
                "base_apk_sha256": "b" * 64,
            }
        },
    )
    _write_json(
        ml_dir / "model_manifest.json",
        {
            "ml_schema_version": 1,
            "feature_schema_version": "v1.1",
            "tool_git_commit": "abc1234",
            "schema_version": "0.2.6",
            "freeze_manifest_sha256": freeze_sha,
            "models": {
                "isolation_forest": {
                    "training_mode": "baseline_only",
                    "quality_gates": {
                        "baseline_pcap_bytes_ok": True,
                        "baseline_windows_ok": True,
                    },
                }
            },
        },
    )
    _write_json(ml_dir / "cohort_status.json", {"status": "CANONICAL_PAPER_ELIGIBLE"})
    _write_json(ml_dir / "ml_summary.json", {"models": {"isolation_forest": {"median": 0.1}}})
    _write_json(
        ml_dir / "baseline_threshold.json",
        {"models": {"isolation_forest": {"threshold_value": 1.0}}},
    )
    dars_payload = {"scores": {"isolation_forest": {"dars_v1": 12.3}}}
    _write_json(ml_dir / "dars_v1.json", dars_payload)
    dars_sha = __import__("hashlib").sha256((ml_dir / "dars_v1.json").read_bytes()).hexdigest()
    (ml_dir / "dars_v1.sha256").write_text(dars_sha + "\n", encoding="utf-8")
    (ml_dir / "window_scores.csv").write_text("window_start_s,window_end_s,score,threshold,is_anomalous\n", encoding="utf-8")
    (ml_dir / "top_anomalous_windows.csv").write_text("rank,window_start_s,window_end_s,score,threshold,is_exceedance\n", encoding="utf-8")
    (ml_dir / "attribution_proxy.csv").write_text(
        "rank,window_start_s,window_end_s,score,dominant_feature,bytes_per_sec_z,packets_per_sec_z,avg_packet_size_bytes_z\n",
        encoding="utf-8",
    )

    result = run_paper_gate(freeze_path=freeze_path, evidence_root=evidence_root)
    assert result.passed is True
    assert result.errors == []
    assert result.checked_runs == 1


def test_paper_gate_fails_missing_linkage(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.tools.paper_gate._verify_static_link", lambda **_k: True)
    freeze_path = tmp_path / "freeze.json"
    evidence_root = tmp_path / "evidence"
    run_id = "r1"
    run_dir = evidence_root / run_id
    ml_dir = run_dir / "analysis" / "ml" / "v1"
    _write_json(freeze_path, {"included_run_ids": [run_id]})
    _write_json(run_dir / "inputs" / "static_dynamic_plan.json", {"run_identity": {}})
    _write_json(ml_dir / "cohort_status.json", {"status": "EXCLUDED", "reason_code": "ML_SKIPPED_MISSING_STATIC_LINK"})
    _write_json(ml_dir / "model_manifest.json", {"models": {"isolation_forest": {"training_mode": "baseline_only", "quality_gates": {"baseline_pcap_bytes_ok": True, "baseline_windows_ok": True}}}})
    _write_json(ml_dir / "ml_summary.json", {"models": {"isolation_forest": {}}})
    _write_json(ml_dir / "baseline_threshold.json", {"models": {"isolation_forest": {"threshold_value": 1.0}}})
    _write_json(ml_dir / "dars_v1.json", {"scores": {"isolation_forest": {"dars_v1": 1.0}}})
    (ml_dir / "dars_v1.sha256").write_text("bad\n", encoding="utf-8")
    (ml_dir / "window_scores.csv").write_text("window_start_s,window_end_s,score,threshold,is_anomalous\n", encoding="utf-8")
    (ml_dir / "top_anomalous_windows.csv").write_text("", encoding="utf-8")
    (ml_dir / "attribution_proxy.csv").write_text("", encoding="utf-8")

    result = run_paper_gate(freeze_path=freeze_path, evidence_root=evidence_root)
    assert result.passed is False
    assert result.checked_runs == 1
    assert any("missing_plan_identity:static_handoff_hash" in err for err in result.errors)


def test_paper_gate_fails_static_link_db_mismatch(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("scytaledroid.DynamicAnalysis.tools.paper_gate._verify_static_link", lambda **_k: False)
    freeze_path = tmp_path / "freeze.json"
    evidence_root = tmp_path / "evidence"
    run_id = "r1"
    run_dir = evidence_root / run_id
    ml_dir = run_dir / "analysis" / "ml" / "v1"
    _write_json(freeze_path, {"included_run_ids": [run_id]})
    freeze_sha = __import__("hashlib").sha256(freeze_path.read_bytes()).hexdigest()
    _write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {"run_identity": {"static_handoff_hash": "a" * 64, "base_apk_sha256": "b" * 64}},
    )
    _write_json(ml_dir / "cohort_status.json", {"status": "CANONICAL_PAPER_ELIGIBLE"})
    _write_json(
        ml_dir / "model_manifest.json",
        {
            "ml_schema_version": 1,
            "feature_schema_version": "v1.1",
            "tool_git_commit": "abc1234",
            "schema_version": "0.2.6",
            "freeze_manifest_sha256": freeze_sha,
            "models": {"isolation_forest": {"training_mode": "baseline_only", "quality_gates": {"baseline_pcap_bytes_ok": True, "baseline_windows_ok": True}}},
        },
    )
    _write_json(ml_dir / "ml_summary.json", {"models": {"isolation_forest": {"median": 0.1}}})
    _write_json(ml_dir / "baseline_threshold.json", {"models": {"isolation_forest": {"threshold_value": 1.0}}})
    _write_json(ml_dir / "dars_v1.json", {"scores": {"isolation_forest": {"dars_v1": 1.0}}})
    dars_sha = __import__("hashlib").sha256((ml_dir / "dars_v1.json").read_bytes()).hexdigest()
    (ml_dir / "dars_v1.sha256").write_text(dars_sha + "\n", encoding="utf-8")
    (ml_dir / "window_scores.csv").write_text("window_start_s,window_end_s,score,threshold,is_anomalous\n", encoding="utf-8")
    (ml_dir / "top_anomalous_windows.csv").write_text("", encoding="utf-8")
    (ml_dir / "attribution_proxy.csv").write_text("", encoding="utf-8")
    result = run_paper_gate(freeze_path=freeze_path, evidence_root=evidence_root)
    assert result.passed is False
    assert any("static_link_db_mismatch" in err for err in result.errors)
