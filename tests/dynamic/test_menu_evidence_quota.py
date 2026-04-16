from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis import menu
from scytaledroid.DynamicAnalysis.menu import _summarize_evidence_quota
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig
from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import AuditSummary
from scytaledroid.Utils.DisplayUtils import colors


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _run_manifest(
    *,
    package_name: str,
    run_profile: str,
    version_code: str = "123",
    window_count: int = 25,
    include_identity: bool = True,
) -> dict:
    run_identity = {
        "version_code": version_code,
        "base_apk_sha256": "a" * 64,
        "signer_set_hash": "b" * 64,
    }
    if not include_identity:
        run_identity = {"version_code": version_code}
    return {
        "target": {
            "package_name": package_name,
            "run_identity": run_identity,
        },
        "operator": {
            "run_profile": run_profile,
            "capture_policy_version": 1,
        },
        "dataset": {
            "valid_dataset_run": True,
            "window_count": window_count,
        },
    }


def _add_script_protocol_fields(manifest: dict) -> dict:
    profile = str((manifest.get("operator") or {}).get("run_profile") or "").strip().lower()
    if profile.startswith("interaction_scripted"):
        manifest.setdefault("operator", {}).update(
            {
                "template_id": "social_feed_basic_v2",
                "scenario_template": "social_feed_basic_v2",
                "interaction_protocol_version": 2,
                "script_hash": "e" * 64,
                "script_exit_code": 0,
                "script_end_marker": True,
                "step_count_planned": 4,
                "step_count_completed": 4,
                "script_timing_within_tolerance": True,
            }
        )
    return manifest


def _write_plan(
    run_dir: Path,
    *,
    version_code: str = "123",
    include_static_handoff: bool = True,
    include_identity: bool = True,
) -> None:
    run_identity = {"version_code": version_code}
    if include_identity:
        run_identity.update(
            {
                "base_apk_sha256": "a" * 64,
                "artifact_set_hash": "c" * 64,
                "signer_set_hash": "b" * 64,
            }
        )
    if include_static_handoff:
        run_identity["static_handoff_hash"] = "d" * 64
    _write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {
            "package_name": "com.example.app",
            "version_code": version_code,
            "run_identity": run_identity,
        },
    )


def test_summarize_evidence_quota_uses_operator_run_profile(tmp_path: Path, monkeypatch) -> None:
    output_root = tmp_path / "output"
    evidence_root = output_root / "evidence" / "dynamic"
    monkeypatch.setattr("scytaledroid.Config.app_config.OUTPUT_DIR", str(output_root))

    pkg = "com.example.app"
    # run_profile only in operator (dataset.run_profile intentionally absent)
    _write_json(
        evidence_root / "r1" / "run_manifest.json",
        _add_script_protocol_fields(_run_manifest(package_name=pkg, run_profile="baseline_idle")),
    )
    _write_plan(evidence_root / "r1")
    _write_json(
        evidence_root / "r2" / "run_manifest.json",
        _add_script_protocol_fields(_run_manifest(package_name=pkg, run_profile="interaction_scripted")),
    )
    _write_plan(evidence_root / "r2")
    _write_json(
        evidence_root / "r3" / "run_manifest.json",
        _add_script_protocol_fields(_run_manifest(package_name=pkg, run_profile="interaction_manual")),
    )
    _write_plan(evidence_root / "r3")

    cfg = DatasetTrackerConfig()
    summary = _summarize_evidence_quota({pkg}, cfg)
    assert bool(summary["evidence_root_exists"]) is True
    assert int(summary["total_runs"]) == 3
    assert int(summary["paper_eligible_runs"]) == 3
    assert int(summary["quota_runs_counted"]) == 3
    assert int(summary["excluded_runs"]) == 0
    assert int(summary["extra_eligible_runs"]) == 0


def test_summarize_evidence_quota_excludes_missing_identity_or_windows(tmp_path: Path, monkeypatch) -> None:
    output_root = tmp_path / "output"
    evidence_root = output_root / "evidence" / "dynamic"
    monkeypatch.setattr("scytaledroid.Config.app_config.OUTPUT_DIR", str(output_root))

    pkg = "com.example.app"
    # Missing identity hashes -> not paper-eligible
    _write_json(
        evidence_root / "r1" / "run_manifest.json",
        _add_script_protocol_fields(_run_manifest(package_name=pkg, run_profile="baseline_idle", include_identity=False)),
    )
    _write_plan(evidence_root / "r1", include_identity=False)
    # Insufficient windows -> not paper-eligible
    _write_json(
        evidence_root / "r2" / "run_manifest.json",
        _add_script_protocol_fields(_run_manifest(package_name=pkg, run_profile="interaction_scripted", window_count=10)),
    )
    _write_plan(evidence_root / "r2")

    cfg = DatasetTrackerConfig()
    summary = _summarize_evidence_quota({pkg}, cfg)
    assert int(summary["total_runs"]) == 2
    assert int(summary["paper_eligible_runs"]) == 0
    assert int(summary["quota_runs_counted"]) == 0
    assert int(summary["excluded_runs"]) == 2


def test_summarize_evidence_quota_excludes_when_plan_static_link_or_policy_missing(
    tmp_path: Path, monkeypatch
) -> None:
    output_root = tmp_path / "output"
    evidence_root = output_root / "evidence" / "dynamic"
    monkeypatch.setattr("scytaledroid.Config.app_config.OUTPUT_DIR", str(output_root))

    pkg = "com.example.app"
    _write_json(
        evidence_root / "r1" / "run_manifest.json",
        _add_script_protocol_fields(_run_manifest(package_name=pkg, run_profile="baseline_idle")),
    )
    _write_plan(evidence_root / "r1", include_static_handoff=False)
    bad_policy = _add_script_protocol_fields(_run_manifest(package_name=pkg, run_profile="interaction_scripted"))
    bad_policy["operator"]["capture_policy_version"] = 999
    _write_json(evidence_root / "r2" / "run_manifest.json", bad_policy)
    _write_plan(evidence_root / "r2")

    cfg = DatasetTrackerConfig()
    summary = _summarize_evidence_quota({pkg}, cfg)
    assert int(summary["total_runs"]) == 2
    assert int(summary["paper_eligible_runs"]) == 0
    assert int(summary["quota_runs_counted"]) == 0
    assert int(summary["excluded_runs"]) == 2


def test_summarize_evidence_quota_tracks_low_signal_idle_as_exploratory(
    tmp_path: Path, monkeypatch
) -> None:
    output_root = tmp_path / "output"
    evidence_root = output_root / "evidence" / "dynamic"
    monkeypatch.setattr("scytaledroid.Config.app_config.OUTPUT_DIR", str(output_root))

    pkg = "com.example.app"
    baseline = _run_manifest(package_name=pkg, run_profile="baseline_idle")
    baseline.setdefault("dataset", {})["low_signal"] = True
    baseline.setdefault("dataset", {})["invalid_reason_code"] = "LOW_SIGNAL_IDLE"
    _write_json(evidence_root / "r1" / "run_manifest.json", _add_script_protocol_fields(baseline))
    _write_plan(evidence_root / "r1")

    scripted = _run_manifest(package_name=pkg, run_profile="interaction_scripted")
    _write_json(evidence_root / "r2" / "run_manifest.json", _add_script_protocol_fields(scripted))
    _write_plan(evidence_root / "r2")

    cfg = DatasetTrackerConfig()
    summary = _summarize_evidence_quota({pkg}, cfg)
    assert int(summary["paper_eligible_runs"]) == 2
    assert int(summary["quota_runs_counted"]) == 1
    assert int(summary["low_signal_exploratory_runs"]) == 1


def test_dynamic_menu_renders_state_and_evidence_overview(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.schema_gate.dynamic_schema_gate",
        lambda: (True, "", ""),
    )
    monkeypatch.setattr(menu, "_warn_if_code_changed", lambda: None)
    monkeypatch.setattr(menu.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    summary = AuditSummary(
        total_runs=36,
        valid_runs=24,
        paper_eligible_runs=24,
        missing_run_manifest_dirs=0,
        missing_capture_policy_version=0,
        capture_policy_version_mismatch=0,
        missing_signer_set_hash=0,
        identity_mismatch=0,
        missing_window_count=0,
        window_count_below_min=0,
        evidence_root="data/output/evidence/dynamic",
        evidence_root_exists=True,
        runs_discovered_from="evidence",
        expected_valid_runs=24,
        expected_total_runs=36,
        quota_runs_counted=24,
        apps_satisfied=12,
        result="NO-GO",
        reasons=("insufficient valid evidence packs",),
        tracker_runs_hint=36,
        static_runs_hint=12,
        can_freeze=False,
        first_failing_reason="insufficient valid evidence packs",
        freeze_run_ids_present=0,
        freeze_run_ids_total=0,
        canonical_freeze_role="none",
        canonical_freeze_contract_hash_present=False,
        canonical_freeze_demoted_to_legacy=None,
        report_path="output/audit/dynamic/example.json",
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.menu_views.run_freeze_readiness_audit",
        lambda: summary,
    )

    menu.dynamic_analysis_menu()

    out = colors.strip(capsys.readouterr().out)
    assert "State" in out
    assert "Freeze capability" in out
    assert "BLOCKED" in out
    assert "Freeze audit" in out
    assert "NO-GO" in out
    assert "Reason" in out
    assert "insufficient valid evidence packs" in out
    assert "Evidence packs" in out
    assert "(valid 24, invalid 12)" in out
    assert "Latest freeze" in out
    assert "Evidence" in out
    assert "Root" in out
    assert "Freeze" in out
    assert "Tracker" in out
    assert "Primary Actions" in out
    assert "Evidence & Integrity" in out
