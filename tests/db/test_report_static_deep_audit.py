from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_static_deep_audit as report


def test_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_static_deep_audit.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "").lower()
    assert out.startswith("usage:")
    assert "deep audit over static evidence quality" in out


def test_quality_tier_boundaries() -> None:
    assert report._quality_tier(100) == "A+"
    assert report._quality_tier(95) == "A+"
    assert report._quality_tier(94) == "A"
    assert report._quality_tier(90) == "A"
    assert report._quality_tier(89) == "B+"
    assert report._quality_tier(85) == "B+"
    assert report._quality_tier(84) == "B"
    assert report._quality_tier(80) == "B"
    assert report._quality_tier(79) == "C+"
    assert report._quality_tier(70) == "C+"
    assert report._quality_tier(69) == "C"
    assert report._quality_tier(60) == "C"
    assert report._quality_tier(59) == "D"
    assert report._quality_tier(40) == "D"
    assert report._quality_tier(39) == "F"
    assert report._quality_tier(0) == "F"


def test_generate_static_deep_audit_exports_quality_and_gap_signals(
    tmp_path: Path,
    monkeypatch,
) -> None:
    session_stamp = "20260615-rdb-full"
    data_dir = tmp_path / "data"
    output_root = tmp_path / "output"
    output_dir = output_root / "audit" / "static_deep_audit" / "smoke"
    archive_dir = data_dir / "static_analysis" / "reports" / "archive" / session_stamp
    archive_dir.mkdir(parents=True)
    output_dir.mkdir(parents=True)

    run_health = {
        "workflow_completion_status": "complete",
        "final_run_status": "complete",
        "detector_posture": "policy_or_finding_gates",
        "finding_fidelity_status": "complete",
        "run_rollups": {
            "findings_runtime_total": 140,
            "findings_persisted_db_total": 132,
            "findings_capped_not_persisted_total": 8,
            "p0_runtime_findings_total": 10,
            "p0_persisted_db_findings_total": 8,
            "p0_capped_not_persisted_total": 2,
            "db_persistence_status": "ok",
        },
    }
    run_health_packages = {
        "com.example.healthy": {
            "display_name": "Healthy App",
            "runtime_findings": 40,
            "persisted_findings_db": 40,
            "capped_not_persisted": 0,
            "artifact_count": 3,
            "final_status": "complete",
            "workflow_completion_status": "complete",
            "db_persistence_status": "ok",
            "detector_posture": "clean",
            "finding_fidelity_status": "complete",
            "detector_warnings_agg": 0,
            "detector_failures_agg": 0,
            "detector_errors_agg": 0,
        },
        "com.example.problem": {
            "display_name": "Problem App",
            "runtime_findings": 100,
            "persisted_findings_db": 92,
            "capped_not_persisted": 8,
            "artifact_count": 12,
            "final_status": "partial",
            "workflow_completion_status": "complete",
            "db_persistence_status": "ok",
            "detector_posture": "policy_or_finding_gates",
            "finding_fidelity_status": "capped",
            "detector_warnings_agg": 7,
            "detector_failures_agg": 3,
            "detector_errors_agg": 0,
        },
    }

    db_state = {
        "db_name": "scytaledroid_core_prod",
    }
    db_package_rows = {
        "com.example.healthy": {
            "static_run_id": 4001,
            "display_name": "Healthy App",
            "profile_key": "NEWS",
            "persisted_findings_db": 40,
            "handoff_ready": 1,
            "permission_rows": 15,
            "string_summary_rows": 1,
            "string_sample_rows": 4,
            "correlation_rows": 5,
            "schema_version": "0.3.7",
            "tool_semver": "2.2.1",
            "tool_git_commit": "abc123",
        },
        "com.example.problem": {
            "static_run_id": 4002,
            "display_name": "Problem App",
            "profile_key": "SOCIAL",
            "persisted_findings_db": 92,
            "handoff_ready": 0,
            "permission_rows": 25,
            "string_summary_rows": 1,
            "string_sample_rows": 0,
            "correlation_rows": 0,
            "schema_version": "0.3.7",
            "tool_semver": "2.2.1",
            "tool_git_commit": "abc123",
        },
    }
    session_header = {
        "session_status": "COMPLETED",
        "session_disposition": "completed_profile_session",
        "health_class": "healthy",
        "usability_class": "usable",
        "schema_version": "0.3.7",
        "total_run_count": 2,
        "completed_run_count": 2,
        "session_link_rows": 2,
        "rollup_rows": 1,
    }
    report_rows = [
        {
            "package_name": "com.example.healthy",
            "is_split": 0,
            "duration_seconds": 2.5,
            "artifact_total_wall_s": 2.7,
            "string_index_seconds": 0.5,
            "hash_seconds": 0.1,
            "resource_fallback_used": 0,
            "resource_bounds_warning": 0,
            "label_parse_signal": 0,
            "finding_failure_count": 0,
            "policy_failure_count": 0,
            "execution_error_count": 0,
            "warning_stage_count": 0,
        },
        {
            "package_name": "com.example.healthy",
            "is_split": 1,
            "duration_seconds": 1.5,
            "artifact_total_wall_s": 1.7,
            "string_index_seconds": 0.0,
            "hash_seconds": 0.1,
            "resource_fallback_used": 0,
            "resource_bounds_warning": 0,
            "label_parse_signal": 0,
            "finding_failure_count": 0,
            "policy_failure_count": 0,
            "execution_error_count": 0,
            "warning_stage_count": 0,
        },
        {
            "package_name": "com.example.problem",
            "is_split": 0,
            "duration_seconds": 12.0,
            "artifact_total_wall_s": 20.0,
            "string_index_seconds": 5.0,
            "hash_seconds": 0.2,
            "resource_fallback_used": 0,
            "resource_bounds_warning": 0,
            "label_parse_signal": 0,
            "finding_failure_count": 1,
            "policy_failure_count": 1,
            "execution_error_count": 0,
            "warning_stage_count": 2,
        },
    ] + [
        {
            "package_name": "com.example.problem",
            "is_split": 1,
            "duration_seconds": 5.0,
            "artifact_total_wall_s": 8.0,
            "string_index_seconds": 1.5,
            "hash_seconds": 0.1,
            "resource_fallback_used": 0,
            "resource_bounds_warning": 0,
            "label_parse_signal": 0,
            "finding_failure_count": 0,
            "policy_failure_count": 0,
            "execution_error_count": 0,
            "warning_stage_count": 1,
        }
        for _ in range(6)
    ]
    perf_meta = {
        "warnings": [],
        "detector_stage_rows": [
            {
                "package_name": "com.example.healthy",
                "detector_id": "correlation_engine",
                "duration_sec": 1.0,
            },
            {
                "package_name": "com.example.problem",
                "detector_id": "secrets_credentials",
                "duration_sec": 10.0,
            },
            {
                "package_name": "com.example.problem",
                "detector_id": "integrity_identity",
                "duration_sec": 3.0,
            },
        ],
    }
    dynamic_bridge = {
        "com.example.healthy": {
            "linked_dynamic_run_count": 2,
            "linked_dynamic_valid_run_count": 2,
            "corroborated_dynamic_run_count": 1,
            "timeline_run_count": 1,
            "timeline_complete_run_count": 1,
            "average_overlap_ratio": 0.25,
        },
        "com.example.problem": {
            "linked_dynamic_run_count": 0,
            "linked_dynamic_valid_run_count": 0,
            "corroborated_dynamic_run_count": 0,
            "timeline_run_count": 0,
            "timeline_complete_run_count": 0,
            "average_overlap_ratio": None,
        },
    }

    monkeypatch.setattr(report, "_load_run_health", lambda *_args, **_kwargs: (run_health, run_health_packages, []))
    monkeypatch.setattr(report, "_load_optional_db", lambda *_args, **_kwargs: (db_state, []))
    monkeypatch.setattr(report, "_load_session_header", lambda *_args, **_kwargs: (session_header, []))
    monkeypatch.setattr(report, "_load_db_package_rows", lambda *_args, **_kwargs: (db_package_rows, []))
    monkeypatch.setattr(report, "_load_report_rows", lambda *_args, **_kwargs: (report_rows, perf_meta))
    monkeypatch.setattr(report, "_collect_dynamic_bridge", lambda **_kwargs: dynamic_bridge)

    summary = report.generate_static_deep_audit(
        session_stamp=session_stamp,
        data_dir=data_dir,
        output_root=output_root,
        output_dir=output_dir,
    )

    assert summary["package_count"] == 2
    assert summary["packages_with_handoff_ready"] == 1
    assert summary["packages_with_dynamic_bridge"] == 1
    assert summary["packages_with_capped_findings"] == 1
    assert summary["readiness_tier_counts"]["paper_ready"] == 1
    assert summary["readiness_tier_counts"]["incomplete_or_contract_gap"] == 1
    assert summary["top_recommended_actions"]["ready_for_paper_use"] == 1
    assert summary["top_recommended_actions"]["repair_static_handoff_contract"] == 1
    assert summary["pattern_flag_counts"]["split_heavy"] == 1
    assert summary["pattern_flag_counts"]["handoff_gap"] == 1
    assert "static_hidden_pattern_candidates.csv" in summary["output_files"]

    run_rows = list(csv.DictReader((output_dir / "run_evidence_quality.csv").open(encoding="utf-8")))
    assert len(run_rows) == 2
    by_package = {row["package_name"]: row for row in run_rows}
    assert by_package["com.example.healthy"]["recommended_action"] == "ready_for_paper_use"
    assert by_package["com.example.problem"]["recommended_action"] == "repair_static_handoff_contract"
    assert by_package["com.example.problem"]["split_report_count"] == "6"
    assert by_package["com.example.healthy"]["linked_dynamic_run_count"] == "2"
    assert by_package["com.example.healthy"]["dynamic_bridge_state"] == "corroborated"
    assert by_package["com.example.problem"]["dynamic_bridge_state"] == "no_dynamic_runs"
    assert by_package["com.example.problem"]["penalty_reasons"]

    hotspot_rows = list(csv.DictReader((output_dir / "split_performance_hotspots.csv").open(encoding="utf-8")))
    assert len(hotspot_rows) == 1
    assert hotspot_rows[0]["package_name"] == "com.example.problem"

    pattern_rows = list(csv.DictReader((output_dir / "paper_pattern_matrix.csv").open(encoding="utf-8")))
    problem_pattern = next(row for row in pattern_rows if row["package_name"] == "com.example.problem")
    assert problem_pattern["split_heavy_flag"] == "1"
    assert problem_pattern["handoff_gap_flag"] == "1"

    hidden_pattern_rows = list(csv.DictReader((output_dir / "static_hidden_pattern_candidates.csv").open(encoding="utf-8")))
    hidden_problem = next(row for row in hidden_pattern_rows if row["package_name"] == "com.example.problem")
    assert hidden_problem["research_pattern"] == "high_static_surface_without_dynamic_collection"

    actions = json.loads((output_dir / "recommended_next_actions.json").read_text(encoding="utf-8"))
    assert actions["top_recommended_actions"]["ready_for_paper_use"] == 1
    assert actions["top_recommended_actions"]["repair_static_handoff_contract"] == 1
