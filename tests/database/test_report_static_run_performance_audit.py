from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_static_run_performance_audit as report


def _report_payload(
    *,
    package_name: str,
    app_label: str,
    sha256: str,
    session_stamp: str,
    generated_at: str,
    artifact: str = "base",
    is_split: bool = False,
    total_duration_sec: float | None = 4.0,
    findings: list[dict[str, object]] | None = None,
    detector_rows: list[dict[str, object]] | None = None,
    parse_flags: dict[str, object] | None = None,
    detector_metrics: dict[str, object] | None = None,
    receipt_path: str | None = None,
    harvest_manifest_path: str | None = None,
    artifact_total_wall_s: float | None = None,
    hash_seconds: float | None = None,
    string_index_seconds: float | None = None,
    correlation_runtime_stats: dict[str, int] | None = None,
) -> dict[str, object]:
    detector_rows = detector_rows or [
        {
            "detector_id": "correlation_engine",
            "section_key": "correlation_findings",
            "status": "WARN" if findings else "OK",
            "duration_sec": 3.5,
            "metrics": {"policy_gate": False},
            "findings": [],
        },
        {
            "detector_id": "integrity_identity",
            "section_key": "integrity",
            "status": "OK",
            "duration_sec": 0.5,
            "metrics": {},
            "findings": [],
        },
    ]
    findings = findings or []
    status_counts = {"OK": 1, "WARN": 1 if findings else 0}
    payload: dict[str, object] = {
        "generated_at": generated_at,
        "findings": findings,
        "detector_results": detector_rows,
        "detector_metrics": detector_metrics or {},
        "metadata": {
            "package_name": package_name,
            "normalized_package_name": package_name,
            "app_label": app_label,
            "artifact": artifact,
            "artifact_kind": "apk",
            "is_split_member": is_split,
            "base_apk_sha256": sha256 if not is_split else "aa" * 32,
            "apk_set_id": 1,
            "session_stamp": session_stamp,
            "receipt_path": receipt_path,
            "harvest_manifest_path": harvest_manifest_path,
            "research_usable": True,
            "artifact_total_wall_s": artifact_total_wall_s,
            "hash_seconds": hash_seconds,
            "string_index_seconds": string_index_seconds,
            "correlation_runtime_stats": correlation_runtime_stats or {},
            "pipeline_summary": {
                "detector_total": len(detector_rows),
                "detector_executed": len(detector_rows),
                "detector_skipped": 0,
                "status_counts": {k: v for k, v in status_counts.items() if v},
                "total_findings": len(findings),
                "total_duration_sec": total_duration_sec,
                "finding_fail_count": 1
                if any(
                    row.get("status") == "FAIL"
                    and not (row.get("metrics") or {}).get("policy_gate")
                    for row in detector_rows
                )
                else 0,
                "finding_fail_detectors": [
                    {"detector": row.get("detector_id"), "section": row.get("section_key")}
                    for row in detector_rows
                    if row.get("status") == "FAIL"
                    and not (row.get("metrics") or {}).get("policy_gate")
                ],
                "policy_fail_count": 1
                if any(
                    row.get("status") == "FAIL" and (row.get("metrics") or {}).get("policy_gate")
                    for row in detector_rows
                )
                else 0,
                "policy_fail_detectors": [
                    {"detector": row.get("detector_id"), "section": row.get("section_key")}
                    for row in detector_rows
                    if row.get("status") == "FAIL" and (row.get("metrics") or {}).get("policy_gate")
                ],
                "error_count": 1
                if any(row.get("status") == "ERROR" for row in detector_rows)
                else 0,
                "error_detectors": [
                    {
                        "detector": row.get("detector_id"),
                        "section": row.get("section_key"),
                        "reason": "boom",
                    }
                    for row in detector_rows
                    if row.get("status") == "ERROR"
                ],
                "slowest_detectors": [
                    {
                        "detector": "correlation_engine",
                        "section": "correlation_findings",
                        "duration_sec": 3.5,
                    }
                ],
            },
            **(parse_flags or {}),
        },
    }
    return payload


def _receipt_payload(
    *,
    package_name: str,
    session_label: str,
    app_label: str,
    apk_paths: list[str],
    capture_status: str = "clean",
) -> dict[str, object]:
    return {
        "package": {
            "package_name": package_name,
            "app_label": app_label,
            "session_label": session_label,
            "snapshot_id": 1,
            "version_code": "1",
            "version_name": "1.0",
        },
        "inventory": {
            "primary_path": apk_paths[0],
            "apk_paths": apk_paths,
            "split_count": len(apk_paths),
        },
        "status": {
            "capture_status": capture_status,
            "research_status": "pending_audit",
        },
    }


def test_help_is_safe_without_pythonpath() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_static_run_performance_audit.py"
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
    assert "--session-stamp" in out
    assert "static-session performance" in out


def test_build_recommendation_is_conservative_when_timing_missing() -> None:
    rec = report._build_recommendation(
        report_rows=[{"is_split": 0, "duration_seconds": None}],
        package_rows=[],
        detector_rows=[],
    )
    assert rec["recommended_action"] == "collect_more_timing_data_first"


def test_main_generates_expected_output_bundle_for_incomplete_session(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scytaledroid.Config import app_config

    repo_root = tmp_path / "repo"
    data_root = repo_root / "data"
    output_root = repo_root / "output"
    session_stamp = "20260613-all-full"
    harvest_session = "RUN-XYZ"
    archive_dir = data_root / "static_analysis" / "reports" / "archive" / session_stamp
    receipts_dir = data_root / "receipts" / "harvest" / harvest_session
    logs_dir = repo_root / "logs"
    archive_dir.mkdir(parents=True)
    receipts_dir.mkdir(parents=True)
    logs_dir.mkdir(parents=True)

    sha_base = "11" * 32
    base_report = _report_payload(
        package_name="com.example.heavy",
        app_label="Heavy App",
        sha256=sha_base,
        session_stamp=session_stamp,
        generated_at="2026-06-13T16:30:00Z",
        artifact_total_wall_s=7.25,
        hash_seconds=0.35,
        string_index_seconds=0.8,
        correlation_runtime_stats={
            "historical_package_reports_cache_hits": 1,
            "historical_package_reports_cache_misses": 1,
            "previous_network_snapshot_cache_hits": 2,
            "previous_network_snapshot_cache_misses": 1,
        },
        receipt_path=f"data/receipts/harvest/{harvest_session}/com.example.heavy.json",
        harvest_manifest_path=f"data/device_apks/SER/runs/{harvest_session}/com.example.heavy/harvest_package_manifest.json",
        findings=[{"finding_id": "base_only", "title": "Base finding"}],
        detector_metrics={"permissions_profile": {"total_declared": 3}},
    )
    split_report_a = _report_payload(
        package_name="com.example.heavy",
        app_label="Heavy App",
        sha256="22" * 32,
        session_stamp=session_stamp,
        generated_at="2026-06-13T16:30:10Z",
        artifact="split_config.en",
        is_split=True,
        total_duration_sec=6.0,
        artifact_total_wall_s=6.4,
        hash_seconds=0.28,
        string_index_seconds=0.0,
        correlation_runtime_stats={
            "split_related_reports_cache_hits": 1,
            "split_related_group_cache_hits": 1,
        },
        findings=[{"finding_id": "split_only", "title": "Split finding"}],
        detector_metrics={
            "ipc_components": {"components_total": 2, "providers": 1},
            "permissions_profile": {"total_declared": 1},
        },
    )
    split_report_b = _report_payload(
        package_name="com.example.heavy",
        app_label="Heavy App",
        sha256="33" * 32,
        session_stamp=session_stamp,
        generated_at="2026-06-13T16:30:20Z",
        artifact="split_config.xhdpi",
        is_split=True,
        total_duration_sec=5.5,
        artifact_total_wall_s=5.9,
        hash_seconds=0.26,
        string_index_seconds=0.0,
        correlation_runtime_stats={
            "split_related_reports_cache_hits": 1,
            "split_related_group_cache_hits": 1,
            "previous_network_snapshot_cache_hits": 2,
        },
        findings=[{"finding_id": "split_only_2", "title": "Split finding 2"}],
        parse_flags={
            "resource_bounds_warnings": ["Count: 65536"],
            "parser_provenance": {
                "resource_parse_partial": True,
                "resource_reparse_candidate": True,
            },
        },
        detector_metrics={"dfir_hints": {"path_hint_count": 2}},
    )
    detector_rows = [
        {
            "detector_id": "crypto_hygiene",
            "section_key": "crypto_hygiene",
            "status": "FAIL",
            "duration_sec": 0.8,
            "metrics": {"policy_gate": False},
            "findings": [],
        },
        {
            "detector_id": "correlation_engine",
            "section_key": "correlation_findings",
            "status": "OK",
            "duration_sec": 4.0,
            "metrics": {"policy_gate": False},
            "findings": [],
        },
    ]
    light_report = _report_payload(
        package_name="com.example.light",
        app_label="Light App",
        sha256="44" * 32,
        session_stamp=session_stamp,
        generated_at="2026-06-13T16:31:00Z",
        total_duration_sec=2.0,
        artifact_total_wall_s=2.4,
        hash_seconds=0.15,
        string_index_seconds=0.4,
        findings=[{"finding_id": "light_only", "title": "Light finding"}],
        detector_rows=detector_rows,
        receipt_path=f"data/receipts/harvest/{harvest_session}/com.example.light.json",
    )

    reports = [base_report, split_report_a, split_report_b, light_report]
    for idx, payload in enumerate(reports, start=1):
        (archive_dir / f"report-{idx}.json").write_text(json.dumps(payload), encoding="utf-8")

    (receipts_dir / "com.example.heavy.json").write_text(
        json.dumps(
            _receipt_payload(
                package_name="com.example.heavy",
                session_label=harvest_session,
                app_label="Heavy App",
                apk_paths=["/data/app/base.apk", "/data/app/split_a.apk", "/data/app/split_b.apk"],
            )
        ),
        encoding="utf-8",
    )
    (receipts_dir / "com.example.light.json").write_text(
        json.dumps(
            _receipt_payload(
                package_name="com.example.light",
                session_label=harvest_session,
                app_label="Light App",
                apk_paths=["/data/app/light.apk"],
            )
        ),
        encoding="utf-8",
    )
    (receipts_dir / "com.example.blocked.json").write_text(
        json.dumps(
            _receipt_payload(
                package_name="com.example.blocked",
                session_label=harvest_session,
                app_label="Blocked App",
                apk_paths=["/system/app/blocked.apk"],
                capture_status="failed",
            )
        ),
        encoding="utf-8",
    )

    (logs_dir / "static_analysis.log").write_text(
        "[2026-06-13 13:56:37] [INFO] [static] Static persistence app finalized | app_index=1, app_label=Heavy App, app_total=2, event=persist.app, package_name=com.example.heavy, profile=Full, session_stamp=20260613-all-full, static_run_id=3514\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(app_config, "DATA_DIR", str(data_root))
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(output_root))
    monkeypatch.setattr(report, "_REPO_ROOT", repo_root)
    monkeypatch.setattr(
        report,
        "_init_optional_db",
        lambda session: (
            {
                "db_name": "scytaledroid_core_prod",
                "static_run_rows": 2,
                "completed_run_rows": 1,
                "started_run_rows": 1,
                "failed_run_rows": 0,
                "status_breakdown": {"COMPLETED": 1, "STARTED": 1},
                "finding_rows": 12,
                "permission_matrix_rows": 3,
                "string_summary_rows": 2,
                "string_sample_rows": 4,
                "session_rollup_rows": 0,
            },
            [],
        ),
    )

    out_dir = output_root / "audit" / "static_run_performance" / "smoke"
    rc = report.main(["--session-stamp", session_stamp, "--output-dir", str(out_dir)])

    assert rc == 0
    for name in report.OUTPUT_FILES:
        assert (out_dir / name).exists(), name

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["session_stamp"] == session_stamp
    assert summary["archive_report_count"] == 4
    assert summary["expected_packages_from_harvest"] == 2
    assert summary["expected_apk_artifacts_from_harvest"] == 4
    assert summary["blocked_packages_from_harvest"] == 1
    assert summary["session_state"] == "artifact_archive_complete_db_persistence_in_progress"
    assert summary["artifact_finding_failure_events"] == 1
    assert summary["artifact_execution_error_events"] == 0
    assert summary["artifact_wall_clock_available_count"] == 4
    assert summary["resource_parse_partial_artifacts"] == 1
    assert summary["resource_reparse_candidate_artifacts"] == 1
    assert summary["timing_contract"]["artifact_wall_clock_available"] is True
    assert summary["timing_breakdown"]["artifact_wall_clock_total_sec"] == 21.95
    assert summary["timing_breakdown"]["hash_total_sec"] == 1.04
    assert summary["timing_breakdown"]["string_index_total_sec"] == 1.2
    assert summary["correlation_runtime_cache"]["total_hits"] == 9
    assert summary["correlation_runtime_cache"]["total_misses"] == 2
    assert summary["worker_model"]["package_loop_serial"] is True
    assert summary["no_db_writes"] is True
    assert "risk" not in (out_dir / "summary.json").read_text(encoding="utf-8").lower()

    split_rows = list(csv.DictReader((out_dir / "split_heavy_packages.csv").open()))
    assert split_rows[0]["package_name"] == "com.example.heavy"
    assert split_rows[0]["split_artifacts"] == "2"

    artifact_rows = list(csv.DictReader((out_dir / "apk_artifact_runtime_summary.csv").open()))
    heavy_base = next(
        row
        for row in artifact_rows
        if row["package_name"] == "com.example.heavy" and row["artifact_name"] == "base"
    )
    assert heavy_base["artifact_total_wall_s"] == "7.25"
    assert heavy_base["hash_seconds"] == "0.35"
    assert heavy_base["correlation_cache_hits"] == "3"

    evidence_rows = list(csv.DictReader((out_dir / "base_vs_split_evidence_summary.csv").open()))
    heavy = next(row for row in evidence_rows if row["package_name"] == "com.example.heavy")
    assert heavy["split_only_finding_ids_count"] == "2"
    assert heavy["split_component_metric_artifacts"] == "1"

    package_rows = list(csv.DictReader((out_dir / "package_runtime_summary.csv").open()))
    heavy_pkg = next(row for row in package_rows if row["package_name"] == "com.example.heavy")
    assert heavy_pkg["artifact_total_wall_s_sum"] == "19.55"
    assert heavy_pkg["hash_seconds_sum"] == "0.89"
    assert heavy_pkg["correlation_cache_hits"] == "9"

    parse_rows = list(csv.DictReader((out_dir / "parse_signal_summary.csv").open()))
    heavy_parse = next(row for row in parse_rows if row["package_name"] == "com.example.heavy")
    assert heavy_parse["resource_bounds_warning_artifacts"] == "1"
    assert heavy_parse["resource_parse_partial_artifacts"] == "1"
    assert heavy_parse["resource_reparse_candidate_artifacts"] == "1"

    detector_rows_csv = list(csv.DictReader((out_dir / "detector_stage_summary.csv").open()))
    assert any(row["detector_id"] == "correlation_engine" for row in detector_rows_csv)

    failure_rows = list(csv.DictReader((out_dir / "finding_failure_summary.csv").open()))
    assert any(row["detector_id"] == "crypto_hygiene" for row in failure_rows)

    recommendation = json.loads(
        (out_dir / "static_performance_recommendations.json").read_text(encoding="utf-8")
    )
    assert recommendation["recommended_action"] in {
        "optimize_detector_stage_timing_first",
        "add_selective_split_scan_profile",
        "keep_full_split_scan_default",
    }
