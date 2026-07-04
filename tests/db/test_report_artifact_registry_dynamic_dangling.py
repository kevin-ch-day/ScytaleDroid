from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Database.db_utils.artifact_registry_dynamic_dangling import (
    collect_artifact_registry_dynamic_dangling_report,
    write_artifact_registry_dynamic_dangling_bundle,
)


def test_help_is_safe_without_pythonpath(assert_safe_script_help) -> None:
    out = assert_safe_script_help("scripts/db/report_artifact_registry_dynamic_dangling.py").lower()
    assert out.startswith("usage:")
    assert "dangling dynamic" in out
    assert "--output-dir" in out


def test_collect_dynamic_dangling_report_classifies_rows(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    existing = repo_root / "output" / "evidence" / "dynamic" / "run-2" / "artifact.json"
    existing.parent.mkdir(parents=True)
    existing.write_text("ok", encoding="utf-8")

    def fake_run_sql(
        sql: str,
        params: tuple[object, ...] | tuple[()] = (),
        *,
        fetch: str = "all",
        dictionary: bool = False,
        query_name: str | None = None,
    ):
        del sql, params, fetch, dictionary
        if query_name == "artifact_registry_dynamic_dangling.schema_inventory":
            return [
                {
                    "table_name": "dynamic_sessions",
                    "column_name": "dynamic_run_id",
                    "column_type": "char(36)",
                },
                {
                    "table_name": "dynamic_sessions",
                    "column_name": "evidence_path",
                    "column_type": "text",
                },
                {
                    "table_name": "analysis_cohort_runs",
                    "column_name": "dynamic_run_id",
                    "column_type": "char(36)",
                },
                {
                    "table_name": "analysis_cohort_runs",
                    "column_name": "static_run_id",
                    "column_type": "bigint(20)",
                },
                {
                    "table_name": "ml_feature_windows",
                    "column_name": "run_id",
                    "column_type": "varchar(64)",
                },
            ]
        if query_name == "artifact_registry_dynamic_dangling.dynamic_totals":
            return {"linked_dynamic_registry_rows": 10, "dangling_dynamic_registry_rows": 3}
        if query_name == "artifact_registry_dynamic_dangling.dangling_rows":
            return [
                {
                    "artifact_id": 1,
                    "run_type": "dynamic",
                    "run_id": "11111111-1111-4111-8111-111111111111",
                    "dynamic_run_id": "11111111-1111-4111-8111-111111111111",
                    "resolved_dynamic_run_id": "11111111-1111-4111-8111-111111111111",
                    "link_state": "dangling_dynamic_run",
                    "linkage_resolution_path": "typed_dynamic",
                    "artifact_type": "dynamic_run_manifest",
                    "host_path": str(repo_root / "missing" / "one.json"),
                    "created_at_utc": "2026-02-08 01:00:00",
                    "status_reason": None,
                    "meta_package_name": None,
                    "meta_static_run_id": None,
                    "meta_static_handoff_hash": None,
                    "meta_base_apk_sha256": None,
                    "has_dynamic_session": 0,
                    "has_analysis_cohort_run": 0,
                    "has_analysis_dynamic_status": 0,
                    "has_dynamic_network_features": 0,
                    "has_dynamic_network_indicators": 0,
                    "has_dynamic_session_issues": 0,
                    "has_dynamic_telemetry_network": 0,
                    "has_dynamic_telemetry_process": 0,
                    "has_ml_feature_windows": 0,
                    "has_ml_scores": 0,
                },
                {
                    "artifact_id": 2,
                    "run_type": "dynamic",
                    "run_id": "22222222-2222-4222-8222-222222222222",
                    "dynamic_run_id": "22222222-2222-4222-8222-222222222222",
                    "resolved_dynamic_run_id": "22222222-2222-4222-8222-222222222222",
                    "link_state": "dangling_dynamic_run",
                    "linkage_resolution_path": "typed_dynamic",
                    "artifact_type": "pcap_report",
                    "host_path": str(existing),
                    "created_at_utc": "2026-06-14 00:00:00",
                    "status_reason": None,
                    "meta_package_name": None,
                    "meta_static_run_id": None,
                    "meta_static_handoff_hash": None,
                    "meta_base_apk_sha256": None,
                    "has_dynamic_session": 0,
                    "has_analysis_cohort_run": 0,
                    "has_analysis_dynamic_status": 0,
                    "has_dynamic_network_features": 0,
                    "has_dynamic_network_indicators": 0,
                    "has_dynamic_session_issues": 0,
                    "has_dynamic_telemetry_network": 0,
                    "has_dynamic_telemetry_process": 0,
                    "has_ml_feature_windows": 0,
                    "has_ml_scores": 0,
                },
                {
                    "artifact_id": 3,
                    "run_type": "dynamic",
                    "run_id": "bad-run-id",
                    "dynamic_run_id": "bad-run-id",
                    "resolved_dynamic_run_id": "bad-run-id",
                    "link_state": "dangling_dynamic_run",
                    "linkage_resolution_path": "typed_dynamic",
                    "artifact_type": "analysis_summary_json",
                    "host_path": str(repo_root / "missing" / "three.json"),
                    "created_at_utc": "2026-06-14 00:00:00",
                    "status_reason": "legacy",
                    "meta_package_name": None,
                    "meta_static_run_id": None,
                    "meta_static_handoff_hash": None,
                    "meta_base_apk_sha256": None,
                    "has_dynamic_session": 0,
                    "has_analysis_cohort_run": 1,
                    "has_analysis_dynamic_status": 0,
                    "has_dynamic_network_features": 0,
                    "has_dynamic_network_indicators": 0,
                    "has_dynamic_session_issues": 0,
                    "has_dynamic_telemetry_network": 0,
                    "has_dynamic_telemetry_process": 0,
                    "has_ml_feature_windows": 0,
                    "has_ml_scores": 0,
                },
            ]
        raise AssertionError(f"unexpected query_name: {query_name}")

    report = collect_artifact_registry_dynamic_dangling_report(fake_run_sql, repo_root=repo_root)
    summary = report["summary"]
    assert summary["dangling_dynamic_registry_rows"] == 3
    assert summary["linked_dynamic_registry_rows"] == 10
    assert summary["primary_reason_counts"] == {
        "malformed_dynamic_run_id": 1,
        "partially_linked": 1,
        "truly_detached": 1,
    }
    assert summary["reason_flag_counts"]["missing_dynamic_session"] == 3
    assert summary["reason_flag_counts"]["missing_evidence_file"] == 2
    assert summary["reason_flag_counts"]["evidence_file_exists_but_db_detached"] == 1
    assert summary["reason_flag_counts"]["db_reference_exists_but_file_missing"] == 1
    assert summary["reason_flag_counts"]["malformed_dynamic_run_id"] == 1
    rows = report["dynamic_dangling_rows"]
    assert rows[0]["primary_reason"] == "truly_detached"
    assert rows[1]["primary_reason"] == "partially_linked"
    assert rows[2]["primary_reason"] == "malformed_dynamic_run_id"


def test_write_dynamic_dangling_bundle_writes_expected_files(tmp_path: Path) -> None:
    report = {
        "summary": {"dangling_dynamic_registry_rows": 1, "linked_dynamic_registry_rows": 0},
        "dynamic_schema_inventory": [{"table_name": "dynamic_sessions"}],
        "dynamic_dangling_rows": [{"artifact_id": 1, "primary_reason": "truly_detached"}],
        "dynamic_dangling_runs": [{"resolved_dynamic_run_id": "run-1", "row_count": 1}],
        "dynamic_dangling_reason_counts": [{"reason_bucket": "truly_detached", "count": 1}],
        "dynamic_dangling_reason_samples": [{"reason_bucket": "truly_detached", "artifact_id": 1}],
    }
    out_dir = tmp_path / "audit"
    files = write_artifact_registry_dynamic_dangling_bundle(report, out_dir)
    names = {path.name for path in files}
    assert "summary.json" in names
    assert "dynamic_dangling_rows.csv" in names
    payload = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert payload["dangling_dynamic_registry_rows"] == 1
