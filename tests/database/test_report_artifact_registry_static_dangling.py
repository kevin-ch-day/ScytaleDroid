from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Database.db_utils.artifact_registry_static_dangling import (
    collect_artifact_registry_static_dangling_report,
    write_artifact_registry_static_dangling_bundle,
)


def test_collect_static_dangling_report_classifies_rows(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    existing = repo_root / "data" / "static_analysis" / "baseline" / "pkg-a.json"
    existing.parent.mkdir(parents=True)
    existing.write_text("ok", encoding="utf-8")
    evidence = repo_root / "evidence" / "static_runs" / "103" / "run_manifest.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text(
        json.dumps(
            {
                "package_name": "pkg.four",
                "display_name": "Pkg Four",
                "version_name": "1.2.3",
                "version_code": "123",
                "profile_key": "Full",
            }
        ),
        encoding="utf-8",
    )

    def fake_run_sql(
        sql: str,
        params: tuple[object, ...] | tuple[()] = (),
        *,
        fetch: str = "all",
        dictionary: bool = False,
        query_name: str | None = None,
    ):
        del sql, params, fetch, dictionary
        if query_name == "artifact_registry_static_dangling.schema_inventory":
            return [
                {
                    "table_name": "static_analysis_runs",
                    "column_name": "id",
                    "column_type": "bigint(20) unsigned",
                },
                {
                    "table_name": "static_analysis_runs",
                    "column_name": "session_stamp",
                    "column_type": "varchar(128)",
                },
                {
                    "table_name": "static_session_run_links",
                    "column_name": "static_run_id",
                    "column_type": "bigint(20) unsigned",
                },
                {
                    "table_name": "static_analysis_findings",
                    "column_name": "run_id",
                    "column_type": "bigint(20) unsigned",
                },
                {
                    "table_name": "static_permission_matrix",
                    "column_name": "run_id",
                    "column_type": "bigint(20) unsigned",
                },
                {
                    "table_name": "runs",
                    "column_name": "run_id",
                    "column_type": "bigint(20) unsigned",
                },
            ]
        if query_name == "artifact_registry_static_dangling.static_totals":
            return {"linked_static_registry_rows": 50, "dangling_static_registry_rows": 4}
        if query_name == "artifact_registry_static_dangling.dangling_rows":
            return [
                {
                    "artifact_id": 1,
                    "run_type": "static",
                    "run_id": "101",
                    "static_run_id": 101,
                    "resolved_static_run_id": 101,
                    "link_state": "dangling_static_run",
                    "linkage_resolution_path": "typed_static",
                    "artifact_type": "static_report",
                    "origin": "host",
                    "host_path": str(repo_root / "missing" / "report.json"),
                    "created_at_utc": "2026-02-08 01:00:00",
                    "status_reason": None,
                    "meta_package_name": "pkg.one",
                    "meta_session_stamp": None,
                    "meta_session_label": None,
                    "has_static_session_run_link": 0,
                    "has_static_analysis_findings": 0,
                    "has_static_permission_matrix": 0,
                    "has_static_string_summary": 0,
                    "has_static_findings_summary": 0,
                    "has_permission_audit_snapshot": 0,
                    "has_legacy_runs": 0,
                },
                {
                    "artifact_id": 2,
                    "run_type": "static",
                    "run_id": "102",
                    "static_run_id": 102,
                    "resolved_static_run_id": 102,
                    "link_state": "dangling_static_run",
                    "linkage_resolution_path": "typed_static",
                    "artifact_type": "static_baseline_json",
                    "origin": "host",
                    "host_path": str(existing),
                    "created_at_utc": "2026-06-14 00:00:00",
                    "status_reason": None,
                    "meta_package_name": "pkg.two",
                    "meta_session_stamp": None,
                    "meta_session_label": None,
                    "has_static_session_run_link": 0,
                    "has_static_analysis_findings": 0,
                    "has_static_permission_matrix": 0,
                    "has_static_string_summary": 0,
                    "has_static_findings_summary": 0,
                    "has_permission_audit_snapshot": 0,
                    "has_legacy_runs": 1,
                },
                {
                    "artifact_id": 3,
                    "run_type": "static",
                    "run_id": "bad-run-id",
                    "static_run_id": None,
                    "resolved_static_run_id": None,
                    "link_state": "dangling_static_run",
                    "linkage_resolution_path": "legacy_static_untyped",
                    "artifact_type": "static_run_manifest",
                    "origin": "unknown",
                    "host_path": str(evidence),
                    "created_at_utc": "2026-06-14 00:00:00",
                    "status_reason": "legacy",
                    "meta_package_name": None,
                    "meta_session_stamp": None,
                    "meta_session_label": None,
                    "has_static_session_run_link": 0,
                    "has_static_analysis_findings": 0,
                    "has_static_permission_matrix": 0,
                    "has_static_string_summary": 0,
                    "has_static_findings_summary": 0,
                    "has_permission_audit_snapshot": 0,
                    "has_legacy_runs": 0,
                },
                {
                    "artifact_id": 4,
                    "run_type": "static",
                    "run_id": "103",
                    "static_run_id": 103,
                    "resolved_static_run_id": 103,
                    "link_state": "dangling_static_run",
                    "linkage_resolution_path": "typed_static",
                    "artifact_type": "manifest_evidence",
                    "origin": "host",
                    "host_path": str(evidence),
                    "created_at_utc": "2026-06-14 00:00:00",
                    "status_reason": None,
                    "meta_package_name": "pkg.four",
                    "meta_session_stamp": None,
                    "meta_session_label": None,
                    "has_static_session_run_link": 1,
                    "has_static_analysis_findings": 0,
                    "has_static_permission_matrix": 0,
                    "has_static_string_summary": 0,
                    "has_static_findings_summary": 0,
                    "has_permission_audit_snapshot": 0,
                    "has_legacy_runs": 0,
                },
            ]
        raise AssertionError(f"unexpected query_name: {query_name}")

    report = collect_artifact_registry_static_dangling_report(fake_run_sql, repo_root=repo_root)
    summary = report["summary"]
    assert summary["dangling_static_registry_rows"] == 4
    assert summary["linked_static_registry_rows"] == 50
    assert summary["primary_reason_counts"] == {
        "canonical_db_residue": 1,
        "legacy_mirror_only_with_file": 1,
        "malformed_static_run_id": 1,
        "truly_detached": 1,
    }
    assert summary["reason_flag_counts"]["missing_static_run"] == 4
    assert summary["reason_flag_counts"]["missing_host_file"] == 1
    assert summary["reason_flag_counts"]["legacy_runs_row_present"] == 1
    assert summary["reason_flag_counts"]["canonical_db_reference_present"] == 1
    assert summary["runs_with_recovered_manifest_context"] == 1
    assert summary["distinct_recovered_package_count"] == 1
    rows = report["static_dangling_rows"]
    assert rows[0]["primary_reason"] == "truly_detached"
    assert rows[1]["primary_reason"] == "legacy_mirror_only_with_file"
    assert rows[2]["primary_reason"] == "malformed_static_run_id"
    assert rows[3]["primary_reason"] == "canonical_db_residue"
    run_103 = next(
        row for row in report["static_dangling_runs"] if str(row["resolved_static_run_id"]) == "103"
    )
    assert run_103["recovered_run_manifest_exists"] is True
    assert run_103["recovered_package_name"] == "pkg.four"
    assert run_103["recovered_display_name"] == "Pkg Four"
    assert run_103["core_bundle_complete"] is False


def test_collect_static_dangling_report_recovers_bundle_context(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    manifest_path = repo_root / "evidence" / "static_runs" / "200" / "run_manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps(
            {
                "package_name": "com.example.bundle",
                "display_name": "Example Bundle",
                "version_name": "9.9.9",
                "version_code": "999",
                "profile_key": "Full",
                "scenario_id": "static_default",
            }
        ),
        encoding="utf-8",
    )
    baseline = (
        repo_root
        / "data"
        / "static_analysis"
        / "baseline"
        / "com.example.bundle-full-research_cohort-20260615T155108Z.json"
    )
    baseline.parent.mkdir(parents=True, exist_ok=True)
    baseline.write_text("{}", encoding="utf-8")
    plan = (
        repo_root
        / "data"
        / "static_analysis"
        / "dynamic_plan"
        / "com.example.bundle-full-research_cohort-sr200-20260615T155108Z.json"
    )
    plan.parent.mkdir(parents=True, exist_ok=True)
    plan.write_text("{}", encoding="utf-8")
    dep = repo_root / "evidence" / "static_runs" / "200" / "dep.json"
    dep.write_text("{}", encoding="utf-8")
    manifest_evidence = repo_root / "evidence" / "static_runs" / "200" / "manifest_evidence.json"
    manifest_evidence.write_text("{}", encoding="utf-8")
    report_json = repo_root / "data" / "static_analysis" / "reports" / "latest" / "hash200.json"
    report_json.parent.mkdir(parents=True, exist_ok=True)
    report_json.write_text("{}", encoding="utf-8")

    def fake_run_sql(
        sql: str,
        params: tuple[object, ...] | tuple[()] = (),
        *,
        fetch: str = "all",
        dictionary: bool = False,
        query_name: str | None = None,
    ):
        del sql, params, fetch, dictionary
        if query_name == "artifact_registry_static_dangling.schema_inventory":
            return [
                {
                    "table_name": "static_analysis_runs",
                    "column_name": "id",
                    "column_type": "bigint(20) unsigned",
                }
            ]
        if query_name == "artifact_registry_static_dangling.static_totals":
            return {"linked_static_registry_rows": 0, "dangling_static_registry_rows": 7}
        if query_name == "artifact_registry_static_dangling.dangling_rows":
            common = {
                "run_type": "static",
                "run_id": "200",
                "static_run_id": 200,
                "resolved_static_run_id": 200,
                "link_state": "dangling_static_run",
                "linkage_resolution_path": "typed_static",
                "origin": "host",
                "created_at_utc": "2026-06-15 15:51:08",
                "status_reason": None,
                "meta_package_name": None,
                "meta_session_stamp": None,
                "meta_session_label": None,
                "has_static_session_run_link": 0,
                "has_static_analysis_findings": 0,
                "has_static_permission_matrix": 0,
                "has_static_string_summary": 0,
                "has_static_findings_summary": 0,
                "has_permission_audit_snapshot": 0,
                "has_legacy_runs": 0,
            }
            return [
                {
                    "artifact_id": 1,
                    "artifact_type": "dep_snapshot",
                    "host_path": str(dep),
                    **common,
                },
                {
                    "artifact_id": 2,
                    "artifact_type": "dep_snapshot",
                    "host_path": str(dep),
                    **common,
                },
                {
                    "artifact_id": 3,
                    "artifact_type": "static_run_manifest",
                    "host_path": str(manifest_path),
                    **common,
                },
                {
                    "artifact_id": 4,
                    "artifact_type": "manifest_evidence",
                    "host_path": str(manifest_evidence),
                    **common,
                },
                {
                    "artifact_id": 5,
                    "artifact_type": "static_baseline_json",
                    "host_path": str(baseline),
                    **common,
                },
                {
                    "artifact_id": 6,
                    "artifact_type": "static_dynamic_plan_json",
                    "host_path": str(plan),
                    **common,
                },
                {
                    "artifact_id": 7,
                    "artifact_type": "static_report",
                    "host_path": str(report_json),
                    **common,
                },
            ]
        raise AssertionError(f"unexpected query_name: {query_name}")

    report = collect_artifact_registry_static_dangling_report(fake_run_sql, repo_root=repo_root)
    summary = report["summary"]
    assert summary["runs_with_recovered_manifest_context"] == 1
    assert summary["complete_core_bundle_run_count"] == 1
    assert summary["partial_core_bundle_run_count"] == 0
    assert summary["runs_with_duplicate_artifact_types"] == 1
    run_row = report["static_dangling_runs"][0]
    assert run_row["recovered_package_name"] == "com.example.bundle"
    assert run_row["recovered_display_name"] == "Example Bundle"
    assert run_row["core_bundle_complete"] is True
    assert run_row["duplicate_artifact_rows"] == 1
    assert run_row["duplicate_artifact_types_csv"] == "dep_snapshot"
    assert run_row["path_timestamp_hints_csv"] == "20260615T155108Z"


def test_write_static_dangling_bundle_writes_expected_files(tmp_path: Path) -> None:
    report = {
        "summary": {"dangling_static_registry_rows": 1, "linked_static_registry_rows": 0},
        "static_schema_inventory": [{"table_name": "static_analysis_runs"}],
        "static_dangling_rows": [{"artifact_id": 1, "primary_reason": "truly_detached"}],
        "static_dangling_runs": [{"resolved_static_run_id": "101", "row_count": 1}],
        "static_dangling_reason_counts": [{"reason_bucket": "truly_detached", "count": 1}],
        "static_dangling_reason_samples": [{"reason_bucket": "truly_detached", "artifact_id": 1}],
    }
    out_dir = tmp_path / "audit"
    files = write_artifact_registry_static_dangling_bundle(report, out_dir)
    names = {path.name for path in files}
    assert "summary.json" in names
    assert "static_dangling_rows.csv" in names
    payload = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert payload["dangling_static_registry_rows"] == 1
