from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Database.db_utils import artifact_registry_static_file_present_detached as subject


def test_help_is_safe_without_pythonpath(assert_safe_script_help) -> None:
    out = assert_safe_script_help(
        "scripts/db/report_artifact_registry_static_file_present_detached.py"
    ).lower()
    assert out.startswith("usage:")
    assert "file-present detached" in out


def test_collect_static_file_present_detached_report(monkeypatch, tmp_path: Path) -> None:
    report_json = tmp_path / "report.json"
    report_json.write_text(
        json.dumps(
            {
                "metadata": {
                    "package_name": "com.example.alpha",
                    "app_label": "Example Alpha",
                    "version_name": "1.0",
                    "version_code": "10",
                    "base_apk_sha256": "a" * 64,
                    "session_stamp": "20260709-all-full",
                }
            }
        ),
        encoding="utf-8",
    )
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"app": {"package": "com.example.beta", "version_name": "2.0", "version_code": "20"}}),
        encoding="utf-8",
    )
    beta_report = tmp_path / "beta-report.json"
    beta_report.write_text(
        json.dumps(
            {
                "metadata": {
                    "package_name": "com.example.beta",
                    "version_name": "2.0",
                    "version_code": "20",
                    "base_apk_sha256": "b" * 64,
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        subject,
        "collect_artifact_registry_static_dangling_report",
        lambda run_sql, repo_root: {  # noqa: ARG005
            "static_dangling_rows": [
                {
                    "artifact_id": 1,
                    "resolved_static_run_id": 100,
                    "artifact_type": "static_report",
                    "host_path_family": "static_reports_latest",
                    "host_path_exists": True,
                    "host_path": str(report_json),
                    "primary_reason": "file_present_db_detached",
                    "created_at_utc": "2026-07-09 20:00:00",
                },
                {
                    "artifact_id": 2,
                    "resolved_static_run_id": 200,
                    "artifact_type": "static_baseline_json",
                    "host_path_family": "static_baseline_json",
                    "host_path_exists": True,
                    "host_path": str(baseline),
                    "primary_reason": "file_present_db_detached",
                    "created_at_utc": "2026-07-09 20:01:00",
                },
                {
                    "artifact_id": 3,
                    "resolved_static_run_id": 200,
                    "artifact_type": "static_report",
                    "host_path_family": "static_reports_latest",
                    "host_path_exists": True,
                    "host_path": str(beta_report),
                    "primary_reason": "file_present_db_detached",
                    "created_at_utc": "2026-07-09 20:02:00",
                },
                {
                    "artifact_id": 4,
                    "resolved_static_run_id": 200,
                    "artifact_type": "static_dynamic_plan_json",
                    "host_path_family": "static_dynamic_plan_json",
                    "host_path_exists": True,
                    "host_path": str(tmp_path / "plan.json"),
                    "primary_reason": "file_present_db_detached",
                    "created_at_utc": "2026-07-09 20:03:00",
                },
                {
                    "artifact_id": 5,
                    "resolved_static_run_id": 300,
                    "artifact_type": "static_report",
                    "host_path_family": "static_reports_latest",
                    "host_path_exists": False,
                    "host_path": str(tmp_path / "missing.json"),
                    "primary_reason": "truly_detached",
                    "created_at_utc": "2026-07-09 20:04:00",
                },
            ],
            "static_dangling_runs": [
                {
                    "resolved_static_run_id": "100",
                    "row_count": 1,
                    "artifact_types_csv": "static_report",
                    "core_bundle_complete": False,
                    "recovered_run_manifest_exists": False,
                },
                {
                    "resolved_static_run_id": "200",
                    "row_count": 6,
                    "artifact_types_csv": (
                        "dep_snapshot,manifest_evidence,static_baseline_json,"
                        "static_dynamic_plan_json,static_report,static_run_manifest"
                    ),
                    "core_bundle_complete": True,
                    "recovered_run_manifest_exists": True,
                    "recovered_package_name": None,
                    "recovered_display_name": "Example Beta",
                    "recovered_version_name": None,
                    "recovered_version_code": None,
                    "recovered_base_apk_sha256": None,
                },
            ],
        },
    )

    def fake_run_sql(*_args, **kwargs):
        if kwargs.get("query_name") == "artifact_registry_static_file_present_detached.canonical_coverage":
            return [
                {
                    "static_run_id": 900,
                    "package_name_lc": "com.example.alpha",
                    "package_name": "com.example.alpha",
                    "version_code": "10",
                    "version_name": "1.0",
                    "base_apk_sha256": "a" * 64,
                    "session_stamp": "20260709-all-full",
                },
                {
                    "static_run_id": 901,
                    "package_name_lc": "com.example.beta",
                    "package_name": "com.example.beta",
                    "version_code": "21",
                    "version_name": "2.1",
                    "base_apk_sha256": "c" * 64,
                    "session_stamp": "20260710-all-full",
                },
            ]
        return None

    report = subject.collect_static_file_present_detached_report(fake_run_sql, repo_root=tmp_path)
    summary = report["summary"]
    assert summary["file_present_detached_row_count"] == 4
    assert summary["file_present_detached_run_count"] == 2
    assert summary["safe_prune_rows"] == 0
    assert summary["rows_with_json_identity"] == 3
    assert summary["rows_using_run_identity_fallback"] == 2
    assert summary["review_class_counts"] == {
        "REVIEW_PRESENT_COMPLETE_CORE_BUNDLE": 3,
        "REVIEW_PRESENT_REPORT_ONLY": 1,
    }
    assert summary["canonical_coverage_counts"] == {
        "COVERED_BY_CANONICAL_SAME_HASH": 1,
        "SUPERSEDED_BY_NEWER_CANONICAL_VERSION": 3,
    }
    assert summary["registry_resolution_candidate_rows"] == 1
    assert summary["staged_review_action_counts"] == {
        "STAGE_EXACT_HASH_REGISTRY_RESOLUTION_REVIEW": 1,
        "STAGE_PRIOR_VERSION_RETENTION_REVIEW": 3,
    }
    rows = report["file_present_detached_rows"]
    assert rows[0]["inferred_package_name"] == "com.example.alpha"
    assert rows[0]["review_class"] == "REVIEW_PRESENT_REPORT_ONLY"
    assert rows[0]["canonical_coverage_class"] == "COVERED_BY_CANONICAL_SAME_HASH"
    assert rows[0]["staged_review_action"] == "STAGE_EXACT_HASH_REGISTRY_RESOLUTION_REVIEW"
    assert rows[0]["registry_resolution_candidate"] is True
    assert rows[1]["inferred_package_name"] == "com.example.beta"
    assert rows[1]["review_class"] == "REVIEW_PRESENT_COMPLETE_CORE_BUNDLE"
    assert rows[1]["canonical_coverage_class"] == "SUPERSEDED_BY_NEWER_CANONICAL_VERSION"
    assert rows[1]["staged_review_action"] == "STAGE_PRIOR_VERSION_RETENTION_REVIEW"
    assert rows[3]["run_identity_fallback_used"] is True
    assert rows[3]["inferred_base_apk_sha256"] == "b" * 64


def test_write_static_file_present_detached_bundle(tmp_path: Path) -> None:
    report = {
        "summary": {"file_present_detached_row_count": 1},
        "file_present_detached_rows": [{"artifact_id": 1}],
        "file_present_detached_runs": [{"resolved_static_run_id": 100}],
        "file_present_detached_packages": [{"package_name": "com.example.alpha"}],
        "file_present_detached_path_families": [{"host_path_family": "static_reports_latest"}],
    }
    out_dir = tmp_path / "audit"
    files = subject.write_static_file_present_detached_bundle(report, out_dir)
    names = {path.name for path in files}
    assert "summary.json" in names
    assert "file_present_detached_rows.csv" in names
    payload = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert payload["file_present_detached_row_count"] == 1
