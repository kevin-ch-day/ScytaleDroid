"""Unit tests for static session grain integrity helpers (read-only)."""

from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Database.db_utils.static_session_grain_integrity import (
    GRAIN_LEGEND_LINES,
    aggregate_archive_json_pipeline_totals,
    collect_session_grain,
    count_json_files_in_dir,
    format_grain_integrity_cli_command,
    load_grain_operator_display_overrides,
    pipeline_rollup_from_report_dict,
    render_text_report,
    reports_archive_dir,
)


def test_reports_archive_dir_sanitizes_traversal() -> None:
    p = reports_archive_dir(session_stamp="sess-1", data_dir="/tmp/x")
    assert ".." not in str(p)
    assert p.name == "sess-1"


def test_count_json_files_in_dir(tmp_path: Path) -> None:
    (tmp_path / "a.json").write_text("{}", encoding="utf-8")
    (tmp_path / "b.JSON").write_text("{}", encoding="utf-8")
    (tmp_path / "c.txt").write_text("x", encoding="utf-8")
    assert count_json_files_in_dir(tmp_path) == 2
    assert count_json_files_in_dir(tmp_path / "missing") == 0


def test_pipeline_rollup_from_report_dict() -> None:
    payload = {
        "manifest": {"package_name": "com.example.app"},
        "metadata": {
            "pipeline_summary": {
                "status_counts": {"WARN": 3, "OK": 10},
                "policy_fail_detectors": [{"detector": "d1"}],
                "finding_fail_detectors": [{"detector": "d2"}, {"detector": "d3"}],
                "error_detectors": [{"detector": "e1"}, {"detector": "e2"}],
            }
        },
    }
    w, p, e, pkg = pipeline_rollup_from_report_dict(payload)
    assert pkg == "com.example.app"
    assert w == 3
    assert p == 3
    assert e == 2


def test_aggregate_archive_json_pipeline_totals(tmp_path: Path) -> None:
    p1 = {
        "manifest": {"package_name": "com.a"},
        "metadata": {"pipeline_summary": {"status_counts": {"WARN": 1}, "policy_fail_detectors": []}},
    }
    p2 = {
        "manifest": {"package_name": "com.a"},
        "metadata": {"pipeline_summary": {"status_counts": {"WARN": 2}, "finding_fail_detectors": [{}]}},
    }
    (tmp_path / "x.json").write_text(json.dumps(p1), encoding="utf-8")
    (tmp_path / "y.json").write_text(json.dumps(p2), encoding="utf-8")
    agg = aggregate_archive_json_pipeline_totals(tmp_path, max_files=10)
    assert agg["files_seen"] == 2
    assert agg["parse_errors"] == 0
    assert agg["totals"]["warn"] == 3
    assert agg["totals"]["policy"] == 1
    assert agg["per_package"]["com.a"]["files"] == 2


def test_render_text_report_includes_grain_header() -> None:
    data = {
        "session_stamp": "sess",
        "static_run_rows": 2,
        "status_breakdown": [("COMPLETED", 2)],
        "canonical_findings_rows": 5,
        "permission_matrix_rows": 6,
        "permission_risk_vnext_rows": 7,
        "string_summary_rows": 2,
        "string_sample_rows": 9,
        "correlation_rows": 1,
        "session_link_rows": 2,
        "rollup_rows": 1,
        "persistence_failure_rows": 0,
        "artifact_registry_rows_static": 4,
        "top_packages": [
            {
                "static_run_id": 10,
                "package_name": "com.a",
                "finding_rows": 3,
                "matrix_rows": 2,
                "risk_rows": 2,
                "string_summary_rows": 1,
                "string_sample_rows": 4,
                "correlation_rows": 0,
                "persist_fail_rows": 0,
                "artifact_registry_rows": 2,
            }
        ],
    }
    text = render_text_report(data, json_archive_count=5)
    assert "Grain (read-only summary)" in text
    assert "static_analysis_runs          : 2" in text
    assert "APK JSON files (archive dir)   : 5" in text
    assert "com.a" in text
    assert "Persistence-audit" in text and "latest/" in text


def test_render_text_report_with_display_labels_prefers_csv(tmp_path: Path) -> None:
    csv_path = tmp_path / "o.csv"
    csv_path.write_text("package_name,display_name\ncom.a,Override Name\n", encoding="utf-8")
    overrides = load_grain_operator_display_overrides(csv_path)
    data = {
        "session_stamp": "sess",
        "static_run_rows": 1,
        "status_breakdown": [("COMPLETED", 1)],
        "canonical_findings_rows": 1,
        "permission_matrix_rows": 1,
        "permission_risk_vnext_rows": 1,
        "string_summary_rows": 1,
        "string_sample_rows": 1,
        "correlation_rows": 0,
        "session_link_rows": 1,
        "rollup_rows": 1,
        "persistence_failure_rows": 0,
        "artifact_registry_rows_static": 1,
        "top_packages": [
            {
                "static_run_id": 10,
                "package_name": "com.a",
                "display_name": "Db Name",
                "finding_rows": 1,
                "matrix_rows": 1,
                "risk_rows": 1,
                "string_summary_rows": 1,
                "string_sample_rows": 1,
                "correlation_rows": 0,
                "persist_fail_rows": 0,
                "artifact_registry_rows": 1,
            }
        ],
    }
    text = render_text_report(
        data,
        json_archive_count=None,
        with_display_labels=True,
        display_override_by_lower=overrides,
    )
    assert "display" in text
    assert "Override Name" in text


def test_load_grain_operator_display_overrides_missing_file() -> None:
    assert load_grain_operator_display_overrides(Path("/nonexistent/nope.csv")) == {}


def test_collect_session_grain_returns_zero_when_no_runs() -> None:
    def run_sql(sql: str, params=None, fetch="one", **_kwargs):  # type: ignore[no-untyped-def]
        if fetch == "one" and "FROM static_analysis_runs r WHERE r.session_stamp" in sql and "GROUP BY" not in sql:
            return (0,)
        raise AssertionError((sql, params, fetch))

    out = collect_session_grain(run_sql, session_stamp="missing", scope_label=None, top_packages=5)
    assert out["static_run_rows"] == 0


def test_collect_session_grain_mock_happy_path() -> None:
    def run_sql(sql: str, params=None, fetch="one", dictionary=False, **_kwargs):  # type: ignore[no-untyped-def]
        s = " ".join(sql.split())
        if fetch == "one":
            if "COUNT(*) FROM static_analysis_runs r WHERE r.session_stamp" in s and "GROUP BY" not in s:
                return (2,)
            if "FROM static_analysis_findings" in s:
                return (40,)
            if "FROM static_permission_matrix" in s:
                return (80,)
            if "FROM static_permission_risk_vnext" in s:
                return (60,)
            if "FROM static_string_summary s" in s and "INNER JOIN static_analysis_runs r" in s:
                return (2,)
            if "FROM static_string_samples" in s:
                return (100,)
            if "FROM static_correlation_results" in s:
                return (4,)
            if "FROM static_session_run_links" in s:
                return (2,)
            if "FROM static_session_rollups" in s:
                return (1,)
            if "FROM static_persistence_failures" in s:
                return (0,)
            if "FROM artifact_registry" in s:
                return (6,)
        if fetch == "all" and "GROUP BY COALESCE" in s:
            return [("COMPLETED", 2)]
        if fetch == "all" and dictionary and "FROM static_analysis_runs r" in s and "JOIN app_versions" in s:
            return [
                {
                    "static_run_id": 1,
                    "package_name": "com.heavy",
                    "display_name": "Heavy",
                    "run_status": "COMPLETED",
                    "finding_rows": 20,
                    "matrix_rows": 40,
                    "risk_rows": 30,
                    "string_summary_rows": 1,
                    "string_sample_rows": 50,
                    "correlation_rows": 2,
                    "persist_fail_rows": 0,
                    "artifact_registry_rows": 3,
                }
            ]
        raise AssertionError((sql, params, fetch))

    out = collect_session_grain(run_sql, session_stamp="sess", scope_label=None, top_packages=5)
    assert out["static_run_rows"] == 2
    assert out["canonical_findings_rows"] == 40
    assert out["status_breakdown"] == [("COMPLETED", 2)]
    assert len(out["top_packages"]) == 1
    assert out["top_packages"][0]["package_name"] == "com.heavy"


def test_format_grain_integrity_cli_command_escapes_quotes() -> None:
    cmd = format_grain_integrity_cli_command(
        "sess'1",
        scope_label="scope'x",
        count_archive=True,
        aggregate_json=True,
        with_display_labels=True,
    )
    assert "report_static_session_grain_integrity.py" in cmd
    assert "sess'\"'\"'1" in cmd
    assert "scope'\"'\"'x" in cmd
    assert "--count-archive-json" in cmd
    assert "--aggregate-json-summaries" in cmd
    assert "--with-display-labels" in cmd


def test_format_grain_integrity_cli_command_placeholder_when_empty_stamp() -> None:
    out = format_grain_integrity_cli_command("")
    assert "<session_stamp>" in out


def test_grain_legend_tuple_nonempty() -> None:
    assert len(GRAIN_LEGEND_LINES) >= 3
