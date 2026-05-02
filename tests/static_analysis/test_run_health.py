from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunOutcome, ScopeSelection
from scytaledroid.StaticAnalysis.cli.execution.run_health import (
    build_run_health_document,
    compute_run_aggregate_status,
    format_run_health_stdout_lines,
    merge_skipped_detectors,
)


def test_merge_skipped_detectors_dedupes_by_detector_section_reason() -> None:
    merged = merge_skipped_detectors(
        [
            {"detector": "a", "section": "s", "reason": "r1"},
            {"detector": "a", "section": "s", "reason": "r1"},
            {"detector": "b", "section": "", "reason": "r2"},
        ]
    )
    assert len(merged) == 2
    assert merged[0]["reason"] == "r1"


def test_compute_run_aggregate_status_mixed_complete_skipped_is_partial() -> None:
    sel = ScopeSelection(scope="profile", label="P", groups=tuple())
    results = [
        AppRunResult("a.b", "C", final_status="complete"),
        AppRunResult("c.d", "C", final_status="skipped"),
    ]
    out = RunOutcome(
        results,
        datetime.now(UTC),
        datetime.now(UTC),
        sel,
        Path("/tmp"),
        [],
        [],
    )
    assert compute_run_aggregate_status(out) == "partial"


def test_build_run_health_document_finding_persistence_rollups() -> None:
    sel = ScopeSelection(scope="profile", label="P", groups=tuple())
    a = AppRunResult(
        "p1",
        "C",
        persisted_artifacts=1,
        persistence_runtime_findings=100,
        persistence_persisted_findings=75,
        persistence_findings_capped_total=25,
        persistence_findings_capped_by_detector={"secrets": 25},
    )
    outcome = RunOutcome(
        [a],
        datetime.now(UTC),
        datetime.now(UTC),
        sel,
        Path("/tmp"),
        [],
        [],
    )
    from scytaledroid.StaticAnalysis.cli.core.models import RunParameters

    doc = build_run_health_document(
        outcome,
        RunParameters(profile="full", scope="profile", scope_label="L", session_stamp="sess"),
        persistence_enabled=True,
        persist_attempted=True,
    )
    roll = doc["run_rollups"]
    assert isinstance(roll, dict)
    assert roll.get("scan_execution_complete") is True
    assert roll["findings_runtime_total"] == 100
    assert roll["findings_persisted_db_total"] == 75
    assert roll["findings_capped_not_persisted_total"] == 25
    apps = doc["apps"]
    assert isinstance(apps, list) and len(apps) == 1
    fp = apps[0]["finding_persistence"]
    assert fp["runtime_findings"] == 100
    assert fp["persisted_findings_db"] == 75
    assert fp["capped_not_persisted"] == 25
    assert fp["capped_by_detector"] == {"secrets": 25}
    es = apps[0].get("execution_signals")
    assert isinstance(es, dict) and "drivers" in es and "counts" in es
    assert doc["schema_version"] == 3
    align = doc["web_session_health_alignment"]
    assert isinstance(align, dict)
    assert "v_web_app_sessions" in (align.get("reference_mysql_views") or [])
    proj = apps[0]["mysql_web_session_health_projection"]
    approx = proj["approximate_mysql_columns"]
    assert approx["findings_ready"] == 1
    assert approx["findings_runtime_total"] == 100
    assert approx["findings_capped_total"] == 25
    assert isinstance(approx.get("findings_capped_by_detector_json"), dict)


def test_format_run_health_stdout_lines_partial_app_hints() -> None:
    doc = {
        "final_run_status": "partial",
        "run_rollups": {
            "app_total": 1,
            "apps_complete_final": 0,
            "apps_partial_final": 1,
            "apps_failed_final": 0,
            "apps_skipped_final": 0,
            "detector_errors_total_estimate": 0,
            "detector_warnings_total_estimate": 3,
            "detector_failures_total_estimate": 1,
            "scan_execution_complete": True,
            "artifacts_scan_completed_counter": 5,
            "artifact_total_discovered_estimate": 5,
        },
        "outputs": {},
        "status_reasons": {
            "detector_warnings": 3,
            "detector_failures": 1,
            "detector_errors": 0,
            "parse_fallbacks": 0,
            "string_status": "ok",
            "db_persistence_status": "ok",
            "detector_pipeline_status": "warnings_and_policy_failures",
            "detector_status": "warnings_and_policy_failures",
            "governance_grade": "experimental",
            "governance_reason": "x" * 200,
        },
        "apps": [
            {
                "package_name": "com.foo.app",
                "final_status": "partial",
                "execution_signals": {
                    "drivers": ["detector_warnings=3", "detector_failures=1"],
                    "counts": {},
                },
            }
        ],
    }
    lines = format_run_health_stdout_lines(doc)
    assert len(lines) >= 3
    assert "Apps not strictly complete" in lines[-1]
    assert "com.foo.app" in lines[-1]
    gov_line = next(line for line in lines if line.startswith("Governance"))
    assert "…" in gov_line or "experimental" in gov_line


def test_format_run_health_stdout_lines_adds_reasons_row() -> None:
    doc = {
        "final_run_status": "partial",
        "run_rollups": {
            "app_total": 1,
            "apps_complete_final": 0,
            "apps_partial_final": 1,
            "apps_failed_final": 0,
            "apps_skipped_final": 0,
            "detector_errors_total_estimate": 0,
            "detector_warnings_total_estimate": 3,
            "detector_failures_total_estimate": 1,
            "scan_execution_complete": True,
            "artifacts_scan_completed_counter": 3,
            "artifact_total_discovered_estimate": 3,
        },
        "outputs": {},
        "status_reasons": {
            "detector_warnings": 3,
            "detector_failures": 1,
            "detector_errors": 0,
            "parse_fallbacks": 0,
            "string_status": "ok",
            "db_persistence_status": "ok",
            "detector_pipeline_status": "warnings_and_policy_failures",
            "detector_status": "warnings_and_policy_failures",
            "governance_grade": "experimental",
            "governance_reason": "missing_permission_intel",
        },
    }
    lines = format_run_health_stdout_lines(doc)
    assert len(lines) >= 4
    body = "\n".join(lines)
    assert "Execution        : complete" in body
    assert "Detector result  :" in body
    assert "warnings=3" in body and "finding_failures=1" in body
    assert "execution_errors=0" in body
    assert "Overall health   : partial" in body
    assert "pipeline_token=warnings_and_policy_failures" in body


def test_build_run_health_document_includes_string_summary_note() -> None:
    sel = ScopeSelection(scope="profile", label="Research Dataset Alpha", groups=tuple())
    app = AppRunResult("com.example.app", "Uncategorized", discovered_artifacts=45, final_status="partial")
    outcome = RunOutcome(
        [app],
        datetime.now(UTC),
        datetime.now(UTC),
        sel,
        Path("/tmp/scytale-static"),
        [],
        [],
        total_artifacts=45,
        completed_artifacts=45,
    )
    from scytaledroid.StaticAnalysis.cli.core.models import RunParameters

    doc = build_run_health_document(
        outcome,
        RunParameters(profile="full", scope="profile", scope_label="Research Dataset Alpha", session_stamp="s1"),
        persistence_enabled=False,
        persist_attempted=False,
    )
    note = doc["string_summary_note"]
    assert isinstance(note, dict)
    assert note["string_summary_scope"] == "base_apk_only"
    assert "string_summary_warning" in note
