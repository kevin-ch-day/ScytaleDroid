from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunOutcome, ScopeSelection
from scytaledroid.StaticAnalysis.cli.execution.run_health import (
    attach_run_health_outputs_on_document,
    build_run_health_document,
    compact_run_health_stdout_line,
    compute_run_aggregate_status,
    format_run_health_stdout_lines,
    merge_skipped_detectors,
    write_run_health_json,
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


def test_write_run_health_json_emits_complete_newline_terminated_json(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "run_health.json"

    written = write_run_health_json(target, {"status": "complete", "count": 2})

    assert written == target
    assert target.read_text(encoding="utf-8").endswith("\n")
    assert target.read_text(encoding="utf-8").startswith('{\n  "status": "complete"')


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
        final_status="complete",
        persistence_runtime_findings=100,
        persistence_persisted_findings=75,
        persistence_findings_capped_total=25,
        persistence_findings_capped_by_detector={"secrets": 25},
        persistence_runtime_p0_findings=10,
        persistence_persisted_p0_findings=8,
        persistence_capped_p0_findings=2,
    )
    outcome = RunOutcome(
        [a],
        datetime.now(UTC),
        datetime.now(UTC),
        sel,
        Path("/tmp"),
        [],
        [],
        session_metrics={"resolved_worker_budget": 16, "artifact_concurrency_cap": 1},
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
    assert roll["resolved_worker_budget"] == 16
    assert roll["artifact_concurrency_cap"] == 1
    assert doc["final_run_status"] == "complete"
    assert doc["workflow_completion_status"] == "complete"
    assert doc["workflow_run_status"] == "complete"
    assert doc["detector_posture"] == "clean"
    assert doc["detector_posture_status"] == "clean"
    assert doc["finding_fidelity_status"] == "capped"
    assert roll["apps_with_caveats"] == 0
    assert roll["findings_runtime_total"] == 100
    assert roll["findings_persisted_db_total"] == 75
    assert roll["findings_capped_not_persisted_total"] == 25
    assert roll["p0_runtime_findings_total"] == 10
    assert roll["p0_persisted_db_findings_total"] == 8
    assert roll["p0_capped_not_persisted_total"] == 2
    apps = doc["apps"]
    assert isinstance(apps, list) and len(apps) == 1
    fp = apps[0]["finding_persistence"]
    assert apps[0]["workflow_completion_status"] == "complete"
    assert apps[0]["db_persistence_status"] == "ok"
    assert apps[0]["detector_posture"] == "clean"
    assert apps[0]["finding_fidelity_status"] == "capped"
    assert fp["runtime_findings"] == 100
    assert fp["persisted_findings_db"] == 75
    assert fp["capped_not_persisted"] == 25
    assert fp["runtime_p0_findings"] == 10
    assert fp["persisted_p0_findings_db"] == 8
    assert fp["capped_p0_not_persisted"] == 2
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
    assert doc.get("post_run_grain_present") is False
    assert doc.get("post_run_merge_status") == "pending"
    assert doc.get("run_health_revision") == 1
    assert doc.get("post_run_grain_merged_at_utc") is None


def test_successful_scan_with_persistence_failure_is_not_workflow_complete() -> None:
    app = AppRunResult(
        "p1", "C", discovered_artifacts=1, persisted_artifacts=0, final_status="complete"
    )
    outcome = RunOutcome(
        [app],
        datetime.now(UTC),
        datetime.now(UTC),
        ScopeSelection(scope="all", label="All", groups=()),
        Path("/tmp"),
        [],
        [],
        total_artifacts=1,
        completed_artifacts=1,
        persistence_failed=True,
    )
    from scytaledroid.StaticAnalysis.cli.core.models import RunParameters

    doc = build_run_health_document(
        outcome,
        RunParameters(
            profile="full", scope="all", scope_label="All", session_stamp="failed-persist"
        ),
        persistence_enabled=True,
        persist_attempted=True,
    )
    assert doc["workflow_completion_status"] == "failed"
    assert doc["status_reasons"]["db_persistence_status"] == "failed"


def test_run_health_keeps_policy_finding_warning_and_execution_counters_independent(
    monkeypatch,
) -> None:
    app = AppRunResult(
        "p1", "C", discovered_artifacts=1, persisted_artifacts=1, final_status="complete"
    )
    app.artifacts = [SimpleNamespace(report=None)]
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.scan_report._summarize_app_pipeline",
        lambda _app: {
            "error_count": 1,
            "warn_count": 7,
            "policy_fail_count": 2,
            "finding_fail_count": 4,
            "fail_count": 6,
            "parse_fallback_events_est": 0,
            "detector_executed": 1,
            "detector_skipped": 0,
            "detector_total": 1,
            "skipped_detectors": [],
            "placeholder_stage_opportunities": 1,
            "implemented_stage_opportunities": 4,
            "executed_implemented_stage_opportunities": 3,
            "implemented_stage_execution_rate": 0.75,
            "placeholder_detectors": [
                {"detector": "dynamic_loading", "reason": "not implemented"}
            ],
        },
    )
    outcome = RunOutcome(
        [app],
        datetime.now(UTC),
        datetime.now(UTC),
        ScopeSelection(scope="all", label="All", groups=()),
        Path("/tmp"),
        [],
        [],
        total_artifacts=1,
        completed_artifacts=1,
    )
    from scytaledroid.StaticAnalysis.cli.core.models import RunParameters

    doc = build_run_health_document(
        outcome,
        RunParameters(profile="full", scope="all", scope_label="All"),
        persistence_enabled=True,
        persist_attempted=True,
    )
    reasons = doc["status_reasons"]
    assert reasons["detector_warnings"] == 7
    assert reasons["policy_gate_failures"] == 2
    assert reasons["finding_signals"] == 4
    assert reasons["detector_execution_errors"] == 1
    assert "policy_failures" not in reasons
    coverage = doc["measurement_coverage"]
    assert coverage["status"] == "partial_declared_placeholders"
    assert coverage["placeholder_detector_ids"] == ["dynamic_loading"]
    assert coverage["implemented_stage_execution_rate"] == 0.75


def test_format_run_health_stdout_lines_partial_app_hints() -> None:
    doc = {
        "final_run_status": "complete",
        "workflow_completion_status": "complete",
        "workflow_run_status": "complete",
        "detector_posture": "policy_or_finding_gates",
        "detector_posture_status": "policy_or_finding_gates",
        "finding_fidelity_status": "unknown",
        "run_rollups": {
            "app_total": 1,
            "apps_complete_final": 0,
            "apps_partial_final": 1,
            "apps_failed_final": 0,
            "apps_skipped_final": 0,
            "detector_errors_total_estimate": 0,
            "detector_warnings_total_estimate": 3,
            "detector_failures_total_estimate": 1,
            "detector_posture": "policy_or_finding_gates",
            "detector_posture_status": "policy_or_finding_gates",
            "scan_execution_complete": True,
            "artifacts_scan_completed_counter": 5,
            "artifact_total_discovered_estimate": 5,
            "resolved_worker_budget": 16,
            "artifact_concurrency_cap": 1,
        },
        "outputs": {},
        "measurement_coverage": {
            "status": "partial_declared_placeholders",
            "implemented_stage_opportunities": 17,
            "executed_implemented_stage_opportunities": 17,
            "placeholder_stage_opportunities": 3,
            "placeholder_detector_ids": ["dynamic_loading", "file_io_sinks"],
        },
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
                    "drivers": ["detector_warnings=3", "policy_failures=1"],
                    "counts": {},
                },
            }
        ],
    }
    lines = format_run_health_stdout_lines(doc)
    assert "Artifact workers : observed_peak=1 | resolved_budget=16" in lines
    assert (
        "Measurement cov. : partial_declared_placeholders | "
        "implemented_executed=17/17 | placeholder_stages=3 | "
        "placeholders=dynamic_loading,file_io_sinks"
    ) in lines
    assert len(lines) >= 3
    assert "Apps with detector/persistence caveats" in lines[-1]
    assert "com.foo.app" in lines[-1]
    gov_line = next(line for line in lines if line.startswith("Governance"))
    assert "…" in gov_line or "experimental" in gov_line


def test_build_run_health_document_preserves_legacy_partial_but_exposes_complete_workflow_for_warning_only_app(
    monkeypatch,
) -> None:
    sel = ScopeSelection(scope="profile", label="P", groups=tuple())
    app = AppRunResult(
        "com.example.warn",
        "C",
        discovered_artifacts=1,
        persisted_artifacts=1,
        final_status="partial",
        base_string_data={"aggregation_scope": "single_artifact", "warnings": []},
    )
    app.artifacts = [SimpleNamespace(report=None)]
    app.persistence_runtime_findings = 12
    app.persistence_persisted_findings = 12
    app.persistence_findings_capped_total = 0
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.scan_report._summarize_app_pipeline",
        lambda _app: {
            "error_count": 0,
            "warn_count": 1,
            "fail_count": 1,
            "policy_fail_count": 0,
            "finding_fail_count": 1,
            "parse_fallback_events_est": 0,
            "detector_executed": 2,
            "detector_skipped": 0,
            "detector_total": 2,
            "skipped_detectors": [],
        },
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.run_health.document.rollup_parse_fallback_signals",
        lambda _app: {
            "resource_fallback_used_artifacts": 0,
            "resource_bounds_warning_artifacts": 1,
            "resource_parse_partial_artifacts": 1,
            "resource_reparse_candidate_artifacts": 1,
            "label_parse_signal_artifacts": 0,
            "parse_fallback_events_est": 3,
        },
    )

    outcome = RunOutcome(
        [app],
        datetime.now(UTC),
        datetime.now(UTC),
        sel,
        Path("/tmp"),
        [],
        [],
        total_artifacts=1,
        completed_artifacts=1,
    )
    from scytaledroid.StaticAnalysis.cli.core.models import RunParameters

    doc = build_run_health_document(
        outcome,
        RunParameters(profile="full", scope="profile", scope_label="L", session_stamp="sess2"),
        persistence_enabled=True,
        persist_attempted=True,
    )

    app_doc = doc["apps"][0]
    assert app_doc["final_status"] == "partial"
    assert app_doc["workflow_completion_status"] == "complete"
    assert app_doc["db_persistence_status"] == "ok"
    assert app_doc["detector_posture"] == "policy_or_finding_gates"
    assert app_doc["finding_fidelity_status"] == "complete"
    assert app_doc["parse_fallback_signals"]["resource_parse_partial_artifacts"] == 1
    assert app_doc["parse_fallback_signals"]["resource_reparse_candidate_artifacts"] == 1
    assert doc["status_reasons"]["resource_parse_partial_artifacts"] == 1
    assert doc["status_reasons"]["resource_reparse_candidate_artifacts"] == 1
    assert doc["run_rollups"]["resource_parse_partial_artifacts_total"] == 1
    assert doc["run_rollups"]["resource_reparse_candidate_artifacts_total"] == 1


def test_format_run_health_stdout_lines_adds_reasons_row() -> None:
    doc = {
        "final_run_status": "complete",
        "workflow_completion_status": "complete",
        "workflow_run_status": "complete",
        "detector_posture": "policy_or_finding_gates",
        "detector_posture_status": "policy_or_finding_gates",
        "finding_fidelity_status": "capped",
        "run_rollups": {
            "app_total": 1,
            "apps_complete_final": 0,
            "apps_partial_final": 1,
            "apps_failed_final": 0,
            "apps_skipped_final": 0,
            "detector_errors_total_estimate": 0,
            "detector_warnings_total_estimate": 3,
            "detector_failures_total_estimate": 1,
            "detector_posture": "policy_or_finding_gates",
            "detector_posture_status": "policy_or_finding_gates",
            "finding_fidelity_status": "capped",
            "scan_execution_complete": True,
            "artifacts_scan_completed_counter": 3,
            "artifact_total_discovered_estimate": 3,
            "findings_runtime_total": 100,
            "findings_persisted_db_total": 75,
            "findings_capped_not_persisted_total": 25,
            "p0_capped_not_persisted_total": 2,
        },
        "outputs": {},
        "status_reasons": {
            "detector_warnings": 3,
            "detector_failures": 1,
            "detector_errors": 0,
            "parse_fallbacks": 0,
            "resource_parse_partial_artifacts": 2,
            "resource_reparse_candidate_artifacts": 1,
            "string_status": "ok",
            "db_persistence_status": "ok",
            "detector_pipeline_status": "warnings_and_policy_failures",
            "detector_status": "warnings_and_policy_failures",
            "governance_grade": "experimental",
            "governance_reason": "missing_permission_intel",
        },
        "string_summary_note": {
            "string_summary_scope": "artifact_merged",
            "discovered_max_artifacts_per_app": 3,
        },
    }
    lines = format_run_health_stdout_lines(doc)
    assert len(lines) >= 4
    body = "\n".join(lines)
    assert "Execution        : complete" in body
    assert "Detector result  :" in body
    assert "detector_warnings=3" in body
    assert "policy_gate_failures=0" in body
    assert "finding_signals=1" in body
    assert "execution_errors=0 (none - not analyzer crashes)" in body
    assert "Finding fidelity : capped | runtime=100 persisted_db=75 capped_not_persisted=25" in body
    assert "Run completion   : COMPLETE" in body
    assert "Workflow status  : COMPLETE" in body
    assert "Detector posture : POLICY / FINDING GATES" in body
    assert "resource_parse_partial=2" in body
    assert "reparse_candidates=1" in body
    assert "pipeline_token=warnings_and_policy_failures" in body
    assert "String summary   : artifact_merged | max_artifacts_per_app=3" in body
    assert "Operator note    :" in body
    assert (
        "Legacy compatibility counters may still record detector-warning/gate apps under 'partial'"
        in body
    )
    assert (
        "Fidelity warning : CAPPED - 25 runtime findings were capped before canonical DB persistence."
        in body
    )
    assert (
        "High-priority fidelity warning: 2 P0 findings were capped before canonical DB persistence."
        in body
    )
    assert "Persistence note :" in body


def test_format_run_health_stdout_lines_preserves_explicit_zero_finding_signals() -> None:
    doc = {
        "workflow_completion_status": "complete",
        "detector_posture": "policy_or_finding_gates",
        "run_rollups": {
            "scan_execution_complete": True,
            "findings_runtime_total": 0,
            "findings_persisted_db_total": 0,
            "findings_capped_not_persisted_total": 0,
        },
        "status_reasons": {
            "detector_warnings": float("inf"),
            "detector_failures": 3,
            "detector_execution_errors": 0,
            "detector_errors": 9,
            "policy_gate_failures": 3,
            "finding_signals": 0,
            "detector_finding_failures": 0,
            "db_persistence_status": "ok",
            "string_status": "ok",
            "detector_pipeline_status": "policy_failures",
            "governance_grade": "ok",
            "governance_reason": "ready",
        },
    }

    body = "\n".join(format_run_health_stdout_lines(doc))

    assert "policy_gate_failures=3" in body
    assert "detector_warnings=0" in body
    assert "finding_signals=0" in body
    assert "execution_errors=0 (none - not analyzer crashes)" in body


def test_format_run_health_stdout_lines_surfaces_legacy_split_string_warning() -> None:
    doc = {
        "final_run_status": "complete",
        "workflow_completion_status": "complete",
        "workflow_run_status": "complete",
        "detector_posture": "clean",
        "detector_posture_status": "clean",
        "finding_fidelity_status": "complete",
        "outputs": {},
        "run_rollups": {
            "apps_complete_final": 1,
            "apps_partial_final": 0,
            "apps_failed_final": 0,
            "apps_skipped_final": 0,
            "detector_errors_total_estimate": 0,
            "detector_warnings_total_estimate": 0,
            "detector_failures_total_estimate": 0,
            "scan_execution_complete": True,
            "artifacts_scan_completed_counter": 10,
            "artifact_total_discovered_estimate": 10,
        },
        "status_reasons": {
            "detector_warnings": 0,
            "detector_failures": 0,
            "detector_errors": 0,
            "parse_fallbacks": 0,
            "string_status": "ok",
            "db_persistence_status": "ok",
            "detector_pipeline_status": "ok",
            "detector_status": "ok",
            "governance_grade": "ok",
            "governance_reason": "paper_grade_ready",
        },
        "string_summary_note": {
            "string_summary_scope": "base_apk_only",
            "discovered_max_artifacts_per_app": 10,
            "string_summary_warning": "split_specific_strings_not_in_post_summary: one or more split apps still lack a merged post-run string summary.",
        },
    }

    body = "\n".join(format_run_health_stdout_lines(doc))
    assert "String summary   : base_apk_only | max_artifacts_per_app=10" in body
    assert "String note      : split_specific_strings_not_in_post_summary" in body


def test_attach_run_health_outputs_prefers_real_file_location_for_display(tmp_path) -> None:
    base_dir = tmp_path / "data" / "store" / "apk"
    path = base_dir / "sess_run_health.json"
    doc: dict[str, object] = {"outputs": {}}

    attach_run_health_outputs_on_document(doc, path=path, base_dir=base_dir)

    outputs = doc["outputs"]
    assert isinstance(outputs, dict)
    assert outputs["run_health_json_relative"] == "sess_run_health.json"
    assert outputs["run_health_json_display"] == str(path)

    lines = format_run_health_stdout_lines(
        {
            "final_run_status": "complete",
            "workflow_completion_status": "complete",
            "workflow_run_status": "complete",
            "detector_posture": "clean",
            "detector_posture_status": "clean",
            "finding_fidelity_status": "complete",
            "outputs": outputs,
            "status_reasons": {},
        }
    )
    assert str(path) in lines[0]
    compact = compact_run_health_stdout_line(
        {
            "final_run_status": "complete",
            "workflow_completion_status": "complete",
            "workflow_run_status": "complete",
            "detector_posture": "clean",
            "detector_posture_status": "clean",
            "finding_fidelity_status": "complete",
            "outputs": outputs,
            "run_rollups": {
                "apps_complete_final": 1,
                "apps_with_caveats": 0,
                "apps_partial_final": 0,
                "apps_failed_final": 0,
            },
        }
    )
    assert str(path) in compact
    assert "workflow_completion_status=complete" in compact
    assert "detector_posture=clean" in compact
    assert "finding_fidelity_status=complete" in compact
    assert "apps_with_caveats=0" in compact


def test_build_run_health_document_includes_string_summary_note() -> None:
    sel = ScopeSelection(scope="profile", label="Research Dataset Alpha", groups=tuple())
    app = AppRunResult(
        "com.example.app", "Uncategorized", discovered_artifacts=45, final_status="partial"
    )
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
        RunParameters(
            profile="full",
            scope="profile",
            scope_label="Research Dataset Alpha",
            session_stamp="s1",
        ),
        persistence_enabled=False,
        persist_attempted=False,
    )
    note = doc["string_summary_note"]
    assert isinstance(note, dict)
    assert note["string_summary_scope"] == "base_apk_only"
    assert "string_summary_warning" in note


def test_build_run_health_document_marks_split_string_summary_merged() -> None:
    sel = ScopeSelection(scope="profile", label="Research Dataset Beta", groups=tuple())
    app = AppRunResult(
        "com.example.split",
        "Uncategorized",
        discovered_artifacts=3,
        final_status="complete",
        base_string_data={"aggregation_scope": "artifact_merged", "warnings": []},
    )
    outcome = RunOutcome(
        [app],
        datetime.now(UTC),
        datetime.now(UTC),
        sel,
        Path("/tmp/scytale-static"),
        [],
        [],
        total_artifacts=3,
        completed_artifacts=3,
    )
    from scytaledroid.StaticAnalysis.cli.core.models import RunParameters

    doc = build_run_health_document(
        outcome,
        RunParameters(
            profile="full", scope="profile", scope_label="Research Dataset Beta", session_stamp="s2"
        ),
        persistence_enabled=False,
        persist_attempted=False,
    )

    note = doc["string_summary_note"]
    assert isinstance(note, dict)
    assert note["string_summary_scope"] == "artifact_merged"
    assert "string_summary_warning" not in note
    app_note = doc["apps"][0]["string_summary"]
    assert app_note["string_summary_scope"] == "artifact_merged"
    assert "string_summary_warning" not in app_note
