from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunOutcome, ScopeSelection
from scytaledroid.StaticAnalysis.cli.execution.run_health import (
    build_run_health_document,
    compute_run_aggregate_status,
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
