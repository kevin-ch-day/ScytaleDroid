from __future__ import annotations

from types import SimpleNamespace

import pytest
from scytaledroid.StaticAnalysis.cli.execution import results_persist
from scytaledroid.StaticAnalysis.cli.execution.results_persistence import (
    apply_persistence_outcome,
    collect_persistence_errors,
    merge_persistence_metadata,
)
from scytaledroid.StaticAnalysis.cli.persistence.static_session_summary import (
    StaticSessionRunRollups,
)

pytestmark = [pytest.mark.contract, pytest.mark.report_contract]


def test_apply_persistence_outcome_tolerates_partial_status_object() -> None:
    app_result = SimpleNamespace(static_run_id=None)
    outcome = SimpleNamespace(
        persisted_findings=5,
        string_samples_persisted=2,
        persistence_retry_count=None,
        runtime_findings=9,
        findings_capped_total=4,
        findings_capped_by_detector={"d1": 4},
    )

    findings_delta, string_delta = apply_persistence_outcome(
        app_result=app_result,
        outcome_status=outcome,
    )

    assert findings_delta == 5
    assert string_delta == 2
    assert app_result.static_run_id is None
    assert app_result.persistence_retry_count == 0
    assert app_result.persistence_db_disconnect is False
    assert app_result.persistence_runtime_findings == 9
    assert app_result.persistence_persisted_findings == 5
    assert app_result.persistence_findings_capped_total == 4
    assert app_result.persistence_findings_capped_by_detector == {"d1": 4}


def test_collect_persistence_errors_tolerates_missing_success_flag() -> None:
    canonical, persistence, compat = collect_persistence_errors(
        outcome_status=SimpleNamespace(
            errors=[
                "canonical_enforcement_failed:run-1",
                "db_write_failed:metrics.write",
            ]
        )
    )

    assert canonical == ["canonical_enforcement_failed:run-1"]
    assert persistence == ["db_write_failed:metrics.write"]
    assert compat == []


def test_collect_persistence_errors_separates_compat_export_failures() -> None:
    canonical, persistence, compat = collect_persistence_errors(
        outcome_status=SimpleNamespace(
            success=False,
            compat_export_failed=True,
            errors=["db_write_failed:metrics.write"],
        )
    )

    assert canonical == []
    assert persistence == []
    assert compat == ["db_write_failed:metrics.write"]


def test_merge_persistence_metadata_preserves_existing_truthy_values() -> None:
    report = SimpleNamespace(metadata={"base_apk_sha256": "existing", "exploratory_only": False})
    app_result = SimpleNamespace(
        base_apk_sha256="new",
        artifact_set_hash=None,
        run_signature=None,
        run_signature_version=None,
        identity_valid=None,
        identity_error_reason=None,
        harvest_manifest_path=None,
        harvest_capture_status=None,
        harvest_persistence_status=None,
        harvest_research_status=None,
        harvest_matches_planned_artifacts=None,
        harvest_observed_hashes_complete=None,
        research_usable=None,
        exploratory_only=True,
        research_block_reasons=[],
    )
    params = SimpleNamespace(config_hash=None, analysis_version=None, catalog_versions=None)

    merge_persistence_metadata(base_report=report, app_result=app_result, params=params)

    assert report.metadata["base_apk_sha256"] == "existing"
    assert report.metadata["exploratory_only"] is False


def test_merge_persistence_metadata_carries_apk_set_id() -> None:
    report = SimpleNamespace(metadata={})
    app_result = SimpleNamespace(
        base_apk_sha256=None,
        artifact_set_hash=None,
        apk_set_id=144,
        run_signature=None,
        run_signature_version=None,
        identity_valid=None,
        identity_error_reason=None,
        harvest_manifest_path=None,
        harvest_capture_status=None,
        harvest_persistence_status=None,
        harvest_research_status=None,
        harvest_matches_planned_artifacts=None,
        harvest_observed_hashes_complete=None,
        research_usable=None,
        exploratory_only=None,
        research_block_reasons=[],
    )
    params = SimpleNamespace(config_hash=None, analysis_version=None, catalog_versions=None)

    merge_persistence_metadata(base_report=report, app_result=app_result, params=params)

    assert report.metadata["apk_set_id"] == 144


def test_persist_cohort_rollup_refreshes_static_session_header(monkeypatch) -> None:
    calls: list[tuple[str | None, str | None, str]] = []
    audit_refresh_calls: list[tuple[str | None, bool, bool]] = []
    materialize_calls: list[tuple[str | None, str | None]] = []

    monkeypatch.setattr(
        results_persist,
        "fetch_static_session_run_rollups",
        lambda stamp, scope: StaticSessionRunRollups(
            total_run_count=4,
            completed_run_count=4,
            failed_run_count=0,
            running_run_count=0,
            interrupted_run_count=0,
            persist_error_run_count=0,
            missing_artifacts_run_count=0,
            first_created_at=None,
            last_ended_at=None,
        ),
    )
    monkeypatch.setattr(
        results_persist,
        "materialize_static_session_rollup",
        lambda *, session_stamp, scope_label: materialize_calls.append((session_stamp, scope_label))
        or True,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.static_session_summary.maybe_refresh_static_analysis_session_summary",
        lambda stamp, scope, *, reason: calls.append((stamp, scope, reason)),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.flows.run_persistence_audit.refresh_persistence_audit_artifact_for_session",
        lambda session_stamp, *, write, prefer_reconcile: audit_refresh_calls.append(
            (session_stamp, write, prefer_reconcile)
        ),
    )

    results_persist._persist_cohort_rollup("sess-1", "All harvested apps")

    assert materialize_calls == [("sess-1", "All harvested apps")]
    assert calls == [("sess-1", "All harvested apps", "post_cohort_rollup")]
    assert audit_refresh_calls == [("sess-1", True, False)]
