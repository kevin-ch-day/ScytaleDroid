from __future__ import annotations

from types import SimpleNamespace

import pytest

from scytaledroid.StaticAnalysis.cli.execution.results_persistence import (
    apply_persistence_outcome,
    collect_persistence_errors,
    merge_persistence_metadata,
)


pytestmark = [pytest.mark.contract, pytest.mark.report_contract]


def test_apply_persistence_outcome_tolerates_partial_status_object() -> None:
    app_result = SimpleNamespace(static_run_id=None)
    outcome = SimpleNamespace(
        persisted_findings=5,
        string_samples_persisted=2,
        persistence_retry_count=None,
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
