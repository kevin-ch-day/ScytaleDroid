from __future__ import annotations

from scytaledroid.Publication.metric_v2 import (
    aggregate_dynamic_metrics_v2,
    classify_dynamic_evidence_v2,
    compare_metric_methods,
    component_exposure_from_findings_v2,
    median_of_observed,
)
from scytaledroid.Reporting.study_profiles.static_exposure_privacy import (
    _component_exposure_from_findings,
)


def test_median_skips_missing_instead_of_zero() -> None:
    v1_like = [1.0, 0.0, 3.0]  # missing coerced to 0
    v2 = median_of_observed([1.0, None, 3.0])
    assert v2["median"] == 2.0
    assert v2["n_missing"] == 1
    assert v2["missing_treated_as_zero"] is False
    comparison = compare_metric_methods(
        v1_result=1.0,
        v2_result=v2["median"],
        reason="v1 treated missing as observed zero; v2 omits missing before median",
    )
    assert comparison["numeric_changed"] is True
    assert comparison["frozen_outputs_modified"] is False
    assert median_of_observed(v1_like)["median"] == 1.0


def test_missing_baseline_is_not_strict_idle() -> None:
    assert classify_dynamic_evidence_v2({"run_profile": "baseline_idle"}) == "unknown_baseline"
    assert (
        classify_dynamic_evidence_v2(
            {"run_profile": "baseline_idle", "baseline_not_idle": False}
        )
        == "strict_idle"
    )
    assert (
        classify_dynamic_evidence_v2(
            {"run_profile": "baseline_idle", "baseline_not_idle": True}
        )
        == "qfg"
    )


def test_eligibility_is_applied_before_median() -> None:
    rows = [
        {"run_profile": "baseline_idle", "baseline_not_idle": False, "bytes": 10, "status": "COMPLETED"},
        {"run_profile": "baseline_idle", "baseline_not_idle": False, "bytes": 1000, "analytic_eligible": False},
        {"run_profile": "interactive", "bytes": 50, "status": "FAILED"},
    ]
    result = aggregate_dynamic_metrics_v2(
        rows,
        field="bytes",
        snapshot_id="fixture-metric-v2",
        source="unit_fixture",
    )
    assert result["n_eligible"] == 1
    assert result["eligibility_applied_before_median"] is True
    assert result["by_class"]["strict_idle"]["median"] == 10
    assert result["by_class"]["strict_idle"]["denominator"] == 1


def test_component_exposure_prefers_finding_id_over_title() -> None:
    findings = [
        {
            "finding_id": "ipc_activity_open_com.example.Open",
            "title": "unrelated title that would miss v1 substring matching",
            "rule_id": "ipc_activity_open_com.example.Open",
        }
    ]
    v1 = _component_exposure_from_findings(findings)
    v2 = component_exposure_from_findings_v2(findings)
    assert v1["exported_activities"] == 0
    assert v2["exported_activities"] == 1
    assert v2["unguarded_ipc_components"] == 1
    assert v2["identity_source_rule_id_count"] == 1
    comparison = compare_metric_methods(
        v1_result=v1["exported_activities"],
        v2_result=v2["exported_activities"],
        reason="v1 title substring miss; v2 uses finding_id",
    )
    assert comparison["numeric_changed"] is True
    assert comparison["frozen_outputs_modified"] is False
