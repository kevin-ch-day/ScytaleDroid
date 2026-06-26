from __future__ import annotations

from scytaledroid.Reporting.services import cross_analysis_summary
from scytaledroid.Reporting.menu_actions_cross_analysis_helpers import compact_runtime_state


def test_fetch_cross_analysis_summary_rows_prefers_research_cohort_packages(monkeypatch) -> None:
    calls: list[tuple[str, tuple[object, ...], str | None]] = []

    monkeypatch.setattr(
        cross_analysis_summary,
        "resolve_research_cohort_packages",
        lambda cohort_key, fallback_profile_key=None: ["com.alpha.app", "com.beta.app"],  # noqa: ARG005
    )
    monkeypatch.setattr(
        cross_analysis_summary,
        "preferred_static_dynamic_summary_relation",
        lambda runner=None: "v_summary_test",  # noqa: ARG005
    )
    monkeypatch.setattr(
        cross_analysis_summary,
        "static_dynamic_summary_relation_has_required_runtime_columns",
        lambda relation, runner=None: relation == "v_summary_test",  # noqa: ARG005
    )

    def fake_run_sql(sql, params=(), *, fetch="all_dict", query_name=None, **_kwargs):  # noqa: ANN001,ARG001
        calls.append((sql, tuple(params), query_name))
        return [
            {
                "package_name": "com.alpha.app",
                "app_label": "Alpha",
                "category": "News",
                "profile_key": "RESEARCH_DATASET_ALPHA",
                "profile_label": "Research Dataset Alpha",
                "latest_static_run_id": 11,
                "latest_dynamic_run_id": "dyn-1",
                "latest_feature_dynamic_run_id": "dyn-1",
                "static_source_state": "OK",
                "permission_audit_grade": "B",
                "latest_dynamic_grade": "PAPER_GRADE",
                "dynamic_run_profile": "baseline_idle",
                "dynamic_interaction_level": "baseline",
                "dynamic_feature_state": "complete",
                "dynamic_feature_recency_state": "fresh",
                "regime_final_label": "normal",
                "summary_state": "ready",
                "dynamic_bytes_per_sec": 1.25,
                "dynamic_packets_per_sec": 2.5,
                "dynamic_technical_validity_state": "TECH_VALID",
                "dynamic_quota_state": "QUOTA_VALID",
                "dynamic_cohort_eligibility_state": "COHORT_ELIGIBLE",
            }
        ]

    monkeypatch.setattr(cross_analysis_summary.core_q, "run_sql", fake_run_sql)

    rows = cross_analysis_summary.fetch_cross_analysis_summary_rows(profile_key="RESEARCH_DATASET_ALPHA")

    assert rows[0]["package_name"] == "com.alpha.app"
    assert rows[0]["latest_static_run_id"] == 11
    assert rows[0]["latest_dynamic_run_id"] == "dyn-1"
    assert rows[0]["dynamic_bytes_per_sec"] == 1.25
    assert rows[0]["dynamic_technical_validity_state"] == "TECH_VALID"
    assert rows[0]["dynamic_quota_state"] == "QUOTA_VALID"
    assert rows[0]["dynamic_cohort_eligibility_state"] == "COHORT_ELIGIBLE"
    assert calls
    sql, params, query_name = calls[0]
    assert query_name == "reporting.fetch_cross_analysis_summary_rows"
    assert "LOWER(summary.package_name) COLLATE utf8mb4_general_ci IN" in sql
    assert "summary.dynamic_technical_validity_state" in sql
    assert "summary.dynamic_quota_state" in sql
    assert "summary.dynamic_cohort_eligibility_state" in sql
    assert "LEFT JOIN v_dynamic_run_context_v1 ctx" not in sql
    assert params == ("com.alpha.app", "com.beta.app")


def test_fetch_cross_analysis_summary_rows_falls_back_to_profile_filter(monkeypatch) -> None:
    calls: list[tuple[str, tuple[object, ...], str | None]] = []

    monkeypatch.setattr(
        cross_analysis_summary,
        "resolve_research_cohort_packages",
        lambda cohort_key, fallback_profile_key=None: [],  # noqa: ARG005
    )
    monkeypatch.setattr(
        cross_analysis_summary,
        "preferred_static_dynamic_summary_relation",
        lambda runner=None: "v_summary_test",  # noqa: ARG005
    )
    monkeypatch.setattr(
        cross_analysis_summary,
        "static_dynamic_summary_relation_has_required_runtime_columns",
        lambda relation, runner=None: relation == "v_summary_test",  # noqa: ARG005
    )

    def fake_run_sql(sql, params=(), *, fetch="all_dict", query_name=None, **_kwargs):  # noqa: ANN001,ARG001
        calls.append((sql, tuple(params), query_name))
        return []

    monkeypatch.setattr(cross_analysis_summary.core_q, "run_sql", fake_run_sql)

    rows = cross_analysis_summary.fetch_cross_analysis_summary_rows(profile_key="RESEARCH_DATASET_ALPHA")

    assert rows == []
    assert calls
    sql, params, query_name = calls[0]
    assert query_name == "reporting.fetch_cross_analysis_summary_rows"
    assert "summary.profile_key = %s" in sql
    assert params == ("RESEARCH_DATASET_ALPHA",)


def test_compact_runtime_state_prefers_normalized_runtime_labels() -> None:
    assert compact_runtime_state("TECH_VALID", "QUOTA_VALID") == "valid/quota"
    assert compact_runtime_state("TECH_VALID", "SUPPLEMENTAL_VALID") == "valid/supp"
    assert compact_runtime_state("TECH_INVALID", "QUOTA_INELIGIBLE") == "invalid/inelig"
    assert compact_runtime_state("TECH_LEGACY_UNKNOWN", "QUOTA_LEGACY_UNKNOWN") == "legacy/legacy"


def test_fetch_cross_analysis_summary_rows_falls_back_to_context_join_when_summary_relation_lacks_runtime_columns(
    monkeypatch,
) -> None:
    calls: list[tuple[str, tuple[object, ...], str | None]] = []

    monkeypatch.setattr(
        cross_analysis_summary,
        "resolve_research_cohort_packages",
        lambda cohort_key, fallback_profile_key=None: ["com.alpha.app"],  # noqa: ARG005
    )
    monkeypatch.setattr(
        cross_analysis_summary,
        "preferred_static_dynamic_summary_relation",
        lambda runner=None: "v_summary_legacy",  # noqa: ARG005
    )
    monkeypatch.setattr(
        cross_analysis_summary,
        "static_dynamic_summary_relation_has_required_runtime_columns",
        lambda relation, runner=None: False,  # noqa: ARG005
    )

    def fake_run_sql(sql, params=(), *, fetch="all_dict", query_name=None, **_kwargs):  # noqa: ANN001,ARG001
        calls.append((sql, tuple(params), query_name))
        return [
            {
                "package_name": "com.alpha.app",
                "app_label": "Alpha",
                "category": "News",
                "profile_key": "RESEARCH_DATASET_ALPHA",
                "profile_label": "Research Dataset Alpha",
                "latest_static_run_id": 11,
                "latest_dynamic_run_id": "dyn-1",
                "latest_feature_dynamic_run_id": "dyn-1",
                "static_source_state": "OK",
                "permission_audit_grade": "B",
                "latest_dynamic_grade": "PAPER_GRADE",
                "dynamic_run_profile": "baseline_idle",
                "dynamic_interaction_level": "baseline",
                "dynamic_feature_state": "complete",
                "dynamic_feature_recency_state": "fresh",
                "regime_final_label": "normal",
                "summary_state": "ready",
                "dynamic_bytes_per_sec": 1.25,
                "dynamic_packets_per_sec": 2.5,
                "dynamic_technical_validity_state": "TECH_VALID",
                "dynamic_quota_state": "QUOTA_VALID",
                "dynamic_cohort_eligibility_state": "COHORT_ELIGIBLE",
            }
        ]

    monkeypatch.setattr(cross_analysis_summary.core_q, "run_sql", fake_run_sql)

    rows = cross_analysis_summary.fetch_cross_analysis_summary_rows(profile_key="RESEARCH_DATASET_ALPHA")

    assert rows[0]["dynamic_technical_validity_state"] == "TECH_VALID"
    assert rows[0]["dynamic_quota_state"] == "QUOTA_VALID"
    assert rows[0]["dynamic_cohort_eligibility_state"] == "COHORT_ELIGIBLE"
    assert calls
    sql, params, query_name = calls[0]
    assert query_name == "reporting.fetch_cross_analysis_summary_rows"
    assert "LEFT JOIN v_dynamic_run_context_v1 ctx" in sql
    assert "ctx.technical_validity_state AS dynamic_technical_validity_state" in sql
    assert "summary.dynamic_technical_validity_state" not in sql
    assert params == ("com.alpha.app",)
