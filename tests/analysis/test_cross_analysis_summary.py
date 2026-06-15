from __future__ import annotations

from scytaledroid.Reporting.services import cross_analysis_summary


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
            }
        ]

    monkeypatch.setattr(cross_analysis_summary.core_q, "run_sql", fake_run_sql)

    rows = cross_analysis_summary.fetch_cross_analysis_summary_rows(profile_key="RESEARCH_DATASET_ALPHA")

    assert rows[0]["package_name"] == "com.alpha.app"
    assert rows[0]["latest_static_run_id"] == 11
    assert rows[0]["latest_dynamic_run_id"] == "dyn-1"
    assert rows[0]["dynamic_bytes_per_sec"] == 1.25
    assert calls
    sql, params, query_name = calls[0]
    assert query_name == "reporting.fetch_cross_analysis_summary_rows"
    assert "LOWER(package_name) COLLATE utf8mb4_general_ci IN" in sql
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

    def fake_run_sql(sql, params=(), *, fetch="all_dict", query_name=None, **_kwargs):  # noqa: ANN001,ARG001
        calls.append((sql, tuple(params), query_name))
        return []

    monkeypatch.setattr(cross_analysis_summary.core_q, "run_sql", fake_run_sql)

    rows = cross_analysis_summary.fetch_cross_analysis_summary_rows(profile_key="RESEARCH_DATASET_ALPHA")

    assert rows == []
    assert calls
    sql, params, query_name = calls[0]
    assert query_name == "reporting.fetch_cross_analysis_summary_rows"
    assert "profile_key = %s" in sql
    assert params == ("RESEARCH_DATASET_ALPHA",)
