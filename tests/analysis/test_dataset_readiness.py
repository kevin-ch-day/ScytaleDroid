from __future__ import annotations

from scytaledroid.Reporting.services import dataset_readiness


def test_fetch_dataset_readiness_dashboard_prefers_research_cohort_members(monkeypatch) -> None:
    calls: list[tuple[str, tuple[object, ...], str | None]] = []

    monkeypatch.setattr(
        dataset_readiness,
        "resolve_research_cohort_packages",
        lambda cohort_key, fallback_profile_key=None: ["com.alpha.app", "com.beta.app"],  # noqa: ARG005
    )
    monkeypatch.setattr(dataset_readiness, "fetch_latest_analysis_snapshot", lambda: {"ready": True})

    def fake_run_sql(sql, params=(), *, fetch="all_dict", query_name=None, **_kwargs):  # noqa: ANN001,ARG001
        calls.append((sql, tuple(params), query_name))
        return [
            {
                "display_name": "Alpha",
                "package_name": "com.alpha.app",
                "installed": "Y",
                "harvested": "Y",
                "static_ready": "Y",
                "dyn_runs": 2,
                "analysis_runs": 1,
                "canonical_runs": 1,
                "analysis_baseline_runs": 1,
                "analysis_interactive_runs": 0,
                "pcap_valid": "Y",
            }
        ]

    monkeypatch.setattr(dataset_readiness.core_q, "run_sql", fake_run_sql)

    snapshot, rows = dataset_readiness.fetch_dataset_readiness_dashboard()

    assert snapshot == {"ready": True}
    assert rows[0]["package_name"] == "com.alpha.app"
    assert rows[0]["status"] == "DATASET_READY_ANALYSIS"
    assert calls
    sql, params, query_name = calls[0]
    assert query_name == "reporting.fetch_dataset_readiness_dashboard"
    assert "LOWER(a.package_name) COLLATE utf8mb4_general_ci IN" in sql
    assert params == ("com.alpha.app", "com.beta.app")


def test_fetch_dataset_readiness_dashboard_falls_back_to_profile_key(monkeypatch) -> None:
    calls: list[tuple[str, tuple[object, ...], str | None]] = []

    monkeypatch.setattr(
        dataset_readiness,
        "resolve_research_cohort_packages",
        lambda cohort_key, fallback_profile_key=None: [],  # noqa: ARG005
    )
    monkeypatch.setattr(dataset_readiness, "fetch_latest_analysis_snapshot", lambda: None)

    def fake_run_sql(sql, params=(), *, fetch="all_dict", query_name=None, **_kwargs):  # noqa: ANN001,ARG001
        calls.append((sql, tuple(params), query_name))
        return []

    monkeypatch.setattr(dataset_readiness.core_q, "run_sql", fake_run_sql)

    snapshot, rows = dataset_readiness.fetch_dataset_readiness_dashboard(profile_key="RESEARCH_DATASET_ALPHA")

    assert snapshot is None
    assert rows == []
    assert calls
    sql, params, query_name = calls[0]
    assert query_name == "reporting.fetch_dataset_readiness_dashboard"
    assert "WHERE a.profile_key = %s" in sql
    assert params == ("RESEARCH_DATASET_ALPHA",)
