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
                "valid_runs": 1,
                "quota_valid_runs": 1,
                "supplemental_valid_runs": 0,
                "invalid_runs": 0,
                "legacy_unknown_runs": 0,
                "analysis_runs": 1,
                "analysis_baseline_runs": 1,
                "analysis_interactive_runs": 0,
                "pcap_valid": "Y",
            }
        ]

    monkeypatch.setattr(dataset_readiness.core_q, "run_sql", fake_run_sql)

    snapshot, rows = dataset_readiness.fetch_dataset_readiness_dashboard()

    assert snapshot == {"ready": True}
    assert rows[0]["package_name"] == "com.alpha.app"
    assert rows[0]["quota_valid_runs"] == 1
    assert rows[0]["canonical_runs"] == 1
    assert rows[0]["status"] == "DATASET_READY_ANALYSIS"
    assert calls
    sql, params, query_name = calls[0]
    assert query_name == "reporting.fetch_dataset_readiness_dashboard"
    assert "FROM v_dynamic_run_context_v1" in sql
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
    assert "FROM v_dynamic_run_context_v1" in sql
    assert "WHERE a.profile_key = %s" in sql
    assert params == ("RESEARCH_DATASET_ALPHA",)


def test_fetch_dataset_readiness_dashboard_backfills_canonical_runs_from_quota_valid(monkeypatch) -> None:
    monkeypatch.setattr(
        dataset_readiness,
        "resolve_research_cohort_packages",
        lambda cohort_key, fallback_profile_key=None: ["com.alpha.app"],  # noqa: ARG005
    )
    monkeypatch.setattr(dataset_readiness, "fetch_latest_analysis_snapshot", lambda: None)

    def fake_run_sql(sql, params=(), *, fetch="all_dict", query_name=None, **_kwargs):  # noqa: ANN001,ARG001
        assert query_name == "reporting.fetch_dataset_readiness_dashboard"
        return [
            {
                "display_name": "Alpha",
                "package_name": "com.alpha.app",
                "installed": "Y",
                "harvested": "Y",
                "static_ready": "Y",
                "dyn_runs": 2,
                "valid_runs": 1,
                "quota_valid_runs": 1,
                "supplemental_valid_runs": 0,
                "invalid_runs": 0,
                "legacy_unknown_runs": 0,
                "analysis_runs": 0,
                "analysis_baseline_runs": 0,
                "analysis_interactive_runs": 0,
                "pcap_valid": "Y",
            }
        ]

    monkeypatch.setattr(dataset_readiness.core_q, "run_sql", fake_run_sql)

    _snapshot, rows = dataset_readiness.fetch_dataset_readiness_dashboard()

    assert rows[0]["quota_valid_runs"] == 1
    assert rows[0]["canonical_runs"] == 1


def test_classify_dataset_readiness_distinguishes_valid_invalid_and_legacy_capture() -> None:
    base = {
        "installed": "Y",
        "harvested": "Y",
        "static_ready": "Y",
        "analysis_runs": 0,
        "dyn_runs": 1,
        "valid_runs": 0,
        "quota_valid_runs": 0,
        "invalid_runs": 0,
        "legacy_unknown_runs": 0,
    }

    valid_row = {**base, "valid_runs": 1, "quota_valid_runs": 1}
    invalid_row = {**base, "invalid_runs": 1}
    legacy_row = {**base, "legacy_unknown_runs": 1}
    mixed_row = {**base, "invalid_runs": 1, "legacy_unknown_runs": 1}

    assert dataset_readiness.classify_dataset_readiness(valid_row) == "CAPTURED_VALID_NOT_IN_ANALYSIS"
    assert dataset_readiness.classify_dataset_readiness(invalid_row) == "INVALID_EVIDENCE_ONLY"
    assert dataset_readiness.classify_dataset_readiness(legacy_row) == "LEGACY_EVIDENCE_ONLY"
    assert dataset_readiness.classify_dataset_readiness(mixed_row) == "INVALID_AND_LEGACY_ONLY"
