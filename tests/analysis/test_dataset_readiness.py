from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Reporting import menu_actions
from scytaledroid.Reporting.services import dataset_readiness
from scripts.publication import publication_ml_audit_report


def _write_manifest(run_dir: Path, payload: dict[str, object]) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(json.dumps(payload), encoding="utf-8")


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


def test_reporting_services_resolve_freeze_path_at_runtime(monkeypatch, tmp_path: Path) -> None:
    freeze_path = tmp_path / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_freeze.json"
    freeze_path.parent.mkdir(parents=True, exist_ok=True)
    freeze_path.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        publication_ml_audit_report,
        "resolve_dataset_freeze_read_path",
        lambda: freeze_path,
    )

    assert publication_ml_audit_report._freeze_path() == freeze_path


def test_fetch_tier1_status_exposes_quota_named_evidence_counts_with_compat_aliases(
    monkeypatch,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "output"
    data_dir = tmp_path / "data"
    dynamic_root = output_dir / "evidence" / "dynamic"

    _write_manifest(
        dynamic_root / "run-valid",
        {"dataset": {"tier": "dataset", "countable": True, "valid_dataset_run": True}},
    )
    _write_manifest(
        dynamic_root / "run-invalid",
        {"dataset": {"tier": "dataset", "countable": True, "valid_dataset_run": False}},
    )
    _write_manifest(
        dynamic_root / "run-supplemental",
        {"dataset": {"tier": "dataset", "countable": False, "valid_dataset_run": True}},
    )
    _write_manifest(
        dynamic_root / "run-other-tier",
        {"dataset": {"tier": "adhoc", "countable": True, "valid_dataset_run": True}},
    )

    monkeypatch.setattr(menu_actions.app_config, "OUTPUT_DIR", str(output_dir))
    monkeypatch.setattr(menu_actions.app_config, "DATA_DIR", str(data_dir))

    def fake_run_sql(sql, *args, **kwargs):  # noqa: ANN001
        if "SELECT version FROM schema_version" in sql:
            return {"version": "test-schema"}
        if "SELECT COUNT(*) AS cnt FROM dynamic_sessions WHERE tier='dataset'" in sql:
            return {"cnt": 12}
        if "SELECT COUNT(*) AS cnt FROM dynamic_sessions" in sql:
            return {"cnt": 14}
        if "SUM(CASE WHEN pcap_valid = 1 THEN 1 ELSE 0 END)" in sql:
            return {"valid_count": 9, "linked_count": 11}
        if "FROM dynamic_sessions ds" in sql and "telemetry_partial_samples" in sql:
            return {"cnt": 8}
        raise AssertionError(f"Unexpected SQL: {sql}")

    monkeypatch.setattr(menu_actions.core_q, "run_sql", fake_run_sql)

    status = menu_actions.fetch_tier1_status()

    assert status["db_dynamic_sessions_total"] == 14
    assert status["db_dynamic_sessions_dataset_tier"] == 12
    assert status["db_dynamic_sessions_dataset"] == 12
    assert status["evidence_packs_total"] == 4
    assert status["evidence_quota_eligible_packs"] == 2
    assert status["evidence_quota_valid_packs"] == 1
    assert status["evidence_dataset_packs"] == 2
    assert status["evidence_dataset_valid"] == 1
