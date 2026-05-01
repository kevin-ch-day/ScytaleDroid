from __future__ import annotations

from pathlib import Path

from scytaledroid.Database.db_utils.health_checks import analysis_integrity


def test_dynamic_evidence_path_state_counts_present_and_missing(monkeypatch, tmp_path: Path):
    existing = tmp_path / "evidence" / "run-a"
    existing.mkdir(parents=True)
    missing = tmp_path / "evidence" / "run-b"

    monkeypatch.setattr(
        analysis_integrity,
        "run_sql",
        lambda sql, *args, **kwargs: [(str(existing),), (str(missing),)],
    )

    tracked, missing_local = analysis_integrity._dynamic_evidence_path_state()

    assert tracked == 2
    assert missing_local == 1


def test_fetch_analysis_integrity_summary_includes_dynamic_retention_counts(monkeypatch):
    monkeypatch.setattr(analysis_integrity, "_missing_schema_objects", lambda: ())
    monkeypatch.setattr(
        analysis_integrity,
        "_legacy_non_utf8_package_tables",
        lambda: ("static_session_run_links",),
    )
    monkeypatch.setattr(analysis_integrity, "_dynamic_evidence_path_state", lambda: (140, 139))
    monkeypatch.setattr(analysis_integrity, "_dynamic_artifact_host_path_state", lambda: (21, 3769))
    monkeypatch.setattr(
        analysis_integrity,
        "preferred_static_dynamic_summary_relation",
        lambda **_kwargs: "web_static_dynamic_app_summary_cache",
    )
    monkeypatch.setattr(
        analysis_integrity,
        "static_dynamic_summary_cache_status",
        lambda **_kwargs: (547, "2026-04-27 18:00:00"),
    )

    def _scalar(sql: str, *_args, **_kwargs):
        if "FROM dynamic_sessions" in sql and "LEFT JOIN dynamic_network_features" not in sql:
            return 140
        if "FROM dynamic_network_features" in sql:
            return 37
        if "WHERE nf.dynamic_run_id IS NULL" in sql and "COALESCE(ds.countable, 0) = 1" not in sql:
            return 103
        if "COALESCE(ds.countable, 0) = 1" in sql:
            return 95
        if "FROM web_static_dynamic_app_summary_cache" in sql and "dynamic_feature_recency_state = 'latest_run_has_features'" in sql:
            return 1
        if "FROM web_static_dynamic_app_summary_cache" in sql and "dynamic_feature_recency_state = 'latest_run_missing_features_older_features_exist'" in sql:
            return 12
        if "FROM web_static_dynamic_app_summary_cache" in sql and "dynamic_feature_recency_state = 'no_feature_rows_for_package'" in sql:
            return 5
        if "WHERE ds.static_run_id IS NOT NULL" in sql:
            return 0
        if "FROM artifact_registry ar" in sql and "ar.run_type = 'dynamic'" in sql:
            return 0
        if "FROM artifact_registry ar" in sql and "ar.run_type = 'static'" in sql:
            return 0
        if "FROM apps a" in sql and "vw_static_risk_surfaces_latest" in sql:
            return 0
        if "FROM apps a" in sql and "LEFT JOIN app_versions" in sql:
            return 0
        if "SELECT COUNT(*)\n            FROM (\n              SELECT DISTINCT r.app_id, r.version_code" in sql:
            return 162
        if "FROM app_versions\n            WHERE target_sdk IS NULL" in sql:
            return 77
        if "FROM app_versions\n            WHERE min_sdk IS NULL" in sql:
            return 81
        if "JOIN static_analysis_runs sar ON sar.app_version_id = av.id\n            WHERE av.target_sdk IS NULL" in sql:
            return 0
        if "JOIN static_analysis_runs sar ON sar.app_version_id = av.id\n            WHERE av.min_sdk IS NULL" in sql:
            return 14
        if "SELECT COUNT(*)\n            FROM (\n              SELECT app_id, version_code" in sql:
            return 2
        if "SELECT COALESCE(SUM(x.c), 0)\n            FROM (\n              SELECT COUNT(*) AS c" in sql:
            return 4
        if "EXISTS (\n                SELECT 1 FROM static_permission_matrix" in sql:
            return 25
        if "LEFT JOIN runs r" in sql and "r.run_id IS NULL" in sql:
            return 3
        if "LEFT JOIN risk_scores rs" in sql and "rs.id IS NULL" in sql:
            return 4
        if "LEFT JOIN static_findings_summary sfs ON sfs.static_run_id = sar.id" in sql:
            return 5
        if "FROM vw_static_risk_surfaces_latest" in sql and "permission_run_score IS NOT NULL" in sql and "ABS(permission_run_score - permission_audit_score_capped)" not in sql and "permission_run_dangerous_count" not in sql:
            return 118
        if "FROM vw_static_risk_surfaces_latest" in sql and "ABS(permission_run_score - permission_audit_score_capped)" in sql:
            return 118
        if "FROM vw_static_risk_surfaces_latest" in sql and "permission_run_dangerous_count" in sql:
            return 26
        if "COUNT(DISTINCT COLLATION_NAME)" in sql:
            return 2
        raise AssertionError(f"Unexpected SQL: {sql}")

    monkeypatch.setattr(analysis_integrity, "scalar", _scalar)
    monkeypatch.setattr(analysis_integrity, "_float_scalar", lambda sql, *_a, **_k: 0.884 if "AVG(permission_run_score - permission_audit_score_capped)" in sql else None)

    summary = analysis_integrity.fetch_analysis_integrity_summary()

    assert summary.dynamic_runs == 140
    assert summary.dynamic_feature_rows == 37
    assert summary.dynamic_runs_missing_features == 103
    assert summary.countable_runs_missing_features == 95
    assert summary.packages_latest_run_has_features == 1
    assert summary.packages_latest_run_missing_features_older_features_exist == 12
    assert summary.packages_no_feature_rows_for_package == 5
    assert summary.dynamic_runs_with_evidence_path == 140
    assert summary.dynamic_runs_missing_local_evidence == 139
    assert summary.dynamic_artifact_host_paths_present == 21
    assert summary.dynamic_artifact_host_paths_missing == 3769
    assert summary.harvested_version_pairs_missing_from_app_versions == 162
    assert summary.app_versions_missing_target_sdk == 77
    assert summary.app_versions_missing_min_sdk == 81
    assert summary.referenced_app_versions_missing_target_sdk == 0
    assert summary.referenced_app_versions_missing_min_sdk == 14
    assert summary.duplicate_app_version_code_groups == 2
    assert summary.duplicate_app_version_rows == 4
    assert summary.interrupted_permission_partial_runs == 25
    assert summary.completed_static_runs_missing_legacy_runs == 3
    assert summary.completed_static_runs_missing_risk_scores == 4
    assert summary.completed_static_runs_missing_findings_summary == 5
    assert summary.risk_surface_rows_with_both_scores == 118
    assert summary.risk_surface_score_mismatch_rows == 118
    assert summary.risk_surface_count_mismatch_rows == 26
    assert summary.risk_surface_avg_score_delta == 0.884
    assert summary.static_dynamic_summary_source == "web_static_dynamic_app_summary_cache"
    assert summary.static_dynamic_summary_cache_rows == 547
    assert summary.static_dynamic_summary_cache_materialized_at == "2026-04-27 18:00:00"
    assert summary.package_collation_variants == 2
    assert summary.legacy_non_utf8_package_tables == ("static_session_run_links",)
    assert summary.missing_schema_objects == ()
