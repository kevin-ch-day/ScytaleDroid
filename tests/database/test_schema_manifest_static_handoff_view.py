from __future__ import annotations

from scytaledroid.Database.db_queries import schema_manifest


def test_manifest_orders_canonical_risk_before_legacy_compat_wrapper():
    statements = schema_manifest.ordered_schema_statements()
    idx_canon = next(
        i for i, stmt in enumerate(statements) if "CREATE OR REPLACE VIEW v_static_risk_surfaces_v1" in stmt
    )
    idx_wrap = next(
        i for i, stmt in enumerate(statements) if "CREATE OR REPLACE VIEW vw_static_risk_surfaces_latest" in stmt
    )
    assert idx_canon < idx_wrap


def test_schema_manifest_includes_static_handoff_view():
    statements = schema_manifest.ordered_schema_statements()
    found = any(
        "CREATE OR REPLACE VIEW v_static_handoff_v1" in stmt
        for stmt in statements
    )
    assert found


def test_v_static_handoff_manifest_sql_matches_contract_predicates():
    statements = schema_manifest.ordered_schema_statements()
    handoff = next(stmt for stmt in statements if "CREATE OR REPLACE VIEW v_static_handoff_v1" in stmt)
    low = handoff.lower()
    assert "upper(trim(coalesce(sar.run_class, ''))) = 'canonical'" in low
    assert "coalesce(sar.identity_valid, 0) = 1" in low


def test_manifest_orders_web_consumer_masvs_and_handoff_after_canonical_prereqs():
    statements = schema_manifest.ordered_schema_statements()
    idx_handoff_core = next(
        i for i, stmt in enumerate(statements) if "CREATE OR REPLACE VIEW v_static_handoff_v1" in stmt
    )
    idx_matrix = next(
        i for i, stmt in enumerate(statements) if "CREATE OR REPLACE VIEW v_static_masvs_matrix_v1" in stmt
    )
    idx_web_latest = next(
        i for i, stmt in enumerate(statements) if "CREATE OR REPLACE VIEW v_web_app_masvs_latest_v1" in stmt
    )
    idx_web_ready = next(
        i for i, stmt in enumerate(statements) if "CREATE OR REPLACE VIEW v_web_app_static_handoff_readiness_v1" in stmt
    )
    assert idx_handoff_core < idx_web_ready
    assert idx_matrix < idx_web_latest


def test_schema_manifest_includes_core_reporting_views():
    statements = schema_manifest.ordered_schema_statements()
    assert any("CREATE TABLE IF NOT EXISTS web_static_dynamic_app_summary_cache" in stmt for stmt in statements)
    required = [
        "CREATE OR REPLACE VIEW vw_latest_apk_per_package",
        "CREATE OR REPLACE VIEW vw_latest_permission_risk",
        "CREATE OR REPLACE VIEW vw_permission_audit_latest",
        "CREATE OR REPLACE VIEW vw_static_risk_surfaces_latest",
        "CREATE OR REPLACE VIEW vw_static_finding_surfaces_latest",
        "CREATE OR REPLACE VIEW v_run_overview",
        "CREATE OR REPLACE VIEW v_run_identity",
        "CREATE OR REPLACE VIEW v_runtime_dynamic_cohort_status_v1",
        "CREATE OR REPLACE VIEW v_web_app_directory",
        "CREATE OR REPLACE VIEW v_web_static_dynamic_app_summary",
        "CREATE OR REPLACE VIEW v_web_app_masvs_latest_v1",
        "CREATE OR REPLACE VIEW v_web_app_static_handoff_readiness_v1",
        "CREATE OR REPLACE VIEW v_web_runtime_run_index",
        "CREATE OR REPLACE VIEW v_web_runtime_run_detail",
        "CREATE OR REPLACE VIEW v_artifact_registry_integrity",
        "CREATE OR REPLACE VIEW v_current_artifact_registry",
        "CREATE OR REPLACE VIEW v_static_masvs_findings_v1",
        "CREATE OR REPLACE VIEW v_static_masvs_matrix_v1",
        "CREATE OR REPLACE VIEW v_static_masvs_session_summary_v1",
        "CREATE OR REPLACE VIEW v_static_risk_surfaces_v1",
    ]
    for marker in required:
        assert any(marker in stmt for stmt in statements), marker


def test_schema_manifest_uses_ascii_bin_for_static_finding_evidence_hashes():
    statements = schema_manifest.ordered_schema_statements()
    combined = "\n".join(statements).lower()
    assert (
        "evidence_hash char(64) character set ascii collate ascii_bin not null"
        in combined
    )
    assert (
        "evidence_hash char(64) character set ascii collate ascii_bin default null"
        in combined
    )


def test_schema_manifest_includes_dynamic_static_exact_hash_indexes():
    statements = schema_manifest.ordered_schema_statements()
    combined = "\n".join(statements).lower()
    assert "ix_dynamic_sessions_base_apk_sha256" in combined
    assert "on dynamic_sessions (base_apk_sha256)".lower() in combined
    assert "ix_static_runs_base_hash_contract" in combined
    assert (
        "on static_analysis_runs (base_apk_sha256, status, run_class, identity_valid)".lower()
        in combined
    )


def test_schema_manifest_includes_apk_install_set_spine():
    statements = schema_manifest.ordered_schema_statements()
    combined = "\n".join(statements)
    assert "CREATE TABLE IF NOT EXISTS harvest_sessions" in combined
    assert "CREATE TABLE IF NOT EXISTS apk_sets" in combined
    assert "CREATE TABLE IF NOT EXISTS apk_set_members" in combined
    assert "CREATE TABLE IF NOT EXISTS harvest_apk_observations" in combined
    assert "CREATE OR REPLACE VIEW v_apk_set_coverage_v1" in combined
    assert "ux_apk_sets_hash_version" in combined
    assert "artifact_set_hash_version" in combined
    assert "ADD COLUMN IF NOT EXISTS apk_set_id BIGINT UNSIGNED DEFAULT NULL" in combined
    assert "ix_static_runs_apk_set_id" in combined
    assert "ix_dynamic_sessions_apk_set_id" in combined
