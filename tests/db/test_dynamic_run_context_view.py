from __future__ import annotations

from scytaledroid.Database.db_queries import schema_manifest
from scytaledroid.Database.db_queries.sql_typed_reads import resolved_dynamic_session_static_run_id


def _manifest_sql() -> str:
    return "\n".join(schema_manifest.ordered_schema_statements())


def test_schema_manifest_includes_dynamic_run_context_view() -> None:
    sql = _manifest_sql()
    assert "CREATE OR REPLACE VIEW v_dynamic_run_context_v1" in sql


def test_dynamic_run_context_view_normalizes_effective_runtime_fields() -> None:
    sql = _manifest_sql()
    expected_static_expr = resolved_dynamic_session_static_run_id("ds")

    assert "ds.grade" in sql
    assert "technical_validity_state" in sql
    assert "quota_state" in sql
    assert "cohort_eligibility_state" in sql
    assert "effective_run_profile" in sql
    assert "COALESCE(ds.operator_run_profile, nf.run_profile, ds.profile_key, 'unknown') AS effective_run_profile" in sql
    assert (
        "COALESCE(ds.operator_interaction_level, nf.interaction_level, 'unknown') AS effective_interaction_level"
        in sql
    )
    assert "analysis_dynamic_cohort_status adcs" in sql
    assert "adcs.paper_eligible AS cohort_paper_eligible" in sql
    assert expected_static_expr in sql
    assert "AS effective_static_run_id" in sql


def test_dynamic_run_context_view_exposes_domain_service_signal_rollups() -> None:
    sql = _manifest_sql()

    assert "FROM dynamic_domain_observations obs" in sql
    assert "LEFT JOIN dynamic_service_domain_map sdm" in sql
    assert "LEFT JOIN dynamic_service_catalog svc" in sql
    assert "LEFT JOIN dynamic_service_signal_map ssm" in sql
    assert "LEFT JOIN dynamic_signal_catalog sig" in sql
    assert "COUNT(DISTINCT obs.observation_id) AS domain_observation_rows" in sql
    assert "COUNT(DISTINCT obs.observation_id" in sql
    assert "COUNT(DISTINCT svc.service_id) AS matched_service_count" in sql
    assert "COUNT(DISTINCT sig.signal_id) AS matched_signal_count" in sql
    assert "service_keys_csv" in sql
    assert "signal_keys_csv" in sql
