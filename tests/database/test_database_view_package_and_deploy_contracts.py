"""Package name helpers, web view SQL contracts, views façade exports, deploy remediation.

Merged from ``test_package_utils``, ``test_web_view_static_preference``,
``test_views_module_exports``, ``test_view_deploy_remediation``.
"""

from __future__ import annotations

from scytaledroid.Database.db_queries import views
from scytaledroid.Database.db_queries import (
    views_admin,
    views_bridge,
    views_dynamic,
    views_inventory,
    views_permission,
    views_static,
    views_web,
)
from scytaledroid.Database.db_scripts import view_deploy_remediation as vdr
from scytaledroid.Database.db_utils.package_utils import (
    is_invalid_package_name,
    is_suspicious_package_name,
    normalize_package_name,
)


# --- package_utils ---


def test_normalize_package_name_rejects_numeric_only_token() -> None:
    assert normalize_package_name("20260204", context="test") == ""
    assert is_invalid_package_name("20260204") is True


def test_apk_suffix_package_is_quarantined_not_rejected() -> None:
    package_name = "com.google.android.appsearch.apk"
    assert normalize_package_name(package_name, context="test") == package_name
    assert is_invalid_package_name(package_name) is False
    assert is_suspicious_package_name(package_name) is True


# --- Web view SQL (static preference / canonical rows) ---


def test_web_app_directory_prefers_completed_canonical_static_rows() -> None:
    sql = views.CREATE_V_WEB_APP_DIRECTORY
    assert (
        "SELECT CONVERT(package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci AS package_name\n"
        "  FROM apps\n  UNION" in sql
    )
    assert "UPPER(COALESCE(sar2.status, '')) = 'COMPLETED'" in sql
    assert "UPPER(COALESCE(sar2.run_class, '')) = 'CANONICAL'" in sql


def test_web_static_dynamic_summary_prefers_completed_canonical_static_rows() -> None:
    sql = views.CREATE_V_WEB_STATIC_DYNAMIC_APP_SUMMARY
    assert "UPPER(COALESCE(sar2.status, '')) = 'COMPLETED'" in sql
    assert "UPPER(COALESCE(sar2.run_class, '')) = 'CANONICAL'" in sql
    assert "UPPER(COALESCE(sar3.status, '')) = 'COMPLETED'" in sql
    assert "UPPER(COALESCE(sar3.run_class, '')) = 'CANONICAL'" in sql
    assert "latest_feature_dynamic_run_id" in sql
    assert "latest_run_missing_features_older_features_exist" in sql


def test_web_runtime_run_index_prefers_dynamic_run_context_semantics() -> None:
    sql = views.CREATE_V_WEB_RUNTIME_RUN_INDEX
    assert "FROM v_dynamic_run_context_v1 ctx" in sql
    assert "ctx.technical_validity_state" in sql
    assert "ctx.quota_state" in sql
    assert "ctx.cohort_eligibility_state" in sql
    assert "ctx.cohort_status" in sql
    assert "ctx.cohort_reason_code" in sql
    assert "ctx.countable" in sql
    assert "ctx.valid_dataset_run" in sql
    assert "FROM dynamic_sessions ds" not in sql


def test_web_dynamic_app_queue_v1_uses_cohort_and_quota_semantics() -> None:
    sql = views.CREATE_V_WEB_DYNAMIC_APP_QUEUE_V1
    assert "CREATE OR REPLACE VIEW v_web_dynamic_app_queue_v1" in sql
    assert "research_cohort_members" in sql
    assert "research_dataset_beta" in sql
    assert "v_dynamic_run_context_v1" in sql
    assert "baseline_quota_counted" in sql
    assert "interactive_quota_counted" in sql
    assert "current_build_baseline_quota_counted" in sql
    assert "all_build_baseline_quota_counted" in sql
    assert "legacy_unknown_runs" in sql
    assert "baseline_extra_valid" in sql
    assert "baseline_low_signal_retained" in sql
    assert "collection_status" in sql
    assert "quota_gap_label" in sql
    assert "data_scope" in sql
    assert "db_current_build" in sql
    assert "latest_scoped_valid_dataset_run" in sql
    assert "current_build_invalid_run_count" in sql
    assert "3 AS baseline_required" in sql
    assert "4 AS interactive_required" in sql


def test_web_runtime_run_detail_enriches_dynamic_sessions_with_context_states() -> None:
    sql = views.CREATE_V_WEB_RUNTIME_RUN_DETAIL
    assert "FROM dynamic_sessions ds" in sql
    assert "LEFT JOIN v_dynamic_run_context_v1 ctx" in sql
    assert "ctx.technical_validity_state" in sql
    assert "ctx.quota_state" in sql
    assert "ctx.cohort_eligibility_state" in sql
    assert "ctx.cohort_status" in sql
    assert "ctx.cohort_reason_code" in sql
    assert "COALESCE(NULLIF(ctx.app_label, ''), NULLIF(a.display_name, ''), ds.package_name) AS app_label" in sql


def test_web_app_report_summary_centralizes_details_bridge() -> None:
    sql = views.CREATE_V_WEB_APP_REPORT_SUMMARY
    assert "COALESCE(sfs.details, strs.findings_details) AS details_json" in sql
    assert "LEFT JOIN static_findings_summary sfs" in sql
    assert "LEFT JOIN v_web_app_string_summary strs" in sql


# --- views façade __all__ ---


def test_views_facade_exports_union_of_domain_modules():
    domain_modules = (
        views_inventory,
        views_static,
        views_dynamic,
        views_web,
        views_permission,
        views_bridge,
        views_admin,
    )
    expected = []
    for module in domain_modules:
        expected.extend(module.__all__)

    assert views.__all__ == expected


def test_views_facade_symbols_exist_and_are_sql_strings():
    for symbol in views.__all__:
        value = getattr(views, symbol)
        assert isinstance(value, str)
        assert "CREATE OR REPLACE VIEW" in value


# --- view_deploy_remediation ---


def test_sql_object_missing_error_detects_mysql_1146():
    class E(Exception):
        pass

    exc = E(1146, "Table 'db.v_static_masvs_matrix_v1' doesn't exist")
    assert vdr.sql_object_missing_error(exc)


def test_sql_object_missing_error_string_fallback():
    assert vdr.sql_object_missing_error(RuntimeError("Table 'x.y' doesn't exist"))


def test_remediation_text_mentions_repair_entrypoint():
    text = vdr.remediation_text()
    assert "recreate_web_consumer_views.py" in text
