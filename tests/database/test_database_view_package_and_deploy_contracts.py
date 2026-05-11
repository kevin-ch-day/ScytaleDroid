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
        "SELECT CONVERT(package_name USING utf8mb4) COLLATE utf8mb4_general_ci AS package_name\n"
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
