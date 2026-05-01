from __future__ import annotations

from scytaledroid.Database.db_queries import views


def test_web_app_directory_prefers_completed_canonical_static_rows() -> None:
    sql = views.CREATE_V_WEB_APP_DIRECTORY
    assert "SELECT package_name COLLATE utf8mb4_general_ci AS package_name\n  FROM apps\n  UNION" in sql
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
