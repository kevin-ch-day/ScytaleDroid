from __future__ import annotations

import inspect

from scytaledroid.Database.db_queries import views
from scytaledroid.Database.db_queries.canonical import schema as canonical_schema
from scytaledroid.Database.db_utils.health_checks import inventory_checks


def test_latest_permission_risk_view_uses_risk_scores_not_legacy_table():
    sql = views.CREATE_VW_LATEST_PERMISSION_RISK.lower()
    assert "risk_scores" in sql
    assert "static_permission_risk" not in sql
    assert "collate utf8mb4_unicode_ci" in sql


def test_run_identity_view_normalizes_package_name_collation():
    sql = views.CREATE_V_RUN_IDENTITY.lower()
    assert "dynamic_sessions" in sql
    assert "collate utf8mb4_unicode_ci" in sql
    assert "convert(ds.package_name using utf8mb4)" in sql


def test_inventory_case_drift_check_normalizes_package_name_collation():
    source = inspect.getsource(inventory_checks.run_inventory_snapshot_checks).lower()
    assert "collate utf8mb4_unicode_ci" in source
    assert "convert(i.package_name using utf8mb4)" in source
    assert "convert(a.package_name using utf8mb4)" in source


def test_canonical_category_summary_uses_risk_scores_not_legacy_table():
    joined_sql = "\n".join(canonical_schema._DDL_STATEMENTS).lower()
    target = "create or replace view v_static_run_category_summary"
    assert target in joined_sql
    assert "left join risk_scores" in joined_sql
    assert "left join static_permission_risk" not in joined_sql
