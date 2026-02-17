from __future__ import annotations

from scytaledroid.Database.db_queries import views
from scytaledroid.Database.db_queries.canonical import schema as canonical_schema


def test_latest_permission_risk_view_uses_risk_scores_not_legacy_table():
    sql = views.CREATE_VW_LATEST_PERMISSION_RISK.lower()
    assert "risk_scores" in sql
    assert "static_permission_risk" not in sql


def test_canonical_category_summary_uses_risk_scores_not_legacy_table():
    joined_sql = "\n".join(canonical_schema._DDL_STATEMENTS).lower()
    target = "create or replace view v_static_run_category_summary"
    assert target in joined_sql
    assert "left join risk_scores" in joined_sql
    assert "left join static_permission_risk" not in joined_sql
