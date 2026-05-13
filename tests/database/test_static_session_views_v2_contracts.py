from __future__ import annotations

from scytaledroid.Database.db_queries import views_static_sessions_v2 as v


def test_static_session_health_v2_eligibility_contract() -> None:
    sql = v.CREATE_V_STATIC_SESSION_HEALTH_V2.lower()
    assert "create or replace sql security invoker view v_static_session_health_v2" in sql
    assert "web_default_eligible" in sql
    assert "interrupted_run_count" in sql
    assert "persist_error_run_count" in sql
    assert "persistence_failure_rows" in sql
    assert "session_link_rows" in sql
    assert "rollup_rows" in sql
    assert "'completed_full_session'" in sql or '"completed_full_session"' in sql
    assert "'completed_profile_session'" in sql or '"completed_profile_session"' in sql
    assert "all harvested apps" in sql
    assert "trim(both from s.scope_label)" in sql
    assert "%all-full%" in sql
    assert "%smoke%" in sql
    assert "%phase4a%" in sql
    assert "from static_analysis_sessions s" in sql


def test_web_static_session_index_v2_filters_default_eligible() -> None:
    sql = v.CREATE_V_WEB_STATIC_SESSION_INDEX_V2.lower()
    assert "from v_static_session_health_v2 h" in sql
    assert "web_default_eligible = 1" in sql


def test_web_static_latest_session_by_scope_v2_windows_on_eligible() -> None:
    sql = v.CREATE_V_WEB_STATIC_LATEST_SESSION_BY_SCOPE_V2.lower()
    assert "from v_static_session_health_v2 h" in sql
    assert "partition by h.scope_label" in sql
    assert "web_default_eligible = 1" in sql


def test_static_session_cleanup_and_supersession_reference_health() -> None:
    cleanup = v.CREATE_V_STATIC_SESSION_CLEANUP_CANDIDATES_V2.lower()
    assert "from v_static_session_health_v2 h" in cleanup
    supers = v.CREATE_V_STATIC_SESSION_SUPERSESSION_CANDIDATES_V1.lower()
    assert "v_static_session_cleanup_candidates_v2 bad" in supers
    assert "v_static_session_health_v2 good" in supers
    assert "good.web_default_eligible = 1" in supers
