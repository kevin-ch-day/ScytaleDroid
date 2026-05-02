from __future__ import annotations

from scytaledroid.Database.db_queries import views


def test_static_risk_surface_view_names_all_three_surfaces() -> None:
    sql = views.CREATE_VW_STATIC_RISK_SURFACES_LATEST.lower()

    assert "create or replace view vw_static_risk_surfaces_latest" in sql
    assert "from v_static_risk_surfaces_v1" in sql
    assert " from runs" not in sql
    assert " from buckets" not in sql
    assert "permission_audit_surface" in sql
    assert "composite_static_surface_state" in sql
    assert "canonical_static_latest" in sql
    assert "cli_runtime_only" in sql


def test_static_finding_surface_view_names_all_three_finding_layers() -> None:
    sql = views.CREATE_VW_STATIC_FINDING_SURFACES_LATEST.lower()

    assert "create or replace view vw_static_finding_surfaces_latest" in sql
    assert "static_analysis_findings" in sql
    assert "static_findings_summary" in sql
    assert "static_findings" in sql
    assert "baseline_section_hits_only" in sql


def test_web_app_directory_reads_explicit_latest_static_surfaces() -> None:
    sql = views.CREATE_V_WEB_APP_DIRECTORY.lower()

    assert "create or replace view v_web_app_directory" in sql
    assert "v_static_risk_surfaces_v1" in sql
    assert "vw_static_risk_surfaces_latest" not in sql
    assert "vw_static_finding_surfaces_latest" in sql
    assert "from permission_audit_apps" not in sql
    assert "from static_findings_summary" not in sql


def test_canonical_masvs_risk_views_avoid_legacy_tables() -> None:
    from scytaledroid.Database.db_queries import views_static

    f = views_static.CREATE_V_STATIC_MASVS_FINDINGS_V1.lower()
    m = views_static.CREATE_V_STATIC_MASVS_MATRIX_V1.lower()
    s = views_static.CREATE_V_STATIC_MASVS_SESSION_SUMMARY_V1.lower()
    r = views_static.CREATE_V_STATIC_RISK_SURFACES_V1.lower()
    compat_m = views_static.CREATE_V_MASVS_MATRIX.lower()
    for sql in (f, m, s, r):
        assert "create or replace view" in sql
        assert " from runs" not in sql
        assert " from buckets" not in sql
        assert " from findings " not in sql
        assert "masvs_control_coverage" not in sql
    assert "v_static_masvs_findings_v1" in f
    assert "v_static_masvs_matrix_v1" in m
    assert "v_static_masvs_session_summary_v1" in s
    assert "v_static_risk_surfaces_v1" in r
    assert "'no data'" in m or '"no data"' in m
    assert "masvs_network_status" in m
    assert "from v_static_masvs_matrix_v1" in compat_m
    assert " from runs" not in compat_m


def test_web_app_masvs_latest_reads_canonical_matrix_for_preferred_run() -> None:
    sql = views.CREATE_V_WEB_APP_MASVS_LATEST_V1.lower()

    assert "create or replace view v_web_app_masvs_latest_v1" in sql
    assert "from v_static_masvs_matrix_v1" in sql
    assert "preferred_static_run_id" in sql


def test_web_app_static_handoff_readiness_joins_handoff_contract_view() -> None:
    sql = views.CREATE_V_WEB_APP_STATIC_HANDOFF_READINESS_V1.lower()

    assert "create or replace view v_web_app_static_handoff_readiness_v1" in sql
    assert "from static_analysis_runs sar" in sql
    assert "left join v_static_handoff_v1 h" in sql


def test_web_static_dynamic_summary_reads_explicit_latest_static_surfaces() -> None:
    sql = views.CREATE_V_WEB_STATIC_DYNAMIC_APP_SUMMARY.lower()

    assert "create or replace view v_web_static_dynamic_app_summary" in sql
    assert "v_static_risk_surfaces_v1" in sql
    assert "vw_static_risk_surfaces_latest" not in sql
    assert "vw_static_finding_surfaces_latest" in sql
    assert "from permission_audit_apps" not in sql
    assert "from static_findings_summary" not in sql
