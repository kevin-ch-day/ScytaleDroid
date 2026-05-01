from __future__ import annotations

from scytaledroid.Database.db_queries import views


def test_static_risk_surface_view_names_all_three_surfaces() -> None:
    sql = views.CREATE_VW_STATIC_RISK_SURFACES_LATEST.lower()

    assert "create or replace view vw_static_risk_surfaces_latest" in sql
    assert "risk_scores" in sql
    assert "permission_audit_apps" in sql
    assert "composite_static_surface_state" in sql
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
    assert "vw_static_risk_surfaces_latest" in sql
    assert "vw_static_finding_surfaces_latest" in sql
    assert "from permission_audit_apps" not in sql
    assert "from static_findings_summary" not in sql


def test_web_static_dynamic_summary_reads_explicit_latest_static_surfaces() -> None:
    sql = views.CREATE_V_WEB_STATIC_DYNAMIC_APP_SUMMARY.lower()

    assert "create or replace view v_web_static_dynamic_app_summary" in sql
    assert "vw_static_risk_surfaces_latest" in sql
    assert "vw_static_finding_surfaces_latest" in sql
    assert "from permission_audit_apps" not in sql
    assert "from static_findings_summary" not in sql
