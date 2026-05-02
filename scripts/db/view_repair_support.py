"""Shared helpers for operational SQL VIEW repair scripts (MariaDB/MySQL).

Not imported by runtime application code — scripts/db tooling only."""

from __future__ import annotations

import re
from typing import Callable

_VIEW_HEAD = re.compile(
    r"^\s*CREATE\s+OR\s+REPLACE\s+VIEW\s+`?([a-zA-Z0-9_]+)`?",
    re.IGNORECASE | re.MULTILINE,
)


def ddl_view_name(ddl: str) -> str | None:
    m = _VIEW_HEAD.match(ddl.strip())
    return m.group(1).strip().lower() if m else None


def views_from_ordered_schema_manifest() -> tuple[list[tuple[str, str]], dict[str, str]]:
    """Extract CREATE OR REPLACE VIEW statements in ``ordered_schema_statements()`` order."""

    from scytaledroid.Database.db_queries.schema_manifest import ordered_schema_statements

    ordered: list[tuple[str, str]] = []
    by_name: dict[str, str] = {}
    for stmt in ordered_schema_statements():
        name = ddl_view_name(stmt)
        if name is None:
            continue
        lk = name.lower()
        if lk in by_name:
            continue
        by_name[lk] = stmt
        ordered.append((name, stmt))
    return ordered, by_name


def web_consumer_extension_ddls(
    by_name: dict[str, str], *, force_full_chain: bool = False
) -> list[tuple[str, str]]:
    """DDL for v_web_* + supporting vw_*.

    When ``force_full_chain`` is False (default), skip objects already declared in the
    manifest so the **full** repair sequence does not duplicate DDL. When True (the
    **web**-only layer), emit every consumer view—``CREATE OR REPLACE VIEW`` remains
    idempotent even when the names also appear in ``ordered_schema_statements``.
    """

    from scytaledroid.Database.db_queries.views_inventory import CREATE_VW_LATEST_APK_PER_PACKAGE
    from scytaledroid.Database.db_queries.views_permission import (
        CREATE_VW_LATEST_PERMISSION_RISK,
        CREATE_VW_PERMISSION_AUDIT_LATEST,
        CREATE_V_WEB_PERMISSION_INTEL_CURRENT,
    )
    from scytaledroid.Database.db_queries.views_static import (
        CREATE_V_STATIC_HANDOFF_V1,
        CREATE_V_STATIC_MASVS_FINDINGS_V1,
        CREATE_V_STATIC_MASVS_MATRIX_V1,
        CREATE_V_STATIC_MASVS_SESSION_SUMMARY_V1,
        CREATE_V_STATIC_RISK_SURFACES_V1,
        CREATE_VW_STATIC_FINDING_SURFACES_LATEST,
        CREATE_VW_STATIC_RISK_SURFACES_LATEST,
    )
    from scytaledroid.Database.db_queries.views_web import (
        CREATE_V_WEB_APP_COMPONENT_ACL,
        CREATE_V_WEB_APP_COMPONENT_SUMMARY,
        CREATE_V_WEB_APP_COMPONENTS,
        CREATE_V_WEB_APP_DIRECTORY,
        CREATE_V_WEB_APP_FINDINGS,
        CREATE_V_WEB_APP_MASVS_LATEST_V1,
        CREATE_V_WEB_APP_PERMISSION_SUMMARY,
        CREATE_V_WEB_APP_PERMISSIONS,
        CREATE_V_WEB_APP_REPORT_SUMMARY,
        CREATE_V_WEB_APP_SESSIONS,
        CREATE_V_WEB_APP_STATIC_HANDOFF_READINESS_V1,
        CREATE_V_WEB_APP_STRING_SAMPLES,
        CREATE_V_WEB_APP_STRING_SUMMARY,
        CREATE_V_WEB_RUNTIME_RUN_DETAIL,
        CREATE_V_WEB_RUNTIME_RUN_INDEX,
        CREATE_V_WEB_STATIC_DYNAMIC_APP_SUMMARY,
        CREATE_V_WEB_STATIC_SESSION_HEALTH,
    )

    chain: list[tuple[str, str]] = [
        ("vw_latest_apk_per_package", CREATE_VW_LATEST_APK_PER_PACKAGE),
        ("vw_latest_permission_risk", CREATE_VW_LATEST_PERMISSION_RISK),
        ("vw_permission_audit_latest", CREATE_VW_PERMISSION_AUDIT_LATEST),
        ("v_static_masvs_findings_v1", CREATE_V_STATIC_MASVS_FINDINGS_V1),
        ("v_static_masvs_matrix_v1", CREATE_V_STATIC_MASVS_MATRIX_V1),
        ("v_static_masvs_session_summary_v1", CREATE_V_STATIC_MASVS_SESSION_SUMMARY_V1),
        ("v_static_handoff_v1", CREATE_V_STATIC_HANDOFF_V1),
        ("v_static_risk_surfaces_v1", CREATE_V_STATIC_RISK_SURFACES_V1),
        ("vw_static_risk_surfaces_latest", CREATE_VW_STATIC_RISK_SURFACES_LATEST),
        ("vw_static_finding_surfaces_latest", CREATE_VW_STATIC_FINDING_SURFACES_LATEST),
        ("v_web_static_session_health", CREATE_V_WEB_STATIC_SESSION_HEALTH),
        ("v_web_app_sessions", CREATE_V_WEB_APP_SESSIONS),
        ("v_web_app_permissions", CREATE_V_WEB_APP_PERMISSIONS),
        ("v_web_app_permission_summary", CREATE_V_WEB_APP_PERMISSION_SUMMARY),
        ("v_web_app_findings", CREATE_V_WEB_APP_FINDINGS),
        ("v_web_app_string_summary", CREATE_V_WEB_APP_STRING_SUMMARY),
        ("v_web_app_string_samples", CREATE_V_WEB_APP_STRING_SAMPLES),
        ("v_web_app_components", CREATE_V_WEB_APP_COMPONENTS),
        ("v_web_app_component_summary", CREATE_V_WEB_APP_COMPONENT_SUMMARY),
        ("v_web_app_component_acl", CREATE_V_WEB_APP_COMPONENT_ACL),
        ("v_web_permission_intel_current", CREATE_V_WEB_PERMISSION_INTEL_CURRENT),
        ("v_web_app_report_summary", CREATE_V_WEB_APP_REPORT_SUMMARY),
        ("v_web_app_directory", CREATE_V_WEB_APP_DIRECTORY),
        ("v_web_static_dynamic_app_summary", CREATE_V_WEB_STATIC_DYNAMIC_APP_SUMMARY),
        ("v_web_runtime_run_index", CREATE_V_WEB_RUNTIME_RUN_INDEX),
        ("v_web_runtime_run_detail", CREATE_V_WEB_RUNTIME_RUN_DETAIL),
    ]
    out: list[tuple[str, str]] = []
    for name, ddl in chain:
        if force_full_chain or name.lower() not in by_name:
            out.append((name, ddl))
    return out


def supplementary_reporting_ddls(by_name: dict[str, str]) -> list[tuple[str, str]]:
    """Views not included in bootstrap manifest (reporting/auxiliary surfaces)."""

    from scytaledroid.Database.db_queries.views_dynamic import CREATE_VW_DYNLOAD_HOTSPOTS
    from scytaledroid.Database.db_queries.views_static import (
        CREATE_V_MASVS_MATRIX,
        CREATE_VW_STATIC_MODULE_COVERAGE,
        CREATE_VW_STORAGE_SURFACE_RISK,
    )

    spec: list[tuple[str, Callable[[], str]]] = [
        ("vw_static_module_coverage", lambda: CREATE_VW_STATIC_MODULE_COVERAGE),
        ("vw_storage_surface_risk", lambda: CREATE_VW_STORAGE_SURFACE_RISK),
        ("vw_dynload_hotspots", lambda: CREATE_VW_DYNLOAD_HOTSPOTS),
        ("v_masvs_matrix", lambda: CREATE_V_MASVS_MATRIX),
    ]
    out: list[tuple[str, str]] = []
    for name, fac in spec:
        key = name.lower()
        if key not in by_name:
            ddl = fac()
            out.append((name, ddl))
            by_name[key] = ddl
    return out


def full_operational_view_repair_sequence() -> list[tuple[str, str]]:
    """Manifest-derived views plus supplementary + web-consumer extensions."""

    manifest_pairs, by_name = views_from_ordered_schema_manifest()
    extra_supp = supplementary_reporting_ddls(by_name)
    extra_web = web_consumer_extension_ddls(by_name)
    return [*manifest_pairs, *extra_supp, *extra_web]


def manifest_only_sequence() -> list[tuple[str, str]]:
    v, _ = views_from_ordered_schema_manifest()
    return v


def web_consumer_only_sequence() -> list[tuple[str, str]]:
    """Recreate full web-consumer stack (CREATE OR REPLACE; manifest overlap allowed)."""

    _, by_name = views_from_ordered_schema_manifest()
    return web_consumer_extension_ddls(by_name, force_full_chain=True)


EXPECTED_VIEW_OBJECTS: tuple[str, ...] = (
    # From analysis_integrity + extended operational contract (VIEW names only).
    # analysis_dynamic_cohort_status is a BASE TABLE (analysis/schema.py).
    "v_provider_exposure",
    "v_session_string_samples",
    "v_static_run_category_summary",
    "v_runtime_dynamic_cohort_status_v1",
    "v_paper_dynamic_cohort_v1",
    "v_run_overview",
    "v_run_identity",
    "v_static_handoff_v1",
    "v_web_app_directory",
    "v_web_static_dynamic_app_summary",
    "v_web_app_masvs_latest_v1",
    "v_web_app_static_handoff_readiness_v1",
    "v_web_runtime_run_index",
    "v_web_runtime_run_detail",
    "v_artifact_registry_integrity",
    "v_current_artifact_registry",
    "vw_latest_apk_per_package",
    "vw_latest_permission_risk",
    "vw_permission_audit_latest",
    "vw_static_risk_surfaces_latest",
    "vw_static_finding_surfaces_latest",
    "v_static_masvs_findings_v1",
    "v_static_masvs_matrix_v1",
    "v_static_masvs_session_summary_v1",
    "v_static_risk_surfaces_v1",
    "v_masvs_matrix",
    "v_web_app_sessions",
    "v_web_app_findings",
    "v_web_app_permissions",
    "v_web_permission_intel_current",
    "v_web_static_session_health",
)


REQUIRED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("static_analysis_runs", "findings_runtime_total", "INT UNSIGNED NULL"),
    ("static_analysis_runs", "findings_capped_total", "INT UNSIGNED NULL"),
    ("static_analysis_runs", "findings_capped_by_detector_json", "JSON DEFAULT NULL"),
    ("static_analysis_findings", "severity_raw", "VARCHAR(64) DEFAULT NULL AFTER severity"),
)


def _cli() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Shared helpers for operational SQL VIEW repair (imported by recreate_web_consumer_views); "
            "not a standalone operator entrypoint."
        ),
    )
    parser.parse_args()
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
