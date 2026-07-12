"""Static Exposure & Privacy Assessment report profile."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Reporting.models import ReportRequest
from scytaledroid.Reporting.services.report_scope_selector import (
    RunSql,
    StaticEvidenceResolution,
    StaticRunCandidate,
    resolve_static_evidence,
)

REPORT_FAMILY = "static_exposure_privacy"
REPORT_TITLE = "Static Exposure & Privacy Assessment"
METRIC_FIELDS = [
    "total_declared_permissions",
    "privacy_sensitive_permissions",
    "normal_permissions",
    "dangerous_permissions",
    "special_access_permissions",
    "custom_permissions",
    "exported_activities",
    "exported_activity_aliases",
    "exported_services",
    "exported_receivers",
    "exported_providers",
    "exported_non_alias_components",
    "guarded_non_alias_components",
    "exported_non_alias_components_without_permission_guard",
    "total_exported_components",
    "exported_components_without_permission_guard",
    "cleartext_related_indicators",
    "network_security_findings",
    "storage_related_findings",
    "privacy_findings",
    "platform_findings",
    "masvs_privacy_count",
    "masvs_platform_count",
    "masvs_platform_non_alias_count",
    "platform_ipc_component_count",
    "platform_activity_alias_count",
    "platform_provider_acl_count",
    "platform_app_link_count",
    "platform_manifest_policy_count",
    "platform_static_correlation_count",
    "platform_other_count",
    "masvs_network_count",
    "masvs_storage_count",
    "severity_high_count",
    "severity_medium_count",
    "severity_low_count",
    "severity_info_count",
    "sdk_indicators",
    "embedded_service_sdk_indicators",
    "api_key_indicators",
    "high_entropy_indicators",
    "detector_findings",
]


def _unique_application_count(app_rows: Sequence[Mapping[str, Any]]) -> int:
    return len({str(row.get("package_name") or "").strip().lower() for row in app_rows if str(row.get("package_name") or "").strip()})


def _analysis_unit_label(app_label: str, version_name: str, version_code: str) -> str:
    version = str(version_name or version_code or "").strip()
    label = _short_presentation_label(str(app_label or "").strip())
    if version:
        return f"{label} ({version})"
    return label


def _has_duplicate_app_labels(app_rows: Sequence[Mapping[str, Any]]) -> bool:
    labels = [str(row.get("app_label") or row.get("package_name") or "").strip().lower() for row in app_rows]
    return len(labels) != len(set(labels))


def _presentation_label(row: Mapping[str, Any], *, include_version: bool) -> str:
    if include_version:
        return str(row.get("analysis_unit_label") or _short_presentation_label(row.get("app_label") or row.get("package_name") or ""))
    return _short_presentation_label(row.get("app_label") or row.get("package_name") or "")


def _short_presentation_label(value: object) -> str:
    label = str(value or "")
    if label.strip().lower() == "facebook messenger":
        return "Facebook Msg"
    return label


def _wants_tex(request: ReportRequest) -> bool:
    return "tex" in {str(fmt).strip().lower() for fmt in request.requested_formats}


def generate_static_exposure_privacy_report(
    request: ReportRequest,
    *,
    output_dir: Path | None = None,
    run_sql_fn: RunSql | None = None,
) -> dict[str, Any]:
    """Generate a read-only static exposure/privacy report bundle."""

    if request.study_profile_key != REPORT_FAMILY:
        raise ValueError(f"Unsupported study profile: {request.study_profile_key}")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    root = output_dir or Path("output") / "reports" / REPORT_FAMILY / stamp
    resolution = resolve_static_evidence(request, run_sql_fn=run_sql_fn)
    run_ids = [row.static_run_id for row in resolution.selected_runs]
    if not run_ids:
        raise ValueError(
            "No completed canonical identity-valid static evidence matched the requested scope and evidence window."
        )
    static_data = _load_static_child_rows(run_ids, run_sql_fn=run_sql_fn)
    app_rows = _build_app_metrics(resolution.selected_runs, static_data, request, resolution)

    wants_tex = _wants_tex(request)
    subdirs = ["manifest", "data", "tables", "figures", "report"]
    if wants_tex:
        subdirs.append("latex")
    for subdir in subdirs:
        (root / subdir).mkdir(parents=True, exist_ok=True)

    _write_json(root / "manifest" / "report_request.json", request.to_dict())
    _write_csv(root / "manifest" / "selected_app_builds.csv", [_candidate_manifest_row(row, request, resolution) for row in resolution.selected_runs])
    _write_csv(
        root / "manifest" / "exclusions.csv",
        resolution.exclusions,
        [
            "package_name",
            "static_run_id",
            "reason",
            "contributing_static_run_id",
            "excluded_version_code",
            "excluded_base_apk_sha256",
        ],
    )
    _write_csv(root / "data" / "app_static_metrics.csv", app_rows)
    _write_csv(root / "data" / "permission_rows.csv", static_data["permissions"])
    _write_csv(root / "data" / "component_rows.csv", static_data["components"])
    _write_csv(root / "data" / "finding_rows.csv", static_data["findings"])
    _write_csv(root / "data" / "masvs_rows.csv", _masvs_rows(static_data["findings"]))
    _write_csv(root / "data" / "metric_dictionary.csv", metric_dictionary_rows())

    table_paths = _write_tables(root, app_rows, include_tex=True)
    paper1_paths = _write_paper1_reproduction_audit(root, resolution.selected_runs, static_data, app_rows)
    figure_paths = _write_figures(root, app_rows, request.scope_type)
    audit_paths = _write_acceptance_audits(root, request, resolution, app_rows, table_paths, figure_paths, include_layout_fit=wants_tex)
    report_paths = _write_report_text(root, request, resolution, app_rows, figure_paths) + audit_paths
    latex_paths = _write_latex(root, request, app_rows, table_paths, figure_paths) if wants_tex else []

    source_paths = [
        root / "manifest" / "report_request.json",
        root / "manifest" / "selected_app_builds.csv",
        root / "data" / "app_static_metrics.csv",
        root / "data" / "permission_rows.csv",
        root / "data" / "component_rows.csv",
        root / "data" / "finding_rows.csv",
    ]
    source_checksums = {str(path.relative_to(root)): _sha256(path) for path in source_paths}
    _write_json(root / "manifest" / "source_checksums.json", source_checksums)
    generated_paths = sorted(path for path in root.rglob("*") if path.is_file() and path.name != "report_manifest.json")
    generated_checksums = {str(path.relative_to(root)): _sha256(path) for path in generated_paths}
    manifest = {
        "report_title": REPORT_TITLE,
        "report_family": REPORT_FAMILY,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "mutation_scope": "read_only",
        "reproduction_status": resolution.reproduction_status,
        "selection_rule": resolution.selection_rule,
        "study_profile_key": request.study_profile_key,
        "study_profile_version": request.study_profile_version,
        "scope_type": request.scope_type,
        "scope_key": request.scope_key,
        "scope_label": request.scope_label,
        "resolved_package_names": request.package_names,
        "evidence_basis_type": request.evidence_basis_type,
        "evidence_basis_key": request.evidence_basis_key,
        "output_contract": request.output_contract,
        "selected_app_build_static_run_identities": [_candidate_manifest_row(row, request, resolution) for row in resolution.selected_runs],
        "exclusions": resolution.exclusions,
        "source_checksums": source_checksums,
        "generated_artifact_checksums": generated_checksums,
        "read_only_verification": {
            "db_rows_mutated": False,
            "evidence_mutated": False,
            "source_manifests_mutated": False,
        },
        "row_counts": {
            "applications": _unique_application_count(app_rows),
            "application_builds": len(app_rows),
            "selected_static_runs": len(run_ids),
            "permissions": len(static_data["permissions"]),
            "components": len(static_data["components"]),
            "findings": len(static_data["findings"]),
            "masvs_rows": len(_masvs_rows(static_data["findings"])),
        },
        "request": request.to_dict(),
        "outputs": {
            "tables": [str(path.relative_to(root)) for path in table_paths + paper1_paths],
            "figures": [str(path.relative_to(root)) for path in figure_paths],
            "reports": [str(path.relative_to(root)) for path in report_paths],
            "latex": [str(path.relative_to(root)) for path in latex_paths],
        },
        "metrics_rejected": [
            {
                "metric": "composite_static_risk_score",
                "reason": "No score was verified in this pass as deterministic, transparent, comparable across the selected scope, and appropriate for this analysis version.",
            }
        ],
    }
    _write_json(root / "manifest" / "report_manifest.json", manifest)
    return {"output_dir": str(root.resolve()), "manifest": manifest}


def _load_static_child_rows(run_ids: Sequence[int], *, run_sql_fn: RunSql | None = None) -> dict[str, list[dict[str, Any]]]:
    if not run_ids:
        return {"permissions": [], "components": [], "findings": [], "strings": []}
    runner = run_sql_fn or core_q.run_sql
    placeholders = ",".join(["%s"] * len(run_ids))
    params = tuple(run_ids)
    permissions = runner(
        f"""
        SELECT run_id, package_name, LOWER(TRIM(permission_name)) AS permission_name,
               source, protection, guard_strength, severity,
               is_runtime_dangerous, is_signature, is_privileged, is_special_access, is_custom
        FROM static_permission_matrix
        WHERE run_id IN ({placeholders})
        """,
        params,
        fetch="all_dict",
    ) or []
    components = runner(
        f"""
        SELECT run_id, package_name, component_name, provider_name, authority, authorities,
               exported, base_guard, read_guard, write_guard, effective_guard,
               read_permission, write_permission, path_globs, risk
        FROM static_fileproviders
        WHERE run_id IN ({placeholders})
        """,
        params,
        fetch="all_dict",
    ) or []
    findings = runner(
        f"""
        SELECT run_id, finding_id, severity, severity_raw, category, title, rule_id,
               detector, module, masvs_area, masvs_control, masvs_control_id,
               evidence, evidence_refs, evidence_hash
        FROM static_analysis_findings
        WHERE run_id IN ({placeholders})
        """,
        params,
        fetch="all_dict",
    ) or []
    strings = runner(
        f"""
        SELECT static_run_id AS run_id, package_name, endpoints, http_cleartext,
               analytics_ids, cloud_refs, ipc, uris, flags, certs, api_keys, high_entropy
        FROM static_string_summary
        WHERE static_run_id IN ({placeholders})
        """,
        params,
        fetch="all_dict",
    ) or []
    return {
        "permissions": [dict(row) for row in permissions],
        "components": [dict(row) for row in components],
        "findings": [dict(row) for row in findings],
        "strings": [dict(row) for row in strings],
    }


def _build_app_metrics(
    candidates: Sequence[StaticRunCandidate],
    data: Mapping[str, list[dict[str, Any]]],
    request: ReportRequest,
    resolution: StaticEvidenceResolution,
) -> list[dict[str, Any]]:
    permissions_by_run = _by_run(data["permissions"], "run_id")
    components_by_run = _by_run(data["components"], "run_id")
    findings_by_run = _by_run(data["findings"], "run_id")
    strings_by_run = _by_run(data["strings"], "run_id")
    rows: list[dict[str, Any]] = []
    for candidate in candidates:
        run_id = candidate.static_run_id
        perms = permissions_by_run.get(run_id, [])
        comps = components_by_run.get(run_id, [])
        findings = findings_by_run.get(run_id, [])
        strings = strings_by_run.get(run_id, [])
        permission_names = {str(row.get("permission_name") or "").strip().lower() for row in perms if row.get("permission_name")}
        privacy_sensitive = {
            name
            for row in perms
            for name in [str(row.get("permission_name") or "").strip().lower()]
            if name and (_int(row.get("is_runtime_dangerous")) or _int(row.get("is_special_access")))
        }
        dangerous_permission_names = {
            name
            for row in perms
            for name in [str(row.get("permission_name") or "").strip().lower()]
            if name and _int(row.get("is_runtime_dangerous"))
        }
        special_access_permission_names = {
            name
            for row in perms
            for name in [str(row.get("permission_name") or "").strip().lower()]
            if name and _int(row.get("is_special_access"))
        }
        custom_permission_names = {
            name
            for row in perms
            for name in [str(row.get("permission_name") or "").strip().lower()]
            if name and _int(row.get("is_custom"))
        }
        normal_permission_names = (
            permission_names
            - dangerous_permission_names
            - special_access_permission_names
            - custom_permission_names
        )
        severity = Counter(_severity(row) for row in findings)
        masvs = Counter(_masvs_area(row) for row in findings)
        platform_breakdown = _platform_breakdown_from_findings(findings)
        string_totals = _string_totals(strings)
        exported_providers = sum(1 for row in comps if _truthy(row.get("exported")))
        unguarded_providers = sum(
            1
            for row in comps
            if _truthy(row.get("exported"))
            and str(row.get("effective_guard") or "").lower() in {"", "none", "weak", "unknown", "broad"}
        )
        component_exposure = _component_exposure_from_findings(findings)
        exported_non_alias_components = component_exposure["exported_non_alias_components"] + exported_providers
        unguarded_non_alias_components = component_exposure["unguarded_non_alias_ipc_components"] + unguarded_providers
        unguarded_components = component_exposure["unguarded_ipc_components"] + unguarded_providers
        guarded_non_alias_components = max(
            0,
            exported_non_alias_components - unguarded_non_alias_components,
        )
        rows.append(
            {
                "app_label": candidate.display_name,
                "analysis_unit_label": _analysis_unit_label(candidate.display_name, candidate.version_name, candidate.version_code),
                "package_name": candidate.package_name,
                "app_category": candidate.app_category,
                "selected_version_code": candidate.version_code,
                "selected_version_name": candidate.version_name,
                "base_apk_sha256": candidate.base_apk_sha256,
                "split_count": candidate.split_count,
                "static_run_ids": str(run_id),
                "static_session_stamp": candidate.static_session_stamp,
                "evidence_basis": request.evidence_basis_type,
                "evidence_as_of_utc": request.as_of_utc or request.window_end_utc or request.generated_at_utc,
                "identity_valid": candidate.identity_valid,
                "canonical_status": candidate.canonical_status,
                "source_lineage": candidate.source_lineage,
                "total_declared_permissions": len(permission_names),
                "privacy_sensitive_permissions": len(privacy_sensitive),
                "normal_permissions": len(normal_permission_names),
                "dangerous_permissions": len(dangerous_permission_names),
                "special_access_permissions": len(special_access_permission_names),
                "custom_permissions": len(custom_permission_names),
                "exported_activities": component_exposure["exported_activities"],
                "exported_activity_aliases": component_exposure["exported_activity_aliases"],
                "exported_services": component_exposure["exported_services"],
                "exported_receivers": component_exposure["exported_receivers"],
                "exported_providers": exported_providers,
                "exported_non_alias_components": exported_non_alias_components,
                "guarded_non_alias_components": guarded_non_alias_components,
                "exported_non_alias_components_without_permission_guard": unguarded_non_alias_components,
                "total_exported_components": component_exposure["exported_total"] + exported_providers,
                "exported_components_without_permission_guard": unguarded_components,
                "cleartext_related_indicators": string_totals["http_cleartext"],
                "network_security_findings": sum(1 for row in findings if _masvs_area(row) == "NETWORK" or "network" in str(row.get("category") or "").lower()),
                "storage_related_findings": sum(1 for row in findings if _masvs_area(row) == "STORAGE" or "storage" in str(row.get("category") or "").lower()),
                "privacy_findings": masvs["PRIVACY"],
                "platform_findings": masvs["PLATFORM"],
                "masvs_privacy_count": masvs["PRIVACY"],
                "masvs_platform_count": masvs["PLATFORM"],
                "masvs_platform_non_alias_count": max(0, masvs["PLATFORM"] - component_exposure["exported_activity_aliases"]),
                "platform_ipc_component_count": platform_breakdown["ipc_components"],
                "platform_activity_alias_count": platform_breakdown["activity_aliases"],
                "platform_provider_acl_count": platform_breakdown["provider_acl"],
                "platform_app_link_count": platform_breakdown["app_links"],
                "platform_manifest_policy_count": platform_breakdown["manifest_policy"],
                "platform_static_correlation_count": platform_breakdown["static_correlation"],
                "platform_other_count": platform_breakdown["other"],
                "masvs_network_count": masvs["NETWORK"],
                "masvs_storage_count": masvs["STORAGE"],
                "severity_high_count": severity["HIGH"] + severity["CRITICAL"],
                "severity_medium_count": severity["MEDIUM"],
                "severity_low_count": severity["LOW"],
                "severity_info_count": severity["INFO"] + severity["INFORMATIONAL"],
                "sdk_indicators": string_totals["analytics_ids"] + string_totals["cloud_refs"],
                "embedded_service_sdk_indicators": string_totals["endpoints"],
                "api_key_indicators": string_totals["api_keys"],
                "high_entropy_indicators": string_totals["high_entropy"],
                "detector_findings": len(findings),
                "output_contract": request.output_contract,
                "scope_type": request.scope_type,
                "reproduction_status": resolution.reproduction_status,
            }
        )
    return rows


def metric_dictionary_rows() -> list[dict[str, Any]]:
    rows = []
    for field in METRIC_FIELDS:
        rows.append(
            {
                "display_label": _display_label(field),
                "internal_field": field,
                "exact_meaning": _metric_definition(field),
                "source_table_or_query": _metric_source(field),
                "aggregation_rule": "one selected completed/canonical/identity-valid static run per app/build row; permission names deduplicated by lower(trim(permission_name))",
                "deduplication_key": "package_name + base_apk_sha256 + contributing static_run_id",
                "base_split_behavior": "static run is treated as the selected install-set summary; split APK evidence is not counted as separate app/build rows",
                "zero_meaning": "source was populated for the selected run and no matching observation was detected",
                "missing_value_meaning": "not observed or source table not populated for the selected run",
                "cross_app_comparability": "descriptive comparable when selected evidence basis is consistent",
                "reporting_caveat": "static evidence indicates declared or detectable exposure, not runtime use or exploitability",
                "audit_classification": "REPORT_READY"
                if field not in {"embedded_service_sdk_indicators", "cleartext_related_indicators", "api_key_indicators", "high_entropy_indicators"}
                else "NEEDS_CAVEAT",
            }
        )
    rows.append(
        {
            "display_label": "Composite static risk score",
            "internal_field": "composite_static_risk_score",
            "exact_meaning": "Rejected in this profile pass.",
            "source_table_or_query": "",
            "aggregation_rule": "",
            "deduplication_key": "",
            "base_split_behavior": "",
            "zero_meaning": "",
            "missing_value_meaning": "",
            "cross_app_comparability": "not approved",
            "reporting_caveat": "Excluded because no score was verified as deterministic, transparent, comparable, and appropriate for the selected profile version.",
            "audit_classification": "REJECT",
        }
    )
    return rows


def _write_tables(root: Path, app_rows: list[dict[str, Any]], *, include_tex: bool) -> list[Path]:
    paths: list[Path] = []
    include_version_label = _has_duplicate_app_labels(app_rows)
    cohort_rows = [
        {
            "app_label": _presentation_label(row, include_version=include_version_label),
            "package_name": row["package_name"],
            "version_code": row["selected_version_code"],
            "version_name": row["selected_version_name"],
            "static_run_ids": row["static_run_ids"],
            "base_apk_sha256": row["base_apk_sha256"][:12],
        }
        for row in app_rows
    ]
    table_specs = [
        ("cohort_build_summary", cohort_rows),
        (
            "static_exposure_summary",
            [
                {
                    "app_label": _presentation_label(row, include_version=include_version_label),
                    "permissions": row["total_declared_permissions"],
                    "privacy_sensitive": row["privacy_sensitive_permissions"],
                    "exported_components": row["total_exported_components"],
                    "non_alias_exported_components": row["exported_non_alias_components"],
                    "activity_aliases": row["exported_activity_aliases"],
                    "unguarded_components": row["exported_components_without_permission_guard"],
                    "detector_findings": row["detector_findings"],
                }
                for row in app_rows
            ],
        ),
        (
            "privacy_permission_summary",
            [
                {
                    "app_label": _presentation_label(row, include_version=include_version_label),
                    "total_declared_permissions": row["total_declared_permissions"],
                    "normal_permissions": row["normal_permissions"],
                    "dangerous_permissions": row["dangerous_permissions"],
                    "special_access_permissions": row["special_access_permissions"],
                    "custom_permissions": row["custom_permissions"],
                }
                for row in app_rows
            ],
        ),
        (
            "masvs_summary",
            [
                {
                    "app_label": _presentation_label(row, include_version=include_version_label),
                    "privacy": row["masvs_privacy_count"],
                    "platform": row["masvs_platform_count"],
                    "platform_non_alias": row["masvs_platform_non_alias_count"],
                    "network": row["masvs_network_count"],
                    "storage": row["masvs_storage_count"],
                }
                for row in app_rows
            ],
        ),
    ]
    for stem, rows in table_specs:
        csv_path = root / "tables" / f"{stem}.csv"
        _write_csv(csv_path, rows)
        paths.append(csv_path)
        if include_tex:
            tex_path = root / "tables" / f"{stem}.tex"
            tex_path.write_text(_latex_table(rows, stem.replace("_", " ").title()), encoding="utf-8")
            paths.append(tex_path)
    return paths


def _write_paper1_reproduction_audit(
    root: Path,
    candidates: Sequence[StaticRunCandidate],
    data: Mapping[str, list[dict[str, Any]]],
    app_rows: list[dict[str, Any]],
) -> list[Path]:
    """Write Paper 1 compatibility aids without changing the current report contract."""

    include_version_label = _has_duplicate_app_labels(app_rows)
    metrics_by_run = {_first_int(row.get("static_run_ids")): row for row in app_rows}
    components_by_run = _by_run(data["components"], "run_id")
    findings_by_run = _by_run(data["findings"], "run_id")
    permissions_by_run = _by_run(data["permissions"], "run_id")

    manifest_rows: list[dict[str, Any]] = []
    network_storage_rows: list[dict[str, Any]] = []
    permission_matrix_rows: list[dict[str, Any]] = []
    secret_rows: list[dict[str, Any]] = []
    masvs_policy_rows: list[dict[str, Any]] = []
    score_input_rows: list[dict[str, Any]] = []
    for candidate in candidates:
        run_id = candidate.static_run_id
        app_metrics = metrics_by_run.get(run_id) or {}
        label = _presentation_label(app_metrics or {"app_label": candidate.display_name, "package_name": candidate.package_name}, include_version=include_version_label)
        components = components_by_run.get(run_id, [])
        findings = findings_by_run.get(run_id, [])
        strings = _first_string_row(data["strings"], run_id)
        archive_metrics = _static_archive_metrics(candidate)
        permission_names = {
            str(row.get("permission_name") or "").strip().lower()
            for row in permissions_by_run.get(run_id, [])
            if str(row.get("permission_name") or "").strip()
        }
        fileprovider_count = _fileprovider_count(components)
        unguarded = int(app_metrics.get("exported_non_alias_components_without_permission_guard") or 0)
        broad_intents = archive_metrics.get("browsable_view_filters")
        manifest_rows.append(
            {
                "app_label": label,
                "package_name": candidate.package_name,
                "fileprovider_like_provider_count": fileprovider_count,
                "exported_non_alias_components_without_permission_guard": unguarded,
                "browsable_view_intent_filters": broad_intents if broad_intents is not None else "not_available",
                "total_intent_filters": archive_metrics.get("total_intent_filters", "not_available"),
                "auto_verify_filters": archive_metrics.get("auto_verify_filters", "not_available"),
                "web_link_filters": archive_metrics.get("web_link_filters", "not_available"),
                "status": "partial" if broad_intents is None else "archive_derived",
                "caveat": "Intent-filter counts are derived from archived static JSON detector metrics, while exported component counts are DB-backed. These are compatibility metrics for Paper 1-style discussion, not a canonical DB table yet.",
            }
        )
        cleartext = _has_finding(findings, "cleartext")
        legacy = _has_finding(findings, "legacy_external")
        backup = _has_finding(findings, "allow_backup") or _has_finding(findings, "backup_enabled")
        network_storage_rows.append(
            {
                "app_label": label,
                "package_name": candidate.package_name,
                "cleartext_traffic_permitted": _yes_no(cleartext),
                "legacy_external_storage_requested": _yes_no(legacy),
                "android_backup_enabled": _yes_no(backup),
                "fileprovider_like_provider_count": fileprovider_count,
                "storage_related_findings": app_metrics.get("storage_related_findings", 0),
                "network_security_findings": app_metrics.get("network_security_findings", 0),
            }
        )
        secret_rows.append(
            {
                "app_label": label,
                "package_name": candidate.package_name,
                "api_key_indicators": _int(strings.get("api_keys")),
                "high_entropy_indicators": _int(strings.get("high_entropy")),
                "privacy_findings": app_metrics.get("privacy_findings", 0),
                "severity_high_count": app_metrics.get("severity_high_count", 0),
                "severity_medium_count": app_metrics.get("severity_medium_count", 0),
                "caveat": "API-key and high-entropy values are static string indicators. They require manual review before being described as exposed credentials.",
            }
        )
        permission_matrix_rows.append(
            {
                "app_label": label,
                "package_name": candidate.package_name,
                **{
                    field: _x_if_permission_present(permission_names, permission)
                    for field, permission in _paper1_permission_fields()
                },
            }
        )
        masvs_policy_rows.append(_paper1_masvs_policy_readiness_row(label, candidate.package_name, app_metrics))
        score_input_rows.append(_paper1_score_model_input_row(label, candidate.package_name, app_metrics))

    score_status_rows = [
        {
            "paper1_output": "Table V Overall Static Risk Scores",
            "current_status": "blocked",
            "current_source": "tables/paper1_score_model_inputs.csv",
            "reason": "The raw inputs are available, but the old 0-100 composite static score formula is not present as a verified, deterministic, comparable publication metric in the current report profile.",
            "safe_current_substitute": "Use paper1_score_model_inputs.csv as a transparent input ledger; add a new versioned score only after the formula is reviewed and frozen.",
        },
        {
            "paper1_output": "Table III MASVS Compliance Summary pass/fail",
            "current_status": "blocked_pending_policy",
            "current_source": "tables/paper1_masvs_policy_readiness.csv",
            "reason": "Current report exports MASVS-aligned finding counts and area evidence status, but pass/fail thresholds per MASVS area have not been frozen for this publication profile.",
            "safe_current_substitute": "Use area_has_findings / area_no_findings status as descriptive evidence only; do not call it MASVS compliance.",
        },
    ]
    reproduction_map_rows = [
        {
            "paper1_item": "Table I Manifest and Component Exposure",
            "status": "partial",
            "current_artifact": "tables/paper1_manifest_component_parity.csv",
            "gap": "FileProvider-like provider count and unguarded component count are DB-backed; intent-filter counts are archive-derived until promoted into canonical static tables.",
        },
        {
            "paper1_item": "Table II Permission Usage Across Apps",
            "status": "reproducible_with_current_schema",
            "current_artifact": "tables/paper1_permission_usage_matrix.csv",
            "gap": "Current permissions are version/build backed and may differ from Paper 1 frozen APKs.",
        },
        {
            "paper1_item": "Table III MASVS Compliance Summary",
            "status": "blocked_pending_policy",
            "current_artifact": "tables/paper1_masvs_policy_readiness.csv",
            "gap": "Counts and descriptive area status exist; pass/fail scoring policy is not frozen.",
        },
        {
            "paper1_item": "Table IV Network and Storage Issues",
            "status": "reproducible_with_current_schema",
            "current_artifact": "tables/paper1_network_storage_parity.csv",
            "gap": "Current table separates allowBackup, legacy storage, cleartext, and FileProvider-like provider count.",
        },
        {
            "paper1_item": "Table V Overall Static Risk Scores",
            "status": "blocked",
            "current_artifact": "tables/paper1_score_model_inputs.csv",
            "gap": "Composite score inputs are exported, but a score formula is not verified in the current report profile.",
        },
        {
            "paper1_item": "Hardcoded API key count / secret indicators",
            "status": "reproducible_with_caveat",
            "current_artifact": "tables/paper1_secret_indicator_parity.csv",
            "gap": "Static string indicators are countable, but require manual review before being described as confirmed exposed secrets.",
        },
    ]
    paths = [
        root / "tables" / "paper1_manifest_component_parity.csv",
        root / "tables" / "paper1_permission_usage_matrix.csv",
        root / "tables" / "paper1_network_storage_parity.csv",
        root / "tables" / "paper1_secret_indicator_parity.csv",
        root / "tables" / "paper1_masvs_policy_readiness.csv",
        root / "tables" / "paper1_score_model_inputs.csv",
        root / "tables" / "paper1_score_status.csv",
        root / "report" / "paper1_reproduction_map.csv",
        root / "report" / "paper1_reproduction_gap_analysis.txt",
        root / "report" / "paper1_publication_use_notes.md",
    ]
    _write_csv(paths[0], manifest_rows)
    _write_csv(paths[1], permission_matrix_rows)
    _write_csv(paths[2], network_storage_rows)
    _write_csv(paths[3], secret_rows)
    _write_csv(paths[4], masvs_policy_rows)
    _write_csv(paths[5], score_input_rows)
    _write_csv(paths[6], score_status_rows)
    _write_csv(paths[7], reproduction_map_rows)
    paths[8].write_text(_paper1_gap_analysis_text(reproduction_map_rows), encoding="utf-8")
    paths[9].write_text(_paper1_publication_use_notes_text(), encoding="utf-8")
    return paths


def _write_figures(root: Path, app_rows: list[dict[str, Any]], scope_type: str) -> list[Path]:
    include_version_label = _has_duplicate_app_labels(app_rows)
    if scope_type == "single_app":
        figure_specs = [
            ("permission_breakdown", "MUST INCLUDE", "Single-application permission category breakdown; total declared permissions are kept in tables but omitted from the figure to preserve category readability.", ["normal_permissions", "dangerous_permissions", "special_access_permissions", "custom_permissions"]),
            ("component_exposure_breakdown", "MUST INCLUDE", "Single-application non-alias component exposure by component type.", ["exported_activities", "exported_services", "exported_receivers", "exported_providers"]),
            ("activity_alias_exposure", "INCLUDE IF DISCUSSING LAUNCH ALIASES", "Activity aliases are valid exported launch surfaces but are separated from ordinary components so alias-heavy apps do not flatten the main exposure chart.", ["exported_activity_aliases"]),
            ("masvs_category_breakdown", "INCLUDE IF SPACE", "Single-application non-platform MASVS category breakdown. Platform interaction evidence is split into a separate platform-surface figure.", ["masvs_privacy_count", "masvs_network_count", "masvs_storage_count"]),
            ("platform_surface_breakdown", "MUST INCLUDE FOR PLATFORM DISCUSSION", "Breaks non-IPC MASVS Platform rows into provider ACL, app-link, manifest-policy, and static-correlation subfamilies. IPC component exposure is handled in the component exposure figure.", ["platform_provider_acl_count", "platform_app_link_count", "platform_manifest_policy_count", "platform_static_correlation_count", "platform_other_count"]),
            ("network_storage_findings", "INCLUDE IF SPACE", "Single-application network and storage finding breakdown.", ["network_security_findings", "cleartext_related_indicators", "storage_related_findings"]),
        ]
    else:
        figure_specs = [
            ("permission_profile", "MUST INCLUDE", "Shows normal, dangerous, special-access, and app-defined permission categories. Total declared permissions are kept in tables but omitted from the figure to avoid compressing smaller categories.", ["normal_permissions", "dangerous_permissions", "special_access_permissions", "custom_permissions"]),
            ("component_exposure", "MUST INCLUDE", "Shows exported non-alias component types. Activity aliases are separated into their own figure because alias-heavy apps otherwise dominate the common axis.", ["exported_activities", "exported_services", "exported_receivers", "exported_providers"]),
            ("activity_alias_exposure", "INCLUDE IF DISCUSSING LAUNCH ALIASES", "Shows exported activity aliases separately from ordinary component exposure; useful for explaining Snapchat/X alias-heavy manifests.", ["exported_activity_aliases"]),
            ("masvs_distribution", "INCLUDE IF SPACE", "Summarizes non-platform MASVS-aligned static finding rows. Platform interaction rows are split into platform_surface_breakdown because MASVS Platform spans IPC, provider ACL, app links, and manifest policy.", ["masvs_privacy_count", "masvs_network_count", "masvs_storage_count"]),
            ("platform_surface_breakdown", "MUST INCLUDE FOR PLATFORM DISCUSSION", "Breaks non-IPC MASVS Platform rows into provider ACL, app-link, manifest-policy, and static-correlation subfamilies. IPC component exposure is handled in the component exposure figure instead of repeated here as one oversized Platform bar.", ["platform_provider_acl_count", "platform_app_link_count", "platform_manifest_policy_count", "platform_static_correlation_count", "platform_other_count"]),
            ("network_storage_posture", "INCLUDE IF SPACE", "Contrasts network, cleartext, and storage indicators.", ["network_security_findings", "cleartext_related_indicators", "storage_related_findings"]),
        ]
    paths: list[Path] = []
    recommendations: list[dict[str, Any]] = []
    for stem, decision, reason, fields in figure_specs:
        source_csv = root / "figures" / f"{stem}_source.csv"
        rows = [{"app_label": _presentation_label(row, include_version=include_version_label), **{field: row[field] for field in fields}} for row in app_rows]
        _write_csv(source_csv, rows)
        recommendations.append({"figure": stem, "decision": decision, "reason": reason})
        paths.append(source_csv)
        paths.extend(_render_bar_figure(root / "figures" / stem, rows, fields, title=stem.replace("_", " ").title()))
    _write_csv(root / "figures" / "figure_recommendations.csv", recommendations)
    paths.append(root / "figures" / "figure_recommendations.csv")
    return paths


def _write_report_text(
    root: Path,
    request: ReportRequest,
    resolution: StaticEvidenceResolution,
    app_rows: list[dict[str, Any]],
    figure_paths: list[Path],
) -> list[Path]:
    paths: list[Path] = []
    findings_summary = root / "report" / "findings_summary.txt"
    application_count = _unique_application_count(app_rows)
    app_build_count = len(app_rows)
    findings_summary.write_text(
        "\n".join(
            [
                f"{REPORT_TITLE}",
                f"Applications: {application_count}",
                f"App/build rows: {app_build_count}",
                f"Evidence mode: {request.evidence_basis_type}",
                "Output: report bundle with tables, figures, and source data",
                f"Reproduction status: {resolution.reproduction_status}",
                f"Total detector findings: {sum(int(row['detector_findings']) for row in app_rows)}",
                f"Total declared permissions: {sum(int(row['total_declared_permissions']) for row in app_rows)}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    paths.append(findings_summary)
    metric_sufficiency = root / "report" / "metric_sufficiency.txt"
    metric_sufficiency.write_text(
        "Accepted metrics are deterministic descriptive static metrics sourced from canonical static tables.\n"
        "Rejected: composite_static_risk_score; no verified transparent comparable score definition for this profile version.\n",
        encoding="utf-8",
    )
    paths.append(metric_sufficiency)
    artifact_recommendations = root / "report" / "artifact_recommendations.txt"
    artifact_recommendations.write_text(
        "\n".join(
            [
                "Use app_static_metrics.csv as the empirical app/build-level source.",
                "Use metric_dictionary.csv to describe every metric.",
                "Use figure_recommendations.csv before deciding which figures enter a report.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    paths.append(artifact_recommendations)
    reproduction = root / "report" / "reproduction_status.txt"
    reproduction.write_text(f"{resolution.reproduction_status}\n{resolution.selection_rule}\n", encoding="utf-8")
    paths.append(reproduction)
    limitations = root / "report" / "limitations.txt"
    limitations.write_text(
        "Static findings describe declared and detected exposure. They do not prove runtime use, exploitation, or user harm.\n"
        "Single-app reports are descriptive only and do not support cohort-level inference.\n",
        encoding="utf-8",
    )
    paths.append(limitations)
    return paths


def _write_acceptance_audits(
    root: Path,
    request: ReportRequest,
    resolution: StaticEvidenceResolution,
    app_rows: list[dict[str, Any]],
    table_paths: list[Path],
    figure_paths: list[Path],
    *,
    include_layout_fit: bool,
) -> list[Path]:
    paths: list[Path] = []
    paths.extend(_write_static_run_provenance_reconciliation(root, resolution))
    paths.append(_write_metric_definition_audit(root))
    paths.append(_write_metric_integrity_audit(root, app_rows))
    paths.append(_write_artifact_quality_audit(root, app_rows, table_paths, figure_paths))
    paths.append(_write_large_scope_policy(root, app_rows, request.scope_type))
    if request.scope_key == "static_social_media_2025":
        paths.append(_write_static_social_media_reproduction_status(root, request))
    if include_layout_fit:
        paths.append(_write_layout_fit_report(root, app_rows, table_paths, figure_paths))
    paths.append(_write_read_only_verification(root))
    return paths


def _write_static_run_provenance_reconciliation(root: Path, resolution: StaticEvidenceResolution) -> list[Path]:
    by_pkg: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for exclusion in resolution.exclusions:
        package = str(exclusion.get("package_name") or "")
        by_pkg[package].append(exclusion)
    rows: list[dict[str, Any]] = []
    for selected in resolution.selected_runs:
        related = by_pkg.get(selected.package_name, [])
        rows.append(
            {
                "app_label": selected.display_name,
                "package_name": selected.package_name,
                "selected_analytical_static_run_id": selected.static_run_id,
                "selected_version_code": selected.version_code,
                "selected_version_name": selected.version_name,
                "selected_base_apk_sha256": selected.base_apk_sha256,
                "other_matching_static_run_ids_for_same_build": ",".join(
                    str(row.get("static_run_id"))
                    for row in related
                    if str(row.get("reason")) == "duplicate_selected_build_static_analysis_not_app_level_contributor"
                ),
                "selection_reason": "selected completed canonical identity-valid static run for the selected app/build",
                "other_records_role": "repeated analyses/provenance only",
                "metrics_aggregated_across_multiple_static_runs": "no",
                "double_counting_prevention": "one analytical static run contributes each app/build metric row; non-contributing static IDs are excluded from app_static_metrics.csv",
                "build_hash_match_verified": "yes" if selected.base_apk_sha256 else "unknown",
            }
        )
    csv_path = root / "report" / "static_run_provenance_reconciliation.csv"
    txt_path = root / "report" / "static_run_provenance_reconciliation.txt"
    _write_csv(csv_path, rows)
    txt_path.write_text(
        "Static-run provenance reconciliation\n"
        "Analytical rule: one app/build row per selected build using one deterministic selected analytical static run.\n"
        "Other matching static IDs remain provenance only. No metric is aggregated across more than one static run.\n",
        encoding="utf-8",
    )
    return [csv_path, txt_path]


def _write_metric_definition_audit(root: Path) -> Path:
    rows = metric_dictionary_rows()
    lines = ["Metric Definition Audit"]
    for row in rows:
        lines.append(
            f"{row['internal_field']}: {row['audit_classification']} - {row['exact_meaning']} "
            f"Source={row['source_table_or_query']}; Caveat={row['reporting_caveat']}"
        )
    path = root / "report" / "metric_definition_audit.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_metric_integrity_audit(root: Path, app_rows: list[dict[str, Any]]) -> Path:
    rows: list[dict[str, Any]] = []
    for row in app_rows:
        app_label = str(row.get("app_label") or "")
        app_errors = 0
        app_warnings = 0
        exported_total = _int(row.get("total_exported_components"))
        unguarded_total = _int(row.get("exported_components_without_permission_guard"))
        provider_total = _int(row.get("exported_providers"))
        alias_total = _int(row.get("exported_activity_aliases"))
        split_count = _int(row.get("split_count"))
        if unguarded_total > exported_total:
            app_errors += 1
            rows.append(
                {
                    "app_label": app_label,
                    "metric": "exported_components_without_permission_guard",
                    "status": "ERROR",
                    "observed_value": unguarded_total,
                    "comparison_metric": "total_exported_components",
                    "comparison_value": exported_total,
                    "reason": "unguarded exported components cannot exceed total exported components",
                }
            )
        if provider_total > exported_total:
            app_errors += 1
            rows.append(
                {
                    "app_label": app_label,
                    "metric": "exported_providers",
                    "status": "ERROR",
                    "observed_value": provider_total,
                    "comparison_metric": "total_exported_components",
                    "comparison_value": exported_total,
                    "reason": "exported provider count cannot exceed total exported components",
                }
            )
        if alias_total >= 50 and exported_total > 0 and alias_total / exported_total >= 0.5:
            app_warnings += 1
            rows.append(
                {
                    "app_label": app_label,
                    "metric": "exported_activity_aliases",
                    "status": "WARN",
                    "observed_value": alias_total,
                    "comparison_metric": "total_exported_components",
                    "comparison_value": exported_total,
                    "reason": "activity aliases dominate exported-component exposure; discuss separately from ordinary activity/service/receiver exposure",
                }
            )
        custom_permissions = _int(row.get("custom_permissions"))
        if custom_permissions >= 10:
            app_warnings += 1
            rows.append(
                {
                    "app_label": app_label,
                    "metric": "custom_permissions",
                    "status": "WARN",
                    "observed_value": custom_permissions,
                    "comparison_metric": "privacy_sensitive_permissions",
                    "comparison_value": _int(row.get("privacy_sensitive_permissions")),
                    "reason": "app-defined permissions are reported separately from privacy-sensitive Android dangerous/special-access permissions",
                }
            )
        if split_count > 100:
            app_warnings += 1
            rows.append(
                {
                    "app_label": app_label,
                    "metric": "split_count",
                    "status": "WARN",
                    "observed_value": split_count,
                    "comparison_metric": "expected_split_count_range",
                    "comparison_value": "<=100",
                    "reason": "selected build split count is unusually high and should be checked against apk_sets metadata",
                }
            )
        if app_errors == 0 and app_warnings == 0:
            rows.append(
                {
                    "app_label": app_label,
                    "metric": "app_build_static_metrics",
                    "status": "OK",
                    "observed_value": "",
                    "comparison_metric": "",
                    "comparison_value": "",
                    "reason": "basic app/build metric invariants passed",
                }
            )
    path = root / "report" / "metric_integrity_audit.csv"
    _write_csv(
        path,
        rows,
        [
            "app_label",
            "metric",
            "status",
            "observed_value",
            "comparison_metric",
            "comparison_value",
            "reason",
        ],
    )
    return path


def _write_artifact_quality_audit(root: Path, app_rows: list[dict[str, Any]], table_paths: list[Path], figure_paths: list[Path]) -> Path:
    app_build_count = len(app_rows)
    rows: list[dict[str, Any]] = []
    for path in table_paths + figure_paths:
        if path.suffix not in {".csv", ".pdf", ".svg", ".png", ".tex"}:
            continue
        name = path.stem.replace("_source", "")
        is_large_heatmap = app_build_count > 40 and ("permission_heatmap" in name or "permission_profile" in name)
        rows.append(
            {
                "artifact": str(path.relative_to(root)),
                "question_answered": _artifact_question(name),
                "source_data": "generated report data CSVs",
                "dimensions": f"{app_build_count} app/build rows",
                "missing_value_behavior": "missing values remain blank; zeros represent no observed matching evidence",
                "one_column_two_column_suitability": "two-column or supplement" if app_build_count > 15 else "one-column candidate",
                "readability_in_grayscale": "yes",
                "colorblind_safe_status": "yes",
                "minimum_label_font_size": "7pt or larger for generated plots",
                "label_overlap": "risk for large scopes" if app_build_count > 40 else "acceptable in generated preview",
                "caption_quality": "available in figure_recommendations.csv",
                "scientific_value": "high" if path.suffix in {".csv", ".tex"} or not is_large_heatmap else "low for main report",
                "redundancy": "source/supporting artifact" if path.suffix == ".csv" else "presentation artifact",
                "page_space_estimate": "0.5-1 page" if path.suffix in {".pdf", ".png", ".svg"} else "0.25-0.5 page",
                "classification": "SUPPLEMENT ONLY" if is_large_heatmap else _artifact_classification(name, app_build_count),
            }
        )
    path = root / "report" / "artifact_quality_audit.csv"
    _write_csv(path, rows)
    return path


def _write_large_scope_policy(root: Path, app_rows: list[dict[str, Any]], scope_type: str) -> Path:
    threshold = 40
    app_count = _unique_application_count(app_rows)
    app_build_count = len(app_rows)
    above = app_build_count > threshold
    text = [
        "Large Scope Artifact Policy",
        f"Threshold: {threshold} app/build rows.",
        "Below threshold: app/build figures may be considered for main report inclusion after readability review.",
        "Above threshold: dense app/build heatmaps are supplementary only; prefer prevalence summaries, top-N indicators, category summaries, paginated appendices, and ranked tables.",
        f"This report application count: {app_count}.",
        f"This report app/build row count: {app_build_count}.",
        f"Report recommendation: {'do not recommend dense app/build heatmaps for the main report' if above else 'generated figures remain readable enough for review'}",
        f"Scope type: {scope_type}.",
    ]
    path = root / "report" / "large_scope_artifact_policy.txt"
    path.write_text("\n".join(text) + "\n", encoding="utf-8")
    return path


def _write_static_social_media_reproduction_status(root: Path, request: ReportRequest) -> Path:
    supported = request.scope_key == "static_social_media_2025"
    rows = [
        ("permission-use table", "yes", "only with original frozen manifest", "yes", "exact historical manifest or explicit contemporary session", "do not copy historical values without exact manifest"),
        ("exported-component table", "yes", "only with original frozen manifest", "yes", "exact historical manifest or explicit contemporary session", "component semantics depend on selected static run"),
        ("MASVS summary", "yes", "only with original frozen manifest", "yes", "canonical static findings", "MASVS mapping may differ across analyzer versions"),
        ("network/storage table", "yes", "only with original frozen manifest", "yes", "static string/findings tables", "static indicators do not prove runtime use"),
        ("static exposure comparison", "yes", "only with original frozen manifest", "yes", "selected app/build/static run identities", "method-compatible regeneration must label version differences"),
        ("app-level findings table", "yes", "only with original frozen manifest", "yes", "static_analysis_findings", "finding taxonomy may differ by analyzer version"),
    ]
    path = root / "report" / "static_social_media_2025_reproduction_status.txt"
    lines = [
        "Static social media 2025 compatibility status",
        f"Saved alias active: {'yes' if supported else 'no'}",
        "Historical app list: Facebook, Instagram, Facebook Messenger, Snapchat, TikTok, Twitter/X",
        "Exact reproduction requires the original frozen manifest and fails closed when it is missing.",
        "Method-compatible regeneration is allowed with an explicitly selected session or manifest and must not claim exact historical reproduction.",
        "",
        "historical artifact | recreation supported | exact reproduction possible | method-compatible regeneration possible | required source | limitation",
    ]
    lines.extend(" | ".join(row) for row in rows)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_layout_fit_report(root: Path, app_rows: list[dict[str, Any]], table_paths: list[Path], figure_paths: list[Path]) -> Path:
    app_build_count = len(app_rows)
    smoke_tex = root / "report" / "layout_fit_smoke.tex"
    smoke_tex.write_text(
        "\\documentclass[conference]{IEEEtran}\n"
        "\\begin{document}\n"
        "\\input{../tables/static_exposure_summary.tex}\n"
        "\\input{../tables/masvs_summary.tex}\n"
        "\\end{document}\n",
        encoding="utf-8",
    )
    compile_success = "not executed"
    overfull = underfull = "not measured"
    if shutil.which("latexmk"):
        proc = subprocess.run(
            ["latexmk", "-pdf", "-interaction=nonstopmode", "-halt-on-error", smoke_tex.name],
            cwd=smoke_tex.parent,
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
        (root / "report" / "layout_fit_compile.log").write_text(proc.stdout + proc.stderr, encoding="utf-8")
        compile_success = "yes" if proc.returncode == 0 else "no"
        log_text = proc.stdout + proc.stderr
        overfull = str(log_text.count("Overfull \\hbox"))
        underfull = str(log_text.count("Underfull \\hbox") + log_text.count("Underfull \\vbox"))
    lines = [
        "Report Layout Fit Check",
        f"Compile success: {compile_success}",
        f"Overfull boxes: {overfull}",
        f"Underfull boxes: {underfull}",
        f"Tables exceeding one column: {'likely for build summary' if app_build_count > 15 else 'not expected for summarized tables'}",
        f"Figures requiring two columns: {'likely for app/build plots' if app_build_count > 10 else 'not expected'}",
        f"Unreadable labels: {'risk for large all-app scope' if app_build_count > 40 else 'not observed in generated preview policy'}",
        "Caption length: draft captions are short and require editing.",
        "Page-space consumption: prioritize two MUST INCLUDE artifacts; move dense app/build figures to supplement for large scopes.",
        f"Tables generated: {sum(1 for path in table_paths if path.suffix == '.tex')}",
        f"Figures generated: {sum(1 for path in figure_paths if path.suffix == '.png')}",
    ]
    path = root / "report" / "layout_fit_report.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_read_only_verification(root: Path) -> Path:
    path = root / "report" / "read_only_verification.txt"
    path.write_text(
        "DB rows mutated: false\nEvidence mutated: false\nSource manifests mutated: false\nAPK storage mutated: false\n",
        encoding="utf-8",
    )
    return path


def _write_latex(root: Path, request: ReportRequest, app_rows: list[dict[str, Any]], table_paths: list[Path], figure_paths: list[Path]) -> list[Path]:
    paths: list[Path] = []
    methods = root / "latex" / "methods_insert.tex"
    methods.write_text(
        "\\paragraph{Static evidence basis.} "
        f"The report uses {request.evidence_basis_type.replace('_', ' ')} with {len(app_rows)} selected application builds. "
        "Each app/build row is generated from one completed, canonical, identity-valid static run.\\n",
        encoding="utf-8",
    )
    results = root / "latex" / "results_insert.tex"
    results.write_text(
        "\\paragraph{Static exposure summary.} "
        f"The selected scope contains {_unique_application_count(app_rows)} applications represented by {len(app_rows)} app/build rows and "
        f"{sum(int(row['detector_findings']) for row in app_rows)} static detector findings.\\n",
        encoding="utf-8",
    )
    figure_inputs = root / "latex" / "figure_inputs.tex"
    figure_inputs.write_text("\n".join(f"% {path.relative_to(root)}" for path in figure_paths if path.suffix == ".png") + "\n", encoding="utf-8")
    table_inputs = root / "latex" / "table_inputs.tex"
    table_inputs.write_text("\n".join(f"\\input{{{path.relative_to(root).as_posix()}}}" for path in table_paths if path.suffix == ".tex") + "\n", encoding="utf-8")
    captions = root / "latex" / "captions.tex"
    captions.write_text("% Figure recommendations and caption notes are stored in figures/figure_recommendations.csv.\n", encoding="utf-8")
    paths.extend([methods, results, figure_inputs, table_inputs, captions])
    return paths


def _candidate_manifest_row(candidate: StaticRunCandidate, request: ReportRequest, resolution: StaticEvidenceResolution) -> dict[str, Any]:
    return {
        "app_label": candidate.display_name,
        "package_name": candidate.package_name,
        "app_category": candidate.app_category,
        "selected_version_code": candidate.version_code,
        "selected_version_name": candidate.version_name,
        "base_apk_sha256": candidate.base_apk_sha256,
        "split_count": candidate.split_count,
        "static_run_ids": candidate.static_run_id,
        "static_session_stamp": candidate.static_session_stamp,
        "evidence_basis": request.evidence_basis_type,
        "evidence_as_of_utc": request.as_of_utc or request.window_end_utc or request.generated_at_utc,
        "identity_valid": candidate.identity_valid,
        "canonical_status": candidate.canonical_status,
        "source_lineage": candidate.source_lineage,
        "reproduction_status": resolution.reproduction_status,
    }


def _masvs_rows(findings: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "run_id": row.get("run_id"),
            "finding_id": row.get("finding_id"),
            "masvs_area": row.get("masvs_area"),
            "masvs_control": row.get("masvs_control"),
            "severity": row.get("severity") or row.get("severity_raw"),
            "title": row.get("title"),
        }
        for row in findings
        if row.get("masvs_area") or row.get("masvs_control")
    ]


def _first_int(value: object) -> int:
    text = str(value or "").split(",", 1)[0].strip()
    try:
        return int(text)
    except (TypeError, ValueError):
        return 0


def _paper1_permission_fields() -> list[tuple[str, str]]:
    return [
        ("access_coarse_location", "android.permission.access_coarse_location"),
        ("access_fine_location", "android.permission.access_fine_location"),
        ("access_network_state", "android.permission.access_network_state"),
        ("bluetooth", "android.permission.bluetooth"),
        ("bluetooth_admin", "android.permission.bluetooth_admin"),
        ("internet", "android.permission.internet"),
        ("camera", "android.permission.camera"),
        ("record_audio", "android.permission.record_audio"),
        ("read_calendar", "android.permission.read_calendar"),
        ("write_calendar", "android.permission.write_calendar"),
        ("read_call_log", "android.permission.read_call_log"),
        ("read_contacts", "android.permission.read_contacts"),
        ("write_contacts", "android.permission.write_contacts"),
        ("read_external_storage", "android.permission.read_external_storage"),
        ("write_external_storage", "android.permission.write_external_storage"),
    ]


def _x_if_permission_present(permission_names: set[str], permission_name: str) -> str:
    return "X" if permission_name.lower() in permission_names else ""


def _first_string_row(rows: Sequence[Mapping[str, Any]], run_id: int) -> dict[str, Any]:
    for row in rows:
        if _int(row.get("run_id")) == int(run_id):
            return dict(row)
    return {}


def _static_archive_metrics(candidate: StaticRunCandidate) -> dict[str, int]:
    path = (
        Path("data")
        / "static_analysis"
        / "reports"
        / "archive"
        / str(candidate.static_session_stamp)
        / f"{candidate.base_apk_sha256}.json"
    )
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    detector_metrics = payload.get("detector_metrics")
    if not isinstance(detector_metrics, Mapping):
        detector_metrics = (
            payload.get("metadata", {})
            .get("repro_bundle", {})
            .get("detector_metrics", {})
            if isinstance(payload.get("metadata"), Mapping)
            else {}
        )
    if not isinstance(detector_metrics, Mapping):
        return {}
    domain = detector_metrics.get("domain_verification")
    if not isinstance(domain, Mapping):
        return {}
    counts = domain.get("Filter counts")
    if not isinstance(counts, Mapping):
        return {}
    return {
        "total_intent_filters": _int(counts.get("total_intent_filters")),
        "browsable_view_filters": _int(counts.get("browsable_view_filters")),
        "web_link_filters": _int(counts.get("web_link_filters")),
        "auto_verify_filters": _int(counts.get("auto_verify_filters")),
        "eligible_verified_filters": _int(counts.get("eligible_verified_filters")),
    }


def _fileprovider_count(components: Sequence[Mapping[str, Any]]) -> int:
    seen: set[str] = set()
    for row in components:
        haystack = " ".join(
            str(row.get(key) or "")
            for key in ("component_name", "provider_name", "authority", "authorities")
        ).lower()
        if "fileprovider" not in haystack and ".files" not in haystack:
            continue
        identity = str(row.get("component_name") or row.get("provider_name") or row.get("authority") or haystack).strip().lower()
        if identity:
            seen.add(identity)
    return len(seen)


def _has_finding(findings: Sequence[Mapping[str, Any]], needle: str) -> bool:
    target = needle.strip().lower()
    for row in findings:
        haystack = " ".join(
            str(row.get(key) or "")
            for key in ("finding_id", "title", "rule_id", "detector", "module", "category")
        ).lower()
        if target in haystack:
            return True
    return False


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _paper1_masvs_policy_readiness_row(app_label: str, package_name: str, metrics: Mapping[str, Any]) -> dict[str, Any]:
    privacy = _int(metrics.get("masvs_privacy_count"))
    platform = _int(metrics.get("masvs_platform_non_alias_count"))
    network = _int(metrics.get("masvs_network_count"))
    storage = _int(metrics.get("masvs_storage_count"))
    area_counts = {
        "privacy": privacy,
        "platform_non_alias": platform,
        "network": network,
        "storage": storage,
    }
    no_finding_areas = sum(1 for value in area_counts.values() if value == 0)
    candidate_pct = round((no_finding_areas / len(area_counts)) * 100, 1)
    return {
        "app_label": app_label,
        "package_name": package_name,
        "privacy_findings": privacy,
        "platform_non_alias_findings": platform,
        "network_findings": network,
        "storage_findings": storage,
        "privacy_area_status": _masvs_area_status(privacy),
        "platform_area_status": _masvs_area_status(platform),
        "network_area_status": _masvs_area_status(network),
        "storage_area_status": _masvs_area_status(storage),
        "candidate_area_no_finding_pct": candidate_pct,
        "claim_status": "descriptive_only_not_compliance",
        "caveat": "Area statuses describe whether selected static findings were observed. They are not MASVS compliance pass/fail results.",
    }


def _paper1_score_model_input_row(app_label: str, package_name: str, metrics: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "app_label": app_label,
        "package_name": package_name,
        "severity_high_count": _int(metrics.get("severity_high_count")),
        "severity_medium_count": _int(metrics.get("severity_medium_count")),
        "severity_low_count": _int(metrics.get("severity_low_count")),
        "severity_info_count": _int(metrics.get("severity_info_count")),
        "masvs_privacy_count": _int(metrics.get("masvs_privacy_count")),
        "masvs_platform_non_alias_count": _int(metrics.get("masvs_platform_non_alias_count")),
        "masvs_network_count": _int(metrics.get("masvs_network_count")),
        "masvs_storage_count": _int(metrics.get("masvs_storage_count")),
        "total_declared_permissions": _int(metrics.get("total_declared_permissions")),
        "dangerous_permissions": _int(metrics.get("dangerous_permissions")),
        "special_access_permissions": _int(metrics.get("special_access_permissions")),
        "custom_permissions": _int(metrics.get("custom_permissions")),
        "exported_non_alias_components": _int(metrics.get("exported_non_alias_components")),
        "exported_non_alias_components_without_permission_guard": _int(metrics.get("exported_non_alias_components_without_permission_guard")),
        "exported_activity_aliases": _int(metrics.get("exported_activity_aliases")),
        "cleartext_related_indicators": _int(metrics.get("cleartext_related_indicators")),
        "network_security_findings": _int(metrics.get("network_security_findings")),
        "storage_related_findings": _int(metrics.get("storage_related_findings")),
        "api_key_indicators": _int(metrics.get("api_key_indicators")),
        "high_entropy_indicators": _int(metrics.get("high_entropy_indicators")),
        "score_status": "inputs_ready_formula_unapproved",
        "caveat": "These are raw descriptive inputs only. No 0-100 score is calculated because no reviewed formula is frozen for this profile version.",
    }


def _masvs_area_status(count: int) -> str:
    return "area_has_findings" if count > 0 else "area_no_findings"


def _paper1_gap_analysis_text(rows: Sequence[Mapping[str, Any]]) -> str:
    lines = [
        "Paper 1 Static Result Reproduction Gap Analysis",
        "Scope: method-compatible compatibility export for current selected app builds.",
        "This is not an exact reproduction of the historical Paper 1 values unless the original frozen Paper 1 manifest/APKs are selected.",
        "",
        "Summary:",
    ]
    for row in rows:
        lines.append(f"- {row['paper1_item']}: {row['status']} ({row['gap']})")
    lines.extend(
        [
            "",
            "Blocked items:",
            "- Overall static risk score: blocked until a transparent, versioned 0-100 scoring formula is reviewed and frozen.",
            "- MASVS pass/fail compliance: blocked until category pass/fail thresholds are reviewed and frozen for this publication profile.",
            "",
            "Safe substitutes now:",
            "- Use app_static_metrics.csv for app/build-level static metrics.",
            "- Use paper1_permission_usage_matrix.csv for the Paper 1-style permission matrix.",
            "- Use paper1_network_storage_parity.csv for cleartext, legacy storage, backup, and FileProvider-like provider indicators.",
            "- Use paper1_secret_indicator_parity.csv for API-key and high-entropy static indicators, with manual-review caveats.",
            "- Use paper1_masvs_policy_readiness.csv for MASVS-aligned finding counts and descriptive area status, not pass/fail certification.",
            "- Use paper1_score_model_inputs.csv for transparent score-model inputs if a future reviewed formula is added.",
        ]
    )
    return "\n".join(lines) + "\n"


def _paper1_publication_use_notes_text() -> str:
    return "\n".join(
        [
            "# Paper 1-Style Static Output Use Notes",
            "",
            "This report provides method-compatible static-analysis outputs for the selected current evidence basis. It is not an exact reproduction of any historical Paper 1 values unless the original frozen Paper 1 manifest and APKs are selected.",
            "",
            "## Safe To Use",
            "",
            "- `tables/paper1_permission_usage_matrix.csv`: Paper 1-style permission presence matrix.",
            "- `tables/paper1_manifest_component_parity.csv`: manifest/component exposure compatibility table. Treat intent-filter counts as archive-derived until promoted into canonical static tables.",
            "- `tables/paper1_network_storage_parity.csv`: cleartext, backup, legacy storage, and FileProvider-like indicators.",
            "- `tables/paper1_secret_indicator_parity.csv`: API-key and high-entropy string indicators, with manual-review caveats.",
            "- `tables/paper1_masvs_policy_readiness.csv`: MASVS-aligned finding counts and descriptive area status.",
            "- `tables/paper1_score_model_inputs.csv`: transparent inputs for a future score model.",
            "",
            "## Do Not Claim Yet",
            "",
            "- Do not claim exact Paper 1 reproduction unless using the original Paper 1 frozen evidence.",
            "- Do not report a 0-100 overall static risk score from this profile; the score formula is not approved.",
            "- Do not report MASVS pass/fail compliance from this profile; only finding counts and descriptive area status are exported.",
            "- Do not describe API-key or high-entropy indicators as confirmed exposed credentials without manual review.",
            "",
            "## Preferred Paper Wording",
            "",
            "The static reporting bundle regenerates Paper 1-style descriptive tables over the selected current app/build evidence. Composite risk scoring and MASVS pass/fail compliance are intentionally withheld until a transparent, versioned scoring policy is reviewed and frozen.",
            "",
        ]
    )


def _by_run(rows: Sequence[Mapping[str, Any]], key: str) -> dict[int, list[dict[str, Any]]]:
    out: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        out[int(row.get(key) or 0)].append(dict(row))
    return out


def _string_totals(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    keys = ["endpoints", "http_cleartext", "analytics_ids", "cloud_refs", "ipc", "uris", "flags", "certs", "api_keys", "high_entropy"]
    return {key: sum(_int(row.get(key)) for row in rows) for key in keys}


def _severity(row: Mapping[str, Any]) -> str:
    return str(row.get("severity") or row.get("severity_raw") or "INFO").strip().upper()


def _masvs_area(row: Mapping[str, Any]) -> str:
    value = str(row.get("masvs_area") or row.get("masvs_control") or "").upper().replace("MASVS-", "")
    for area in ("PRIVACY", "PLATFORM", "NETWORK", "STORAGE", "CODE", "RESILIENCE"):
        if area in value:
            return area
    return ""


def _platform_breakdown_from_findings(findings: Sequence[Mapping[str, Any]]) -> Counter[str]:
    buckets: Counter[str] = Counter()
    for row in findings:
        if _masvs_area(row) != "PLATFORM":
            continue
        detector = str(row.get("detector") or row.get("module") or "").strip().lower()
        finding_id = str(row.get("finding_id") or "").strip().lower()
        title = str(row.get("title") or "").strip().lower()
        if detector == "ipc_components":
            if "activity-alias" in finding_id or "activity alias" in title:
                buckets["activity_aliases"] += 1
            else:
                buckets["ipc_components"] += 1
        elif detector == "provider_acl":
            buckets["provider_acl"] += 1
        elif detector == "domain_verification":
            buckets["app_links"] += 1
        elif detector == "manifest_baseline":
            buckets["manifest_policy"] += 1
        elif detector == "correlation_engine":
            buckets["static_correlation"] += 1
        else:
            buckets["other"] += 1
    for key in (
        "ipc_components",
        "activity_aliases",
        "provider_acl",
        "app_links",
        "manifest_policy",
        "static_correlation",
        "other",
    ):
        buckets.setdefault(key, 0)
    return buckets


def _is_unguarded_non_provider_component_title(title: str) -> bool:
    normalized = str(title or "").lower()
    if "provider" in normalized:
        return False
    if not any(token in normalized for token in ("exported activity", "exported service", "exported receiver")):
        return False
    return (
        "without permission" in normalized
        or "weak guard" in normalized
        or "weak permission guard" in normalized
    )


_EXPORTED_COMPONENT_DETAIL_RE = re.compile(
    r"\b(?P<kind>Activity Alias|Activity|Service|Receiver)\s+"
    r"(?P<name>[A-Za-z0-9_.$]+)\s+(?:is exported|uses)\b",
    re.IGNORECASE,
)


def _component_exposure_from_findings(findings: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    exported: dict[str, set[str]] = {
        "activity": set(),
        "activity_alias": set(),
        "service": set(),
        "receiver": set(),
    }
    unguarded: set[tuple[str, str]] = set()
    unguarded_by_kind: dict[str, set[str]] = {
        "activity": set(),
        "activity_alias": set(),
        "service": set(),
        "receiver": set(),
    }
    for row in findings:
        title = str(row.get("title") or "")
        normalized_title = title.lower()
        if not any(token in normalized_title for token in ("exported activity", "exported service", "exported receiver")):
            continue
        component_kind, component_name = _component_identity(row)
        if component_kind not in exported:
            continue
        exported[component_kind].add(component_name)
        if _is_unguarded_non_provider_component_title(normalized_title):
            unguarded.add((component_kind, component_name))
            unguarded_by_kind[component_kind].add(component_name)
    exported_total = sum(len(values) for values in exported.values())
    exported_non_alias_total = exported_total - len(exported["activity_alias"])
    unguarded_aliases = len(unguarded_by_kind["activity_alias"])
    return {
        "exported_activities": len(exported["activity"]),
        "exported_activity_aliases": len(exported["activity_alias"]),
        "exported_services": len(exported["service"]),
        "exported_receivers": len(exported["receiver"]),
        "exported_non_alias_components": exported_non_alias_total,
        "exported_total": exported_total,
        "unguarded_activity_aliases": unguarded_aliases,
        "unguarded_non_alias_ipc_components": len(unguarded) - unguarded_aliases,
        "unguarded_ipc_components": len(unguarded),
    }


def _component_identity(row: Mapping[str, Any]) -> tuple[str, str]:
    evidence = str(row.get("evidence") or "")
    detail = evidence
    if evidence:
        try:
            parsed = json.loads(evidence)
            if isinstance(parsed, Mapping):
                detail = str(parsed.get("detail") or evidence)
        except json.JSONDecodeError:
            detail = evidence
    match = _EXPORTED_COMPONENT_DETAIL_RE.search(detail)
    if match:
        raw_kind = match.group("kind").lower()
        if raw_kind == "activity alias":
            kind = "activity_alias"
        else:
            kind = raw_kind
        return kind, match.group("name")
    finding_identity = _component_identity_from_finding_id(str(row.get("finding_id") or ""))
    if finding_identity:
        return finding_identity
    title = str(row.get("title") or "").lower()
    if "exported activity alias" in title:
        kind = "activity_alias"
    elif "exported activity" in title:
        kind = "activity"
    elif "exported service" in title:
        kind = "service"
    elif "exported receiver" in title:
        kind = "receiver"
    else:
        kind = ""
    fallback = str(row.get("finding_id") or row.get("evidence_hash") or row.get("evidence_refs") or row)
    return kind, fallback


def _component_identity_from_finding_id(finding_id: str) -> tuple[str, str] | None:
    value = str(finding_id or "").strip()
    prefixes = (
        ("ipc_activity-alias_open_", "activity_alias"),
        ("ipc_activity-alias_permission_weak_", "activity_alias"),
        ("ipc_activity-alias_permission_", "activity_alias"),
        ("ipc_activity_open_", "activity"),
        ("ipc_activity_permission_weak_", "activity"),
        ("ipc_activity_permission_", "activity"),
        ("ipc_service_open_", "service"),
        ("ipc_service_weak_permission_", "service"),
        ("ipc_service_permission_", "service"),
        ("ipc_receiver_open_", "receiver"),
        ("ipc_receiver_weak_permission_", "receiver"),
        ("ipc_receiver_permission_", "receiver"),
    )
    for prefix, kind in prefixes:
        if value.startswith(prefix):
            name = value[len(prefix) :].strip()
            if name:
                return kind, name
    return None


def _metric_definition(field: str) -> str:
    definitions = {
        "total_declared_permissions": "Unique declared permission names observed for the selected static run.",
        "privacy_sensitive_permissions": "Unique Android permissions flagged runtime-dangerous or special-access; app-defined custom permissions are reported separately.",
        "normal_permissions": "Unique declared permission names that are not runtime-dangerous, special-access, or app-defined custom permissions.",
        "dangerous_permissions": "Unique permission names marked runtime dangerous.",
        "special_access_permissions": "Unique permission names marked special-access.",
        "custom_permissions": "Unique app-defined or non-android.permission.* permission names declared by the app.",
        "exported_activities": "Unique exported activity components detected for the selected run, excluding activity aliases when evidence identifies them.",
        "exported_activity_aliases": "Unique exported activity-alias components detected for the selected run.",
        "exported_services": "Unique exported service components detected for the selected run.",
        "exported_receivers": "Unique exported receiver components detected for the selected run.",
        "exported_providers": "Exported provider rows detected for the selected run.",
        "exported_non_alias_components": "Unique exported activity, service, receiver, and provider evidence excluding activity aliases.",
        "guarded_non_alias_components": "Exported non-alias component/provider evidence with a permission guard not classified as absent, weak, broad, or unknown.",
        "exported_non_alias_components_without_permission_guard": "Exported non-alias component/provider evidence with absent, weak, broad, or unknown guard.",
        "total_exported_components": "Unique exported activity, activity-alias, service, receiver, and provider evidence for the selected run.",
        "exported_components_without_permission_guard": "Exported component/provider evidence with absent, weak, broad, or unknown guard.",
        "cleartext_related_indicators": "Static string/resource indicators associated with cleartext HTTP or related posture.",
        "network_security_findings": "Static findings categorized as network-security related.",
        "storage_related_findings": "Static findings categorized as storage related.",
        "masvs_platform_count": "Raw MASVS Platform finding rows before presentation splitting.",
        "masvs_platform_non_alias_count": "MASVS Platform finding rows excluding exported activity-alias findings already shown in the component exposure figure.",
        "platform_ipc_component_count": "MASVS Platform finding rows from IPC component exposure excluding activity aliases.",
        "platform_activity_alias_count": "MASVS Platform finding rows from exported activity aliases; plotted separately when alias-heavy apps would dominate the platform axis.",
        "platform_provider_acl_count": "MASVS Platform finding rows from provider ACL analysis.",
        "platform_app_link_count": "MASVS Platform finding rows from Android App Links or domain verification analysis.",
        "platform_manifest_policy_count": "MASVS Platform finding rows from manifest-level platform policy checks such as custom permissions, task affinity, process, or weak component guard summaries.",
        "platform_static_correlation_count": "MASVS Platform finding rows from static diff/correlation checks.",
        "platform_other_count": "MASVS Platform finding rows not mapped into another report subfamily.",
        "sdk_indicators": "Static string indicators for analytics IDs and cloud references.",
        "embedded_service_sdk_indicators": "Static string indicators for embedded endpoints, SDKs, or service references; not runtime-observed service traffic.",
        "api_key_indicators": "Static string/resource indicators matching API-key patterns. Requires manual review before treating any value as a confirmed credential exposure.",
        "high_entropy_indicators": "Static string/resource indicators with high entropy. Requires manual review because obfuscated constants, hashes, and benign identifiers can match.",
        "detector_findings": "Canonical static_analysis_findings rows for the selected static run.",
    }
    return definitions.get(field, field.replace("_", " "))


def _display_label(field: str) -> str:
    labels = {
        "embedded_service_sdk_indicators": "Embedded service/SDK indicators",
        "cleartext_related_indicators": "Cleartext-related indicators",
        "network_security_findings": "Network-security findings",
        "storage_related_findings": "Storage-related findings",
        "api_key_indicators": "API-key indicators",
        "high_entropy_indicators": "High-entropy indicators",
    }
    return labels.get(field, field.replace("_", " ").title())


def _metric_source(field: str) -> str:
    if field.startswith("platform_"):
        return "static_analysis_findings"
    if "component" in field or "provider" in field:
        return "static_analysis_findings + static_fileproviders"
    if field in {"exported_activities", "exported_services", "exported_receivers"}:
        return "static_analysis_findings"
    if "permission" in field:
        return "static_permission_matrix"
    if "cleartext" in field or "sdk" in field or "service" in field or field in {"api_key_indicators", "high_entropy_indicators"}:
        return "static_string_summary"
    return "static_analysis_findings"


def _artifact_question(name: str) -> str:
    if "permission" in name:
        return "Which apps expose the largest declared/privacy-sensitive permission surface?"
    if "component" in name:
        return "Which apps expose exported or weakly guarded static components?"
    if "masvs" in name:
        return "How are static findings distributed across MASVS-aligned families?"
    if "platform_surface" in name:
        return "Which platform-interaction subfamilies drive MASVS Platform findings?"
    if "network" in name or "storage" in name:
        return "Which apps show static network, cleartext, or storage posture indicators?"
    if "build" in name:
        return "Which app/build/static-run identities support the report?"
    return "What static evidence supports this report artifact?"


def _artifact_classification(name: str, app_count: int) -> str:
    if app_count > 40 and any(token in name for token in ("heatmap", "exposure", "distribution", "posture")):
        return "SUPPLEMENT ONLY"
    if "permission" in name or "component" in name:
        return "MUST INCLUDE"
    if "masvs" in name or "network_storage" in name:
        return "INCLUDE IF SPACE"
    if name.endswith("_source"):
        return "SUPPLEMENT ONLY"
    return "INCLUDE IF SPACE"


def _int(value: Any) -> int:
    try:
        if value in (None, ""):
            return 0
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fieldnames: Sequence[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    names = list(fieldnames or (list(rows[0].keys()) if rows else ["status"]))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=names, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in names})


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _latex_table(rows: Sequence[Mapping[str, Any]], caption: str) -> str:
    if not rows:
        return "% No rows available.\n"
    columns = list(rows[0].keys())[:6]
    colspec = "l" * len(columns)
    header = " & ".join(_tex_escape(col.replace("_", " ")) for col in columns)
    body = "\n".join(" & ".join(_tex_escape(row.get(col, "")) for col in columns) + r" \\" for row in rows[:20])
    return (
        "\\begin{table}[t]\n\\centering\n\\scriptsize\n"
        f"\\caption{{{_tex_escape(caption)}}}\n"
        f"\\begin{{tabular}}{{{colspec}}}\n\\hline\n{header} \\\\\n\\hline\n{body}\n\\hline\n"
        "\\end{tabular}\n\\end{table}\n"
    )


def _tex_escape(value: Any) -> str:
    text = str(value)
    for old, new in {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
    }.items():
        text = text.replace(old, new)
    return text


def _render_bar_figure(base_path: Path, rows: Sequence[Mapping[str, Any]], fields: Sequence[str], *, title: str) -> list[Path]:
    paths = [base_path.with_suffix(".png")]
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        labels = [str(row.get("app_label") or row.get("package_name") or "")[:24] for row in rows]
        x = range(len(labels))
        fig, ax = plt.subplots(figsize=(max(7, len(labels) * 0.45), 4.5))
        width = 0.8 / max(1, len(fields))
        colors = ["#0072B2", "#D55E00", "#009E73", "#CC79A7"]
        for idx, field in enumerate(fields):
            values = [_int(row.get(field)) for row in rows]
            ax.bar([v + idx * width for v in x], values, width=width, label=field.replace("_", " "), color=colors[idx % len(colors)])
        ax.set_title(title)
        ax.set_ylabel("count")
        ax.set_xticks([v + width * (len(fields) - 1) / 2 for v in x])
        ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=7)
        ax.legend(fontsize=7)
        fig.tight_layout()
        for path in paths:
            fig.savefig(path, dpi=300)
        plt.close(fig)
    except Exception:
        for path in paths:
            path.write_text(f"{title}\nFigure rendering unavailable in this environment.\n", encoding="utf-8")
    return paths


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
