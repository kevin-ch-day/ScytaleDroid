#!/usr/bin/env python3
"""Generate a read-only canonical schema map for ``scytaledroid_core_prod``."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


ROLE_CANONICAL = "canonical_source"
ROLE_DERIVED = "derived_read_model"
ROLE_LEDGER = "ledger_audit"
ROLE_LEGACY = "legacy_compatibility"
ROLE_DEPRECATION = "deprecation_candidate"
ROLE_UNKNOWN = "unknown_needs_review"

COL_CANONICAL = "canonical"
COL_TYPED = "typed_replacement"
COL_LEGACY = "legacy_compatibility"
COL_DERIVED = "derived"
COL_DEPRECATED = "deprecated_zero_signal"
COL_MISSING = "missing_new"
COL_UNKNOWN = "unknown_needs_review"


IDENTITY_TABLES = {
    "android_app_categories",
    "android_app_profiles",
    "android_app_publishers",
    "android_publisher_prefix_rules",
    "apps",
    "app_display_aliases",
    "app_display_orderings",
    "app_versions",
    "android_apk_repository",
    "apk_sets",
    "apk_set_members",
    "apk_split_groups",
}

COLLECTION_TABLES = {
    "device_inventory",
    "device_inventory_snapshots",
    "harvest_apk_observations",
}

EXECUTION_TABLES = {
    "static_analysis_sessions",
    "static_analysis_runs",
    "dynamic_sessions",
    "static_session_run_links",
}

EVIDENCE_TABLES = {
    "static_analysis_findings",
    "static_permission_matrix",
    "static_string_summary",
    "static_string_samples",
    "static_string_sample_sets",
    "static_string_selected_samples",
    "static_fileproviders",
    "static_provider_acl",
    "static_dynload_events",
    "static_reflection_calls",
    "static_finding_evidence_payloads",
    "dynamic_telemetry_network",
    "dynamic_telemetry_process",
}

AUTHORITY_TABLES = {
    "dynamic_domain_reference",
    "permission_audit_apps",
    "permission_audit_snapshots",
    "permission_signal_observations",
    "perm_groups",
    "doc_hosts",
}

DERIVED_TABLES = {
    "analysis_cohorts",
    "analysis_cohort_runs",
    "analysis_dynamic_cohort_status",
    "analysis_ml_app_phase_model_metrics",
    "analysis_risk_regime_summary",
    "analysis_signature_deltas",
    "analysis_static_exposure",
    "dynamic_domain_observations",
    "dynamic_network_features",
    "dynamic_network_indicators",
    "masvs_control_coverage",
    "ml_feature_windows",
    "ml_scores",
    "risk_scores",
    "static_correlation_results",
    "static_findings_summary",
    "static_permission_risk_vnext",
    "static_session_rollups",
    "web_static_dynamic_app_summary_cache",
}

LEDGER_TABLES = {
    "artifact_registry",
    "analysis_derivation_receipts",
    "db_ops_log",
    "dynamic_session_issues",
    "harvest_artifact_paths",
    "harvest_sessions",
    "harvest_source_paths",
    "harvest_storage_roots",
    "schema_migrations",
    "schema_version",
    "static_persistence_failures",
    "static_session_disposition_history",
}

LEGACY_TABLES = {
    "buckets",
    "contributors",
    "findings",
    "metrics",
    "runs",
    "static_findings",
}

ZERO_SIGNAL_COLUMNS = {
    ("artifact_registry", "meta_json"),
    ("static_analysis_runs", "detector_metrics"),
    ("static_analysis_runs", "repro_bundle"),
    ("static_analysis_runs", "analysis_matrices"),
    ("static_analysis_runs", "analysis_indicators"),
}

MANUAL_RELATIONSHIPS: dict[str, str] = {
    "apps": "parent android_app_categories.category_id; soft children app_versions.app_id, apk_sets.package_name, dynamic_sessions.package_name",
    "app_versions": "parent apps.id; soft child static_analysis_runs.app_version_id",
    "android_apk_repository": "soft child apk_sets members and harvest_apk_observations by package/hash lineage",
    "apk_sets": "soft parent apps.package_name / app_versions; child apk_set_members",
    "apk_set_members": "parent apk_sets.apk_set_id; soft child static_analysis_runs.apk_set_id",
    "artifact_registry": "soft links to static_analysis_runs.id via static_run_id and dynamic_sessions.dynamic_run_id via dynamic_run_uuid; remain FK-loose ledger",
    "device_inventory": "parent device_inventory_snapshots.snapshot_id; soft link to apps.package_name and harvested APK library",
    "dynamic_domain_observations": "soft parent dynamic_sessions.dynamic_run_id; rebuildable context rows over observed DNS/SNI domains",
    "dynamic_domain_reference": "repo-owned background classification reference used to interpret dynamic observed domains",
    "dynamic_sessions": "soft parent static_analysis_runs.id via static_run_id_u; children dynamic_telemetry_* and dynamic_session_issues",
    "dynamic_telemetry_network": "parent dynamic_sessions.dynamic_run_id",
    "dynamic_telemetry_process": "parent dynamic_sessions.dynamic_run_id",
    "permission_audit_apps": "parent permission_audit_snapshots.snapshot_id; soft parent static_analysis_runs.id and apps.package_name",
    "permission_signal_observations": "soft parent static_analysis_runs.id; overlay to permission_audit_snapshots and Permission Intel semantics",
    "static_analysis_findings": "parent static_analysis_runs.id",
    "static_analysis_runs": "parents app_versions.id, apk_sets.apk_set_id, static_analysis_sessions.static_session_id; children findings, permission matrix, strings, handoff views",
    "static_analysis_sessions": "child static_analysis_runs.static_session_id; child static_session_disposition_history; summarized by static_session_rollups",
    "static_fileproviders": "soft parent static_analysis_runs.id/session_stamp/package_name",
    "static_finding_evidence_payloads": "parent static_analysis_runs.id",
    "static_findings_summary": "soft parent static_analysis_runs.id; derived summary over canonical findings",
    "static_permission_matrix": "parent static_analysis_runs.id",
    "static_permission_risk_vnext": "soft parent static_analysis_runs.id; derived permission scoring",
    "static_provider_acl": "soft parent static_analysis_runs.id/session_stamp/package_name",
    "static_session_rollups": "soft parent static_analysis_sessions/session_run_links; summary table for operator/web read models",
    "static_session_run_links": "parent static_analysis_sessions/static_analysis_runs by soft linkage; execution-spine relation table",
    "static_string_sample_sets": "parent static_analysis_runs.id",
    "static_string_selected_samples": "parent static_analysis_runs.id",
    "static_string_summary": "parent static_analysis_runs.id",
}

NATURAL_KEY_OVERRIDES: dict[str, str] = {
    "android_app_categories": "category_name",
    "android_app_profiles": "profile_key",
    "android_app_publishers": "publisher_key",
    "android_publisher_prefix_rules": "(publisher_key, match_type, pattern)",
    "apps": "package_name",
    "app_display_aliases": "(alias_key, package_name)",
    "app_display_orderings": "(ordering_key, package_name)",
    "app_versions": "(app_id, version_name, version_code)",
    "android_apk_repository": "sha256 / harvested APK identity",
    "apk_sets": "artifact_set_hash / package_name + version identity",
    "apk_set_members": "(apk_set_id, sha256, split_name)",
    "apk_split_groups": "package_name",
    "artifact_registry": "none; append-only ledger keyed by artifact_id",
    "device_inventory": "(snapshot_id, package_name)",
    "dynamic_domain_reference": "(package_name_scope, domain_pattern, match_type)",
    "dynamic_sessions": "dynamic_run_id",
    "permission_audit_apps": "(snapshot_id, package_name)",
    "permission_audit_snapshots": "static_run_id or snapshot_key",
    "schema_migrations": "migration_id + applied_at_utc",
    "static_analysis_runs": "id; soft natural key is run_signature / handoff hash",
    "static_analysis_sessions": "(session_stamp, scope_label)",
    "static_session_run_links": "(session_stamp, static_run_id)",
}

WRITE_SURFACE_OVERRIDES: dict[str, str] = {
    "analysis_cohorts": "report_script",
    "analysis_cohort_runs": "report_script",
    "analysis_derivation_receipts": "report_script",
    "analysis_dynamic_cohort_status": "report_script",
    "analysis_ml_app_phase_model_metrics": "report_script",
    "analysis_risk_regime_summary": "report_script",
    "analysis_signature_deltas": "report_script",
    "analysis_static_exposure": "report_script",
    "artifact_registry": "runtime_code",
    "db_ops_log": "runtime_code",
    "dynamic_domain_observations": "report_script",
    "dynamic_domain_reference": "migration_code",
    "dynamic_network_features": "report_script",
    "dynamic_network_indicators": "report_script",
    "dynamic_session_issues": "runtime_code",
    "dynamic_sessions": "runtime_code",
    "dynamic_telemetry_network": "runtime_code",
    "dynamic_telemetry_process": "runtime_code",
    "harvest_apk_observations": "runtime_code",
    "harvest_artifact_paths": "runtime_code",
    "harvest_sessions": "runtime_code",
    "harvest_source_paths": "runtime_code",
    "harvest_storage_roots": "runtime_code",
    "masvs_control_coverage": "report_script",
    "ml_feature_windows": "report_script",
    "ml_scores": "report_script",
    "permission_audit_apps": "runtime_code",
    "permission_audit_snapshots": "runtime_code",
    "permission_signal_observations": "runtime_code",
    "risk_scores": "runtime_code",
    "schema_migrations": "migration_code",
    "schema_version": "migration_code",
    "static_analysis_findings": "runtime_code",
    "static_analysis_runs": "runtime_code",
    "static_analysis_sessions": "runtime_code",
    "static_correlation_results": "runtime_code",
    "static_dynload_events": "runtime_code",
    "static_fileproviders": "runtime_code",
    "static_findings_summary": "runtime_code",
    "static_finding_evidence_payloads": "runtime_code",
    "static_permission_matrix": "runtime_code",
    "static_permission_risk_vnext": "runtime_code",
    "static_persistence_failures": "runtime_code",
    "static_provider_acl": "runtime_code",
    "static_reflection_calls": "runtime_code",
    "static_session_disposition_history": "runtime_code",
    "static_session_rollups": "runtime_code",
    "static_session_run_links": "runtime_code",
    "static_string_sample_sets": "runtime_code",
    "static_string_samples": "runtime_code",
    "static_string_selected_samples": "runtime_code",
    "static_string_summary": "runtime_code",
    "web_static_dynamic_app_summary_cache": "report_script",
}


@dataclass(frozen=True)
class TableRecord:
    table_name: str
    object_type: str
    row_count: int | None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON to stdout in addition to writing files.")
    parser.add_argument(
        "--output-root",
        default="output/audit/canonical_schema_map",
        help="Audit output root directory (default: %(default)s).",
    )
    return parser


def _rows(run_sql, sql: str, params: Iterable[object] = (), *, query_name: str) -> list[dict[str, Any]]:
    out = run_sql(sql, tuple(params), fetch="all", dictionary=True, query_name=query_name) or []
    return [dict(row) for row in out if isinstance(row, Mapping)]


def _scalar(run_sql, sql: str, params: Iterable[object] = (), *, query_name: str) -> Any:
    row = run_sql(sql, tuple(params), fetch="one", dictionary=True, query_name=query_name)
    if isinstance(row, Mapping):
        return next(iter(row.values()), None)
    if isinstance(row, (tuple, list)) and row:
        return row[0]
    return None


def _table_role(table_name: str, object_type: str) -> str:
    if object_type.upper() == "VIEW":
        return ROLE_DERIVED
    if table_name in IDENTITY_TABLES | COLLECTION_TABLES | EXECUTION_TABLES | EVIDENCE_TABLES | AUTHORITY_TABLES:
        return ROLE_CANONICAL
    if table_name in DERIVED_TABLES:
        return ROLE_DERIVED
    if table_name in LEDGER_TABLES:
        return ROLE_LEDGER
    if table_name in LEGACY_TABLES:
        return ROLE_LEGACY
    return ROLE_UNKNOWN


def _domain_group(table_name: str, object_type: str, role: str) -> str:
    if object_type.upper() == "VIEW":
        return "read_models"
    if table_name in IDENTITY_TABLES:
        return "identity_spine"
    if table_name in COLLECTION_TABLES:
        return "collection_inventory"
    if table_name in EXECUTION_TABLES:
        return "execution_spine"
    if table_name in EVIDENCE_TABLES:
        return "evidence_facts"
    if table_name in AUTHORITY_TABLES:
        return "authority_overlays"
    if table_name in DERIVED_TABLES:
        return "analysis_derived"
    if table_name in LEDGER_TABLES:
        return "governance_and_ledger"
    if table_name in LEGACY_TABLES:
        return "legacy_bridge"
    return "unknown"


def _risk_level(role: str, table_name: str, object_type: str) -> str:
    if object_type.upper() == "VIEW":
        return "medium"
    if table_name in {"dynamic_sessions", "static_analysis_runs", "static_analysis_sessions", "artifact_registry", "static_session_run_links"}:
        return "high"
    if role in {ROLE_CANONICAL, ROLE_LEDGER}:
        return "medium"
    if role == ROLE_LEGACY:
        return "medium"
    return "low"


def _phase_for_table(table_name: str, object_type: str, role: str) -> str:
    phases: list[str] = []
    if object_type.upper() == "VIEW":
        phases.append("B6")
    if table_name in {
        "static_analysis_runs",
        "static_analysis_sessions",
        "static_session_run_links",
        "static_string_summary",
        "static_findings_summary",
        "risk_scores",
        "apps",
        "apk_sets",
        "dynamic_sessions",
        "artifact_registry",
        "harvest_apk_observations",
    }:
        phases.append("B1")
    if table_name in {"artifact_registry", "dynamic_sessions", "static_analysis_runs"}:
        phases.append("B2")
    if table_name in {
        "apps",
        "app_versions",
        "apk_sets",
        "apk_set_members",
        "static_analysis_sessions",
        "static_analysis_runs",
        "static_analysis_findings",
        "static_permission_matrix",
        "static_string_summary",
        "static_string_samples",
        "dynamic_sessions",
        "dynamic_telemetry_network",
        "dynamic_telemetry_process",
    }:
        phases.append("B3")
    if table_name in {"dynamic_sessions", "static_analysis_runs", "static_analysis_sessions", "harvest_sessions", "schema_migrations", "analysis_dynamic_cohort_status"}:
        phases.append("B4")
    if role in {ROLE_LEGACY, ROLE_DEPRECATION} or table_name in {"artifact_registry", "static_analysis_runs"}:
        phases.append("B5")
    if object_type.upper() == "VIEW" or table_name in {"static_session_rollups", "web_static_dynamic_app_summary_cache"}:
        phases.append("B6")
    return ", ".join(dict.fromkeys(phases)) or "review"


def _major_schema_debt(table_name: str, role: str) -> str:
    debts: list[str] = []
    if table_name == "artifact_registry":
        debts.extend(["dual typed/legacy linkage columns", "ledger must remain FK-loose", "meta_json is zero-signal"])
    if table_name == "dynamic_sessions":
        debts.extend(["signed static_run_id legacy debt", "profile_key collation drift", "typed cutover pending"])
    if table_name == "static_analysis_runs":
        debts.extend(["run_started_utc varchar legacy debt", "profile_key/session_stamp contract debt", "zero-signal JSON columns"])
    if table_name == "static_analysis_sessions":
        debts.append("session_stamp join-key contract depends on child-table normalization")
    if table_name == "static_session_run_links":
        debts.extend(["session_stamp latin1 collation drift", "soft-link table should be hardened after B1/B2"])
    if table_name in {"static_findings_summary", "static_string_summary"}:
        debts.append("session_stamp width debt (varchar(64) vs canonical varchar(128))")
    if table_name in {"apps", "apk_sets", "harvest_apk_observations"}:
        debts.append("package_name collation normalization needed")
    if table_name in {"risk_scores", "static_dynload_events", "static_fileproviders", "static_provider_acl", "static_reflection_calls"}:
        debts.append("session_stamp width/collation debt in child evidence tables")
    if table_name in {"static_analysis_runs", "artifact_registry"} and role != ROLE_DERIVED:
        debts.append("typed cutover affects downstream views/reports")
    if role == ROLE_LEGACY:
        debts.append("historical compatibility surface; should not regain primary-writer status")
    if not debts:
        if role == ROLE_DERIVED:
            debts.append("derived model inherits canonical debt; rebuild after canonical cutover")
        elif role == ROLE_LEDGER:
            debts.append("ledger/audit retention should stay loose and receipt-first")
        elif role == ROLE_CANONICAL:
            debts.append("review FK readiness and naming/typing consistency")
        else:
            debts.append("classification and writer ownership need confirmation")
    return "; ".join(dict.fromkeys(debts))


def _write_surface(table_name: str, object_type: str) -> str:
    if object_type.upper() == "VIEW":
        return "only_views"
    return WRITE_SURFACE_OVERRIDES.get(table_name, "unknown_needs_review")


def _fk_policy(table_name: str, role: str) -> tuple[str, str]:
    if role == ROLE_LEDGER or table_name == "artifact_registry":
        return "no", "ledger/audit history should remain FK-loose or selectively soft-linked"
    if role == ROLE_DERIVED:
        return "no", "derived/read-model surfaces should rebuild from canonical sources instead of carrying strict FKs"
    if role == ROLE_LEGACY:
        return "no", "legacy compatibility surfaces should not be hardened before retirement plan"
    if role == ROLE_CANONICAL:
        return "yes", "canonical source tables should gain selective FKs after collation/type cleanup"
    return "review", "ownership and lifecycle not clean enough yet"


def _csv_write(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _group_columns(columns: list[dict[str, Any]], key: str) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in columns:
        out[str(row.get(key) or "")].append(row)
    return out


def _natural_key(table_name: str, unique_indexes: list[dict[str, Any]]) -> str:
    if table_name in NATURAL_KEY_OVERRIDES:
        return NATURAL_KEY_OVERRIDES[table_name]
    if not unique_indexes:
        return ""
    parts = []
    for item in unique_indexes:
        cols = item.get("columns") or ""
        name = item.get("index_name") or ""
        parts.append(f"{name}({cols})" if name else str(cols))
    return " | ".join(parts)


def _column_classification(
    table_name: str,
    object_type: str,
    table_role: str,
    column_name: str,
    column_type: str,
    populated_rows: int | None = None,
) -> tuple[str, str]:
    key = (table_name, column_name)
    if object_type.upper() == "VIEW":
        return COL_DERIVED, "view-projected column"
    if key in ZERO_SIGNAL_COLUMNS:
        return COL_DEPRECATED, "present but currently zero-signal in live data"
    if column_name == "dynamic_run_uuid":
        return COL_TYPED, "typed replacement for artifact_registry dynamic linkage"
    if column_name == "dynamic_run_id":
        if table_name == "artifact_registry":
            return COL_LEGACY, "legacy dynamic run linkage preserved for backward compatibility"
        if table_role == ROLE_CANONICAL:
            return COL_CANONICAL, "canonical dynamic run identity"
        return COL_DERIVED, "derived or downstream projection of dynamic run identity"
    if column_name == "static_run_id_u":
        return COL_TYPED, "typed replacement for dynamic-to-static linkage"
    if column_name == "static_run_id":
        if table_name == "dynamic_sessions":
            return COL_LEGACY, "signed legacy dynamic-to-static linkage superseded by static_run_id_u"
        if table_name == "artifact_registry":
            return COL_CANONICAL, "typed static linkage retained as canonical ledger field"
        if table_role == ROLE_LEGACY:
            return COL_LEGACY, "legacy compatibility linkage"
        return COL_CANONICAL if table_role == ROLE_CANONICAL else COL_DERIVED, "static run identity linkage"
    if column_name == "session_stamp":
        if table_name in {"static_analysis_runs", "static_analysis_sessions"}:
            return COL_CANONICAL, "canonical session cohort key"
        if table_role == ROLE_LEGACY:
            return COL_LEGACY, "legacy session cohort key"
        if table_role == ROLE_CANONICAL:
            return COL_CANONICAL, "canonical child/session join key with width or collation debt"
        return COL_DERIVED, "derived session cohort projection"
    if column_name == "static_session_id":
        if table_name in {"static_analysis_sessions", "static_analysis_runs", "static_session_disposition_history"}:
            return COL_CANONICAL, "canonical static session identity"
        return COL_DERIVED, "downstream session projection"
    if column_name == "package_name":
        if table_name == "apps":
            return COL_CANONICAL, "canonical package identifier"
        if table_role == ROLE_LEGACY:
            return COL_LEGACY, "legacy package identifier surface"
        return COL_CANONICAL if table_role == ROLE_CANONICAL else COL_DERIVED, "package identifier"
    if column_name == "package_name_lc":
        return COL_DERIVED, "derived lowercase package key; missing on canonical app identity tables"
    if column_name == "profile_key":
        if table_name in {"apps", "android_app_profiles"}:
            return COL_CANONICAL, "canonical profile taxonomy key"
        if table_name in {"dynamic_sessions", "static_analysis_runs"}:
            return COL_CANONICAL, "execution/profile linkage with collation debt"
        return COL_DERIVED if table_role == ROLE_DERIVED else COL_CANONICAL, "profile linkage"
    if column_name in {"status", "session_status", "session_disposition"}:
        if table_role == ROLE_LEGACY:
            return COL_LEGACY, "legacy status domain"
        return COL_CANONICAL if table_role in {ROLE_CANONICAL, ROLE_LEDGER} else COL_DERIVED, "status domain"
    if column_name.endswith("_at_utc") or column_name.endswith("_started_utc") or column_name.endswith("_ended_utc") or column_name.endswith("_created_at"):
        if column_type.startswith("varchar") or column_type.endswith("text"):
            return COL_LEGACY, "string timestamp debt"
        return COL_TYPED if column_name == "run_started_at_utc" else (COL_CANONICAL if table_role in {ROLE_CANONICAL, ROLE_LEDGER} else COL_DERIVED), "temporal column"
    if "permission" in column_name or "authority" in column_name or "intel" in column_name or "canonical" in column_name or "mapping" in column_name:
        if populated_rows == 0 and column_name.endswith("_hash"):
            return COL_MISSING, "hash/version authority interface not yet populated"
        return COL_CANONICAL if table_role == ROLE_CANONICAL else COL_DERIVED, "permission/intel interface surface"
    if column_type in {"json", "longtext", "text", "mediumtext"} or column_name.endswith("_json"):
        if populated_rows == 0:
            return COL_DEPRECATED, "text/json column is zero-signal in current live data"
        return COL_CANONICAL if table_role in {ROLE_CANONICAL, ROLE_LEDGER} else COL_DERIVED, "receipt or evidence payload"
    return (
        COL_CANONICAL if table_role == ROLE_CANONICAL else COL_DERIVED if table_role == ROLE_DERIVED else COL_LEGACY if table_role == ROLE_LEGACY else COL_UNKNOWN,
        "default classification by table role",
    )


def _gather_inventory(run_sql) -> dict[str, Any]:
    tables = _rows(
        run_sql,
        """
        SELECT table_name, table_type, table_rows
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
        ORDER BY table_type, table_name
        """,
        query_name="canonical_schema_map.tables",
    )
    columns = _rows(
        run_sql,
        """
        SELECT
          table_name,
          column_name,
          ordinal_position,
          column_type,
          data_type,
          is_nullable,
          column_key,
          extra,
          character_set_name,
          collation_name,
          column_default
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
        ORDER BY table_name, ordinal_position
        """,
        query_name="canonical_schema_map.columns",
    )
    stats = _rows(
        run_sql,
        """
        SELECT
          table_name,
          index_name,
          non_unique,
          seq_in_index,
          column_name
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
        ORDER BY table_name, index_name, seq_in_index
        """,
        query_name="canonical_schema_map.statistics",
    )
    fks = _rows(
        run_sql,
        """
        SELECT
          kcu.table_name,
          kcu.column_name,
          kcu.referenced_table_name,
          kcu.referenced_column_name,
          rc.constraint_name
        FROM information_schema.key_column_usage kcu
        LEFT JOIN information_schema.referential_constraints rc
          ON rc.constraint_schema = kcu.constraint_schema
         AND rc.constraint_name = kcu.constraint_name
        WHERE kcu.table_schema = DATABASE()
          AND kcu.referenced_table_name IS NOT NULL
        ORDER BY kcu.table_name, kcu.constraint_name, kcu.ordinal_position
        """,
        query_name="canonical_schema_map.fks",
    )
    return {"tables": tables, "columns": columns, "stats": stats, "fks": fks}


def _index_maps(stats: list[dict[str, Any]]) -> tuple[dict[str, str], dict[str, list[dict[str, Any]]]]:
    primary_keys: dict[str, str] = {}
    unique_indexes: dict[str, list[dict[str, Any]]] = defaultdict(list)
    grouped: dict[tuple[str, str], list[tuple[int, str]]] = defaultdict(list)
    non_unique_by_index: dict[tuple[str, str], int] = {}
    for row in stats:
        table_name = str(row.get("table_name") or "")
        index_name = str(row.get("index_name") or "")
        seq = int(row.get("seq_in_index") or 0)
        col = str(row.get("column_name") or "")
        grouped[(table_name, index_name)].append((seq, col))
        non_unique_by_index[(table_name, index_name)] = int(row.get("non_unique") or 0)
    for (table_name, index_name), pairs in grouped.items():
        cols = ", ".join(col for _, col in sorted(pairs))
        if index_name == "PRIMARY":
            primary_keys[table_name] = cols
        elif non_unique_by_index[(table_name, index_name)] == 0:
            unique_indexes[table_name].append({"index_name": index_name, "columns": cols})
    return primary_keys, unique_indexes


def _fk_maps(fks: list[dict[str, Any]]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    parents: dict[str, list[str]] = defaultdict(list)
    children: dict[str, list[str]] = defaultdict(list)
    for row in fks:
        table_name = str(row.get("table_name") or "")
        col = str(row.get("column_name") or "")
        ref_table = str(row.get("referenced_table_name") or "")
        ref_col = str(row.get("referenced_column_name") or "")
        if table_name and ref_table:
            parents[table_name].append(f"{col}->{ref_table}.{ref_col}")
            children[ref_table].append(f"{table_name}.{col}")
    return parents, children


def _collect_collation_drift(run_sql) -> list[dict[str, Any]]:
    return _rows(
        run_sql,
        """
        SELECT
          column_name,
          COUNT(DISTINCT collation_name) AS distinct_collations,
          GROUP_CONCAT(DISTINCT CONCAT(table_name, ':', collation_name) ORDER BY table_name SEPARATOR ' | ') AS table_collations
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND column_name IN ('session_stamp','package_name','package_name_lc','profile_key','dynamic_run_id','dynamic_run_uuid')
          AND collation_name IS NOT NULL
        GROUP BY column_name
        HAVING COUNT(DISTINCT collation_name) > 1
        ORDER BY distinct_collations DESC, column_name
        """,
        query_name="canonical_schema_map.collation_drift",
    )


def _collect_id_type_drift(run_sql) -> list[dict[str, Any]]:
    return _rows(
        run_sql,
        """
        SELECT
          table_name,
          column_name,
          column_type,
          data_type,
          is_nullable,
          column_key
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND (
            column_name LIKE '%run_id%'
            OR column_name LIKE '%session_id%'
            OR column_name LIKE '%app_version_id%'
            OR column_name LIKE '%apk_set_id%'
          )
        ORDER BY column_name, column_type, table_name
        """,
        query_name="canonical_schema_map.id_type_drift",
    )


def _collect_status_domains(run_sql) -> list[dict[str, Any]]:
    status_columns = _rows(
        run_sql,
        """
        SELECT table_name, column_name
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND (
            column_name = 'status'
            OR column_name LIKE '%status'
            OR column_name LIKE '%_status'
            OR column_name LIKE '%disposition'
          )
          AND table_name NOT LIKE 'v_%'
          AND table_name NOT LIKE 'vw_%'
        ORDER BY table_name, column_name
        """,
        query_name="canonical_schema_map.status_columns",
    )
    rows: list[dict[str, Any]] = []
    for item in status_columns:
        table_name = str(item.get("table_name") or "")
        column_name = str(item.get("column_name") or "")
        sql = f"SELECT `{column_name}` AS domain_value, COUNT(*) AS row_count FROM `{table_name}` GROUP BY `{column_name}` ORDER BY row_count DESC"
        values = _rows(run_sql, sql, query_name=f"canonical_schema_map.status_domain.{table_name}.{column_name}")
        for value in values:
            rows.append(
                {
                    "table_name": table_name,
                    "column_name": column_name,
                    "domain_value": value.get("domain_value"),
                    "row_count": int(value.get("row_count") or 0),
                }
            )
    return rows


def _collect_timestamp_debt(run_sql) -> list[dict[str, Any]]:
    timestamp_columns = _rows(
        run_sql,
        """
        SELECT
          table_name,
          column_name,
          column_type,
          data_type,
          is_nullable
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND (
            column_name LIKE '%_utc'
            OR column_name LIKE '%created_at%'
            OR column_name LIKE '%started%'
            OR column_name LIKE '%ended%'
          )
          AND table_name NOT LIKE 'v_%'
          AND table_name NOT LIKE 'vw_%'
        ORDER BY table_name, column_name
        """,
        query_name="canonical_schema_map.timestamp_columns",
    )
    rows: list[dict[str, Any]] = []
    for item in timestamp_columns:
        table_name = str(item.get("table_name") or "")
        column_name = str(item.get("column_name") or "")
        column_type = str(item.get("column_type") or "")
        populated = _scalar(
            run_sql,
            f"SELECT COUNT(*) FROM `{table_name}` WHERE `{column_name}` IS NOT NULL AND TRIM(CAST(`{column_name}` AS CHAR)) <> ''",
            query_name=f"canonical_schema_map.timestamp_populated.{table_name}.{column_name}",
        )
        parseable = None
        if column_type.startswith("varchar") or column_type.endswith("text"):
            parseable = _scalar(
                run_sql,
                f"""
                SELECT COUNT(*) FROM `{table_name}`
                WHERE `{column_name}` IS NOT NULL
                  AND TRIM(`{column_name}`) <> ''
                  AND (
                    STR_TO_DATE(REPLACE(REPLACE(`{column_name}`,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f') IS NOT NULL
                    OR STR_TO_DATE(REPLACE(REPLACE(`{column_name}`,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s') IS NOT NULL
                  )
                """,
                query_name=f"canonical_schema_map.timestamp_parseable.{table_name}.{column_name}",
            )
        rows.append(
            {
                "table_name": table_name,
                "column_name": column_name,
                "column_type": column_type,
                "data_type": item.get("data_type"),
                "is_nullable": item.get("is_nullable"),
                "populated_rows": int(populated or 0),
                "parseable_rows": int(parseable or 0) if parseable is not None else "",
                "timestamp_debt_class": "string_timestamp" if parseable is not None else "typed_temporal",
            }
        )
    return rows


def _collect_json_signal(run_sql) -> list[dict[str, Any]]:
    text_columns = _rows(
        run_sql,
        """
        SELECT table_name, column_name, column_type, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name NOT LIKE 'v_%'
          AND table_name NOT LIKE 'vw_%'
          AND (
            data_type IN ('json','longtext','text','mediumtext')
            OR column_name LIKE '%json%'
          )
        ORDER BY table_name, ordinal_position
        """,
        query_name="canonical_schema_map.json_columns",
    )
    rows: list[dict[str, Any]] = []
    for item in text_columns:
        table_name = str(item.get("table_name") or "")
        column_name = str(item.get("column_name") or "")
        total = _scalar(run_sql, f"SELECT COUNT(*) FROM `{table_name}`", query_name=f"canonical_schema_map.json_total.{table_name}")
        populated = _scalar(
            run_sql,
            f"SELECT COUNT(*) FROM `{table_name}` WHERE `{column_name}` IS NOT NULL AND TRIM(CAST(`{column_name}` AS CHAR)) <> ''",
            query_name=f"canonical_schema_map.json_populated.{table_name}.{column_name}",
        )
        role = _table_role(table_name, "BASE TABLE")
        signal = "zero_signal" if int(populated or 0) == 0 else "populated"
        path_class = "cold_receipt"
        if role == ROLE_DERIVED:
            path_class = "derived_blob"
        elif table_name in {"artifact_registry", "schema_migrations", "analysis_derivation_receipts", "static_persistence_failures"}:
            path_class = "cold_receipt"
        elif table_name in {"static_analysis_runs", "permission_signal_observations", "dynamic_sessions"}:
            path_class = "hot_query_path_debt"
        rows.append(
            {
                "table_name": table_name,
                "column_name": column_name,
                "column_type": item.get("column_type"),
                "data_type": item.get("data_type"),
                "total_rows": int(total or 0),
                "populated_rows": int(populated or 0),
                "signal_class": signal,
                "path_class": path_class,
            }
        )
    return rows


def _collect_permission_interfaces(run_sql) -> list[dict[str, Any]]:
    return _rows(
        run_sql,
        """
        SELECT
          table_name,
          column_name,
          column_type,
          data_type,
          is_nullable
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND (
            column_name LIKE '%permission%'
            OR column_name LIKE '%authority%'
            OR column_name LIKE '%intel%'
            OR column_name LIKE '%canonical%'
            OR column_name LIKE '%mapping%'
          )
        ORDER BY table_name, ordinal_position
        """,
        query_name="canonical_schema_map.permission_interfaces",
    )


def _build_table_rows(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    tables = inventory["tables"]
    stats = inventory["stats"]
    fks = inventory["fks"]
    primary_keys, unique_indexes = _index_maps(stats)
    parents, children = _fk_maps(fks)

    rows: list[dict[str, Any]] = []
    for item in tables:
        table_name = str(item.get("table_name") or "")
        object_type = str(item.get("table_type") or "")
        role = _table_role(table_name, object_type)
        fk_eventual, fk_reason = _fk_policy(table_name, role)
        parent_text = ", ".join(parents.get(table_name, []))
        child_text = ", ".join(children.get(table_name, []))
        inferred = MANUAL_RELATIONSHIPS.get(table_name, "")
        relationships = " | ".join(part for part in [parent_text, child_text, inferred] if part)
        rows.append(
            {
                "table_name": table_name,
                "object_type": object_type,
                "row_count_estimate": item.get("table_rows"),
                "role_classification": role,
                "domain_group": _domain_group(table_name, object_type, role),
                "primary_key": primary_keys.get(table_name, ""),
                "natural_key": _natural_key(table_name, unique_indexes.get(table_name, [])),
                "main_relationships": relationships,
                "write_surface": _write_surface(table_name, object_type),
                "fk_harden_eventually": fk_eventual,
                "fk_loose_reason": fk_reason,
                "major_schema_debt": _major_schema_debt(table_name, role),
                "proposed_migration_phase": _phase_for_table(table_name, object_type, role),
                "risk_level": _risk_level(role, table_name, object_type),
            }
        )
    return rows


def _build_column_role_rows(inventory: dict[str, Any], json_signal: list[dict[str, Any]], permission_interfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    columns = inventory["columns"]
    tables_by_name = {str(row.get("table_name")): str(row.get("table_type")) for row in inventory["tables"]}
    json_populated_map = {(row["table_name"], row["column_name"]): int(row.get("populated_rows") or 0) for row in json_signal}

    target_columns = {
        "session_stamp",
        "static_session_id",
        "static_run_id",
        "static_run_id_u",
        "dynamic_run_id",
        "dynamic_run_uuid",
        "package_name",
        "package_name_lc",
        "profile_key",
        "status",
        "session_status",
        "session_disposition",
    }

    selected: list[dict[str, Any]] = []
    for col in columns:
        table_name = str(col.get("table_name") or "")
        column_name = str(col.get("column_name") or "")
        column_type = str(col.get("column_type") or "")
        object_type = tables_by_name.get(table_name, "BASE TABLE")
        role = _table_role(table_name, object_type)
        if (
            column_name in target_columns
            or column_name.endswith("_at_utc")
            or column_name.endswith("_utc")
            or column_name.endswith("_json")
            or col.get("data_type") in {"json", "longtext", "text", "mediumtext"}
            or any(token in column_name for token in ("permission", "authority", "intel", "canonical", "mapping"))
        ):
            populated = json_populated_map.get((table_name, column_name))
            classification, note = _column_classification(table_name, object_type, role, column_name, column_type, populated_rows=populated)
            selected.append(
                {
                    "table_name": table_name,
                    "object_type": object_type,
                    "table_role": role,
                    "column_name": column_name,
                    "column_type": column_type,
                    "column_classification": classification,
                    "classification_note": note,
                }
            )

    for missing in [
        ("apps", "package_name_lc", "varchar(255)", "lowercase canonical package key missing from app identity spine"),
        ("app_versions", "signing_cert_sha256", "char(64)", "signing certificate digest not yet explicit in canonical version spine"),
        ("permission_audit_snapshots", "permission_intel_snapshot_id", "bigint unsigned", "explicit Permission Intel snapshot FK/hash surface missing"),
        ("permission_audit_snapshots", "permission_authority_hash", "char(64)", "authority hash/version capture missing"),
        ("static_analysis_runs", "permission_authority_hash", "char(64)", "run-level authority overlay hash missing"),
    ]:
        table_name, column_name, column_type, note = missing
        selected.append(
            {
                "table_name": table_name,
                "object_type": "BASE TABLE",
                "table_role": _table_role(table_name, "BASE TABLE"),
                "column_name": column_name,
                "column_type": column_type,
                "column_classification": COL_MISSING,
                "classification_note": note,
            }
        )

    return sorted(selected, key=lambda row: (row["column_name"], row["table_name"]))


def build_report(run_sql) -> dict[str, Any]:
    inventory = _gather_inventory(run_sql)
    table_rows = _build_table_rows(inventory)
    collation_drift = _collect_collation_drift(run_sql)
    id_type_drift = _collect_id_type_drift(run_sql)
    status_domain_drift = _collect_status_domains(run_sql)
    timestamp_debt = _collect_timestamp_debt(run_sql)
    json_signal = _collect_json_signal(run_sql)
    permission_interfaces = _collect_permission_interfaces(run_sql)
    column_role_rows = _build_column_role_rows(inventory, json_signal, permission_interfaces)

    role_counts: dict[str, int] = defaultdict(int)
    object_counts: dict[str, int] = defaultdict(int)
    for row in table_rows:
        role_counts[str(row["role_classification"])] += 1
        object_counts[str(row["object_type"])] += 1

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "base_table_count": object_counts.get("BASE TABLE", 0),
        "view_count": object_counts.get("VIEW", 0),
        "role_counts": dict(sorted(role_counts.items())),
        "collation_drift_count": len(collation_drift),
        "id_type_drift_rows": len(id_type_drift),
        "timestamp_debt_rows": len(timestamp_debt),
        "status_domain_rows": len(status_domain_drift),
        "json_signal_rows": len(json_signal),
        "permission_interface_rows": len(permission_interfaces),
        "column_role_rows": len(column_role_rows),
    }
    return {
        "summary": summary,
        "table_role_inventory": table_rows,
        "column_role_inventory": column_role_rows,
        "collation_drift": collation_drift,
        "id_type_drift": id_type_drift,
        "timestamp_debt": timestamp_debt,
        "status_domain_drift": status_domain_drift,
        "json_signal": json_signal,
        "permission_interface_points": permission_interfaces,
    }


def write_report_bundle(report: Mapping[str, Any], output_root: Path) -> dict[str, str]:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = output_root / stamp
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "summary.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")

    files = {"summary_json": str(json_path.resolve()), "output_dir": str(out_dir.resolve())}
    csv_sections = {
        "table_role_inventory.csv": report.get("table_role_inventory") or [],
        "column_role_inventory.csv": report.get("column_role_inventory") or [],
        "collation_drift.csv": report.get("collation_drift") or [],
        "id_type_drift.csv": report.get("id_type_drift") or [],
        "timestamp_debt.csv": report.get("timestamp_debt") or [],
        "status_domain_drift.csv": report.get("status_domain_drift") or [],
        "json_signal.csv": report.get("json_signal") or [],
        "permission_interface_points.csv": report.get("permission_interface_points") or [],
    }
    for filename, rows in csv_sections.items():
        path = out_dir / filename
        _csv_write(path, list(rows))
        files[filename] = str(path.resolve())
    return files


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    report = build_report(core_q.run_sql)
    files = write_report_bundle(report, Path(args.output_root))
    report["receipt_files"] = files

    if args.json:
        sys.stdout.write(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n")
        return 0

    summary = report.get("summary") or {}
    print("# canonical schema map")
    print(f"output_dir: {files['output_dir']}")
    print(f"base_table_count: {summary.get('base_table_count')}")
    print(f"view_count: {summary.get('view_count')}")
    print(f"role_counts: {json.dumps(summary.get('role_counts') or {}, sort_keys=True)}")
    print(f"collation_drift_count: {summary.get('collation_drift_count')}")
    print(f"id_type_drift_rows: {summary.get('id_type_drift_rows')}")
    print(f"timestamp_debt_rows: {summary.get('timestamp_debt_rows')}")
    print(f"status_domain_rows: {summary.get('status_domain_rows')}")
    print(f"json_signal_rows: {summary.get('json_signal_rows')}")
    print(f"permission_interface_rows: {summary.get('permission_interface_rows')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
