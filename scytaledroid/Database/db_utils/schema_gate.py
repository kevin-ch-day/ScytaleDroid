"""Schema gate helpers for module entry points (canonical-only)."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core import permission_intel as intel_db
from scytaledroid.Database.db_core.permission_intel import MANAGED_TABLES
from scytaledroid.Database.db_utils import diagnostics

MIN_SCHEMA_VERSION = "0.2.6"


def _parse_version(value: str | None) -> tuple[int, ...]:
    if not value:
        return ()
    parts = re.findall(r"\d+", value)
    return tuple(int(part) for part in parts) if parts else ()


def _version_gte(current: str | None, minimum: str) -> bool:
    current_tuple = _parse_version(current)
    minimum_tuple = _parse_version(minimum)
    if not current_tuple:
        return False
    max_len = max(len(current_tuple), len(minimum_tuple))
    current_tuple += (0,) * (max_len - len(current_tuple))
    minimum_tuple += (0,) * (max_len - len(minimum_tuple))
    return current_tuple >= minimum_tuple


def _missing_columns(required: Mapping[str, Sequence[str]]) -> dict[str, list[str]]:
    missing: dict[str, list[str]] = {}
    for table, columns in required.items():
        actual = diagnostics.get_table_columns(table)
        if actual is None:
            missing[table] = list(columns)
            continue
        missing_cols = [col for col in columns if col not in actual]
        if missing_cols:
            missing[table] = missing_cols
    return missing


def check_base_schema() -> tuple[bool, str, str]:
    """Global base check: DB reachable, schema_version and apps exist."""
    if not db_config.db_enabled():
        return (
            False,
            "Database disabled.",
            "DB is optional. Configure SCYTALEDROID_DB_URL (mysql/mariadb) to enable persistence features.",
        )
    if not diagnostics.check_connection():
        return False, "Database connection failed.", "Check DB URL/credentials."
    tables = diagnostics.check_required_tables(["schema_version", "apps"])
    missing = [name for name, ok in tables.items() if not ok]
    if missing:
        return (
            False,
            "Database schema missing required base tables.",
            f"Missing: {', '.join(missing)}",
        )
    return True, "OK", ""


def check_module_schema(
    module: str,
    *,
    min_version: str = MIN_SCHEMA_VERSION,
    required_tables: Sequence[str],
    required_columns: Mapping[str, Sequence[str]] | None = None,
) -> tuple[bool, str, str]:
    schema_version = diagnostics.get_schema_version()
    if not _version_gte(schema_version, min_version):
        return (
            False,
            f"Database schema mismatch for {module}.",
            f"Required: schema_version >= {min_version} | Found: {schema_version or 'MISSING'}",
        )

    table_status = diagnostics.check_required_tables(list(required_tables))
    missing_tables = [name for name, ok in table_status.items() if not ok]
    if missing_tables:
        return (
            False,
            f"Database schema mismatch for {module}.",
            f"Missing tables: {', '.join(missing_tables)}",
        )

    if required_columns:
        missing_cols = _missing_columns(required_columns)
        if missing_cols:
            detail = "; ".join(
                f"{table}: {', '.join(cols)}" for table, cols in missing_cols.items()
            )
            return (
                False,
                f"Database schema mismatch for {module}.",
                f"Missing columns: {detail}",
            )

    return True, "OK", ""


def inventory_schema_gate() -> tuple[bool, str, str]:
    required_tables = [
        "device_inventory_snapshots",
        "device_inventory",
        "apps",
        "android_apk_repository",
        "apk_split_groups",
        "harvest_artifact_paths",
        "harvest_source_paths",
        "harvest_storage_roots",
    ]
    required_columns = {
        "apps": ["package_name", "profile_key"],
        "device_inventory_snapshots": ["snapshot_id", "device_serial", "captured_at", "package_count"],
        "device_inventory": ["snapshot_id", "package_name"],
        "android_apk_repository": ["package_name", "sha256", "harvested_at"],
    }
    return check_module_schema(
        "Inventory/Harvest",
        required_tables=required_tables,
        required_columns=required_columns,
    )


def static_schema_gate() -> tuple[bool, str, str]:
    """Gate for CLI static persistence: canonical tables + operational handoff view.

    Legacy tables such as ``runs``, ``metrics``, ``buckets``, and ``findings`` are no
    longer required here; compat writers may warn or skip when those objects are absent.
    """
    required_tables = [
        "static_analysis_runs",
        "static_analysis_findings",
        "static_permission_matrix",
        "static_string_summary",
        "static_string_samples",
        "static_session_run_links",
        "static_session_rollups",
        "v_static_handoff_v1",
    ]
    required_columns = {
        "static_analysis_runs": [
            "id",
            "app_version_id",
            "session_stamp",
            "session_label",
            "scope_label",
            "status",
            "base_apk_sha256",
            "identity_mode",
            "identity_conflict_flag",
            "static_handoff_hash",
            "static_handoff_json_path",
            "masvs_mapping_hash",
            "run_class",
            "non_canonical_reasons",
        ],
        "static_analysis_findings": [
            "run_id",
            "finding_id",
            "status",
            "severity",
            "severity_raw",
            "category",
            "title",
            "tags",
            "evidence",
            "fix",
            "rule_id",
            "cvss_score",
            "masvs_area",
            "masvs_control_id",
            "masvs_control",
            "detector",
            "module",
            "evidence_refs",
        ],
        "static_session_run_links": ["session_stamp", "package_name", "static_run_id"],
        "static_session_rollups": [
            "session_stamp",
            "scope_label",
            "apps_total",
            "completed",
            "failed",
            "aborted",
            "running",
        ],
        "static_string_summary": ["package_name", "session_stamp", "scope_label", "static_run_id"],
        "static_string_samples": ["summary_id", "static_run_id", "bucket"],
        "static_permission_matrix": ["run_id"],
    }
    return check_module_schema(
        "Static Analysis",
        required_tables=required_tables,
        required_columns=required_columns,
    )


def dynamic_schema_gate() -> tuple[bool, str, str]:
    required_tables = [
        "dynamic_sessions",
        "dynamic_session_issues",
        "dynamic_telemetry_process",
        "dynamic_telemetry_network",
    ]
    required_columns = {
        "dynamic_sessions": [
            "dynamic_run_id",
            "package_name",
            "started_at_utc",
            "tier",
            "sampling_duration_seconds",
            "clock_alignment_delta_s",
            "netstats_available",
            "network_signal_quality",
            "sample_first_gap_s",
            "sample_max_gap_excluding_first_s",
            "netstats_rows",
            "netstats_missing_rows",
            "pcap_relpath",
            "pcap_bytes",
            "pcap_sha256",
            "pcap_valid",
            "pcap_validated_at_utc",
        ],
        "dynamic_telemetry_process": ["dynamic_run_id", "timestamp_utc"],
        "dynamic_telemetry_network": ["dynamic_run_id", "timestamp_utc"],
    }
    return check_module_schema(
        "Dynamic Analysis",
        required_tables=required_tables,
        required_columns=required_columns,
    )


def permissions_schema_gate() -> tuple[bool, str, str]:
    ok, msg, detail = check_module_schema(
        "Permission Cohorts",
        required_tables=[
            "permission_audit_apps",
            "permission_audit_snapshots",
            "permission_signal_observations",
        ],
    )
    if not ok:
        return ok, msg, detail

    missing_managed = [table for table in MANAGED_TABLES if not intel_db.intel_table_exists(table)]
    if missing_managed:
        return (
            False,
            "Permission-intel schema mismatch.",
            "Missing managed tables in dedicated permission-intel DB: "
            + ", ".join(missing_managed),
        )
    return True, "OK", ""


__all__ = [
    "MIN_SCHEMA_VERSION",
    "check_base_schema",
    "inventory_schema_gate",
    "static_schema_gate",
    "dynamic_schema_gate",
    "permissions_schema_gate",
]
