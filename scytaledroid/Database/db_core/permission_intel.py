"""Dedicated access helpers for the permission-intel logical DB target.

Phase 5 posture:
- require the dedicated permission-intel env namespace
- do not fall back to the primary operational DB
- keep permission-intel reads/writes behind one boundary instead of spreading
  direct SQL against reference/governance tables across the codebase
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from typing import Any

from . import db_config
from .db_engine import DatabaseEngine

_ROOT = "SCYTALEDROID_PERMISSION_INTEL_DB"
ParamsType = Sequence[Any] | Mapping[str, Any] | None

AOSP_DICT_TABLE = "android_permission_dict_aosp"
OEM_DICT_TABLE = "android_permission_dict_oem"
UNKNOWN_DICT_TABLE = "android_permission_dict_unknown"
QUEUE_DICT_TABLE = "android_permission_dict_queue"
OEM_VENDOR_META_TABLE = "android_permission_meta_oem_vendor"
OEM_PREFIX_META_TABLE = "android_permission_meta_oem_prefix"
GOVERNANCE_SNAPSHOTS_TABLE = "permission_governance_snapshots"
GOVERNANCE_ROWS_TABLE = "permission_governance_snapshot_rows"
SIGNAL_CATALOG_TABLE = "permission_signal_catalog"
SIGNAL_MAPPINGS_TABLE = "permission_signal_mappings"
COHORT_EXPECTATIONS_TABLE = "permission_cohort_expectations"

_REFERENCE_TABLES: tuple[str, ...] = (
    AOSP_DICT_TABLE,
    OEM_VENDOR_META_TABLE,
    OEM_PREFIX_META_TABLE,
    OEM_DICT_TABLE,
    UNKNOWN_DICT_TABLE,
    QUEUE_DICT_TABLE,
)

_GOVERNANCE_TABLES: tuple[str, ...] = (
    GOVERNANCE_SNAPSHOTS_TABLE,
    GOVERNANCE_ROWS_TABLE,
)

_SIGNAL_TABLES: tuple[str, ...] = (
    SIGNAL_CATALOG_TABLE,
    SIGNAL_MAPPINGS_TABLE,
    COHORT_EXPECTATIONS_TABLE,
)

MANAGED_TABLES: tuple[str, ...] = _REFERENCE_TABLES + _GOVERNANCE_TABLES + _SIGNAL_TABLES


def is_permission_intel_configured() -> bool:
    """Return True when ``SCYTALEDROID_PERMISSION_INTEL_DB_*`` resolves to a mysql/mariadb DSN.

    This checks **configuration only** — not connectivity, grants, or governance row counts.
    """

    resolved, _src = db_config.resolve_db_config_from_root(_ROOT)
    return resolved is not None


permission_intel_db_available = is_permission_intel_configured


def resolve_config() -> tuple[dict[str, Any], str, bool]:
    """Return config, source label, and whether compatibility fallback is active."""

    resolved, source = db_config.resolve_db_config_from_root(_ROOT)
    if resolved is not None:
        return dict(resolved), str(source or f"env:{_ROOT}_*"), False
    raise RuntimeError(
        "Dedicated permission-intel DB is not configured. "
        f"Set {_ROOT}_URL or {_ROOT}_NAME/USER/PASSWD/HOST/PORT."
    )


def describe_target() -> dict[str, Any]:
    """Return a small operator-facing summary of the current permission-intel target."""

    config, source, fallback = resolve_config()
    return {
        "engine": config.get("engine"),
        "host": config.get("host"),
        "port": config.get("port"),
        "database": config.get("database"),
        "user": config.get("user"),
        "source": source,
        "compatibility_mode": bool(fallback),
    }


@contextmanager
def session(*, read_only: bool = False) -> Iterator[DatabaseEngine]:
    """Yield a dedicated engine for permission-intel operations."""

    config, source, _fallback = resolve_config()
    engine = DatabaseEngine(config_override=config, config_source=source)
    if read_only:
        engine.as_reader()
    try:
        yield engine
    finally:
        engine.close()


def run_sql(
    query: str,
    params: ParamsType = None,
    *,
    fetch: str = "none",
    dictionary: bool = False,
    return_lastrowid: bool = False,
    query_name: str | None = None,
    context: Mapping[str, Any] | None = None,
    read_only: bool | None = None,
) -> Any:
    """Execute SQL against the permission-intel target."""

    base = (fetch or "none").strip().lower()
    if dictionary:
        if base == "none":
            raise ValueError("dictionary=True requires fetch in {'one','all'}")
        if not base.endswith("_dict"):
            base = f"{base}_dict"
    with session(read_only=bool(read_only if read_only is not None else base != "none")) as db:
        effective_name = query_name or f"permission_intel.{base}"
        if base == "one":
            return db.fetch_one(query, params, query_name=effective_name, context=context)
        if base == "one_dict":
            return db.fetch_one_dict(query, params, query_name=effective_name, context=context)
        if base == "all":
            return db.fetch_all(query, params, query_name=effective_name, context=context)
        if base == "all_dict":
            return db.fetch_all_dict(query, params, query_name=effective_name, context=context)
        if base != "none":
            raise ValueError(f"Unsupported fetch mode: {fetch}")
        if return_lastrowid:
            return db.execute_with_lastrowid(query, params, query_name=effective_name, context=context)
        db.execute(query, params, query_name=effective_name, context=context)
        return None


def latest_governance_snapshot() -> tuple[str | None, str | None, int]:
    """Return latest governance version, sha, and row count."""

    row = run_sql(
        """
        SELECT s.governance_version, s.snapshot_sha256, COUNT(r.permission_string) AS row_count
        FROM permission_governance_snapshots s
        LEFT JOIN permission_governance_snapshot_rows r
          ON r.governance_version = s.governance_version
        GROUP BY s.governance_version, s.snapshot_sha256
        ORDER BY s.loaded_at_utc DESC
        LIMIT 1
        """,
        fetch="one",
        query_name="permission_intel.latest_governance_snapshot",
        read_only=True,
    )
    if row and row[0]:
        return str(row[0]), str(row[1] or ""), int(row[2] or 0)
    return None, None, 0


def latest_governance_loaded_at(governance_version: str | None) -> str | None:
    """Return the latest load timestamp for a governance snapshot version."""

    if not governance_version:
        return None
    row = run_sql(
        """
        SELECT loaded_at_utc
        FROM permission_governance_snapshots
        WHERE governance_version = %s
        ORDER BY loaded_at_utc DESC
        LIMIT 1
        """,
        (governance_version,),
        fetch="one",
        query_name="permission_intel.latest_governance_loaded_at",
        read_only=True,
    )
    if row and row[0]:
        return str(row[0])
    return None


def governance_row_count() -> int:
    row = run_sql(
        "SELECT COUNT(*) FROM permission_governance_snapshot_rows",
        fetch="one",
        query_name="permission_intel.governance_row_count",
        read_only=True,
    )
    return int(row[0] or 0) if row else 0


def governance_snapshot_count() -> int:
    row = run_sql(
        "SELECT COUNT(*) FROM permission_governance_snapshots",
        fetch="one",
        query_name="permission_intel.governance_snapshot_count",
        read_only=True,
    )
    return int(row[0] or 0) if row else 0


def intel_table_exists(table: str) -> bool:
    row = run_sql(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
        (table,),
        fetch="one",
        query_name="permission_intel.intel_table_exists",
        context={"table": table},
        read_only=True,
    )
    return bool(row and int(row[0] or 0) > 0)


def fetch_aosp_permission_catalog_rows() -> list[tuple[object, object, object, object]]:
    """Return raw AOSP permission catalog rows from the permission-intel source."""

    rows = run_sql(
        """
        SELECT constant_value, protection_level, added_in_api_level, deprecated_in_api_level
        FROM android_permission_dict_aosp
        """,
        fetch="all",
        query_name="permission_intel.fetch_aosp_permission_catalog_rows",
        read_only=True,
    )
    return list(rows or [])


def fetch_aosp_permission_dict_rows(
    values: Sequence[str],
    *,
    case_insensitive: bool = False,
) -> list[tuple[object, ...]]:
    items = tuple(v for v in values if isinstance(v, str) and v)
    if not items:
        return []
    placeholders = ",".join(["%s"] * len(items))
    if case_insensitive:
        sql = f"""
        SELECT constant_value,
               name,
               protection_level,
               hard_restricted,
               soft_restricted,
               not_for_third_party_apps,
               is_deprecated,
               added_in_api_level,
               deprecated_in_api_level
        FROM android_permission_dict_aosp
        WHERE LOWER(constant_value) IN ({placeholders})
        """
        params: ParamsType = tuple(v.lower() for v in items)
    else:
        sql = f"""
        SELECT constant_value,
               name,
               protection_level,
               hard_restricted,
               soft_restricted,
               not_for_third_party_apps,
               is_deprecated,
               added_in_api_level,
               deprecated_in_api_level
        FROM android_permission_dict_aosp
        WHERE constant_value IN ({placeholders})
        """
        params = items
    rows = run_sql(
        sql,
        params,
        fetch="all",
        query_name="permission_intel.fetch_aosp_permission_dict_rows",
        read_only=True,
    )
    return list(rows or [])


def fetch_aosp_permission_name_rows(names: Sequence[str]) -> list[tuple[object, ...]]:
    items = tuple(v for v in names if isinstance(v, str) and v)
    if not items:
        return []
    placeholders = ",".join(["%s"] * len(items))
    rows = run_sql(
        f"""
        SELECT name,
               protection_level,
               hard_restricted,
               soft_restricted,
               not_for_third_party_apps,
               is_deprecated,
               added_in_api_level,
               deprecated_in_api_level
        FROM android_permission_dict_aosp
        WHERE name IN ({placeholders})
        """,
        items,
        fetch="all",
        query_name="permission_intel.fetch_aosp_permission_name_rows",
        read_only=True,
    )
    return list(rows or [])


def fetch_oem_permission_dict_rows(values: Sequence[str]) -> list[tuple[object, ...]]:
    items = tuple(v for v in values if isinstance(v, str) and v)
    if not items:
        return []
    placeholders = ",".join(["%s"] * len(items))
    rows = run_sql(
        f"""
        SELECT permission_string,
               vendor_id,
               display_name,
               protection_level,
               confidence,
               classification_source
        FROM android_permission_dict_oem
        WHERE permission_string IN ({placeholders})
        """,
        items,
        fetch="all",
        query_name="permission_intel.fetch_oem_permission_dict_rows",
        read_only=True,
    )
    return list(rows or [])


def fetch_vendor_prefix_rule_rows() -> list[tuple[object, ...]]:
    rows = run_sql(
        """
        SELECT vendor_id, namespace_prefix, match_type
        FROM android_permission_meta_oem_prefix
        WHERE is_enabled=1
        ORDER BY CHAR_LENGTH(namespace_prefix) DESC, prefix_id ASC
        """,
        fetch="all",
        query_name="permission_intel.fetch_vendor_prefix_rule_rows",
        read_only=True,
    )
    return list(rows or [])


def fetch_vendor_meta_rows() -> list[tuple[object, ...]]:
    rows = run_sql(
        """
        SELECT vendor_id, vendor_name, vendor_slug
        FROM android_permission_meta_oem_vendor
        """,
        fetch="all",
        query_name="permission_intel.fetch_vendor_meta_rows",
        read_only=True,
    )
    return list(rows or [])


def upsert_unknown_permission(payload: Mapping[str, Any]) -> None:
    run_sql(
        """
        INSERT INTO android_permission_dict_unknown
          (permission_string, triage_status, notes,
           first_seen_at_utc, last_seen_at_utc, seen_count, example_package_name, example_sample_id)
        VALUES
          (%(permission_string)s, %(triage_status)s, %(notes)s,
           %(first_seen_at_utc)s, %(last_seen_at_utc)s, %(seen_count)s, %(example_package_name)s, %(example_sample_id)s)
        ON DUPLICATE KEY UPDATE
          last_seen_at_utc = VALUES(last_seen_at_utc),
          seen_count = seen_count + 1,
          example_package_name = COALESCE(example_package_name, VALUES(example_package_name)),
          example_sample_id = COALESCE(example_sample_id, VALUES(example_sample_id)),
          notes = COALESCE(notes, VALUES(notes)),
          triage_status = CASE WHEN triage_status = 'new' THEN VALUES(triage_status) ELSE triage_status END
        """,
        payload,
        query_name="permission_intel.upsert_unknown_permission",
    )


def insert_permission_queue(payload: Mapping[str, Any]) -> None:
    run_sql(
        """
        INSERT INTO android_permission_dict_queue
          (permission_string, queue_action, proposed_bucket, proposed_classification, triage_status,
           notes, requested_by, source_system, status, created_at_utc, updated_at_utc)
        VALUES
          (%(permission_string)s, %(queue_action)s, %(proposed_bucket)s, %(proposed_classification)s, %(triage_status)s,
           %(notes)s, %(requested_by)s, %(source_system)s, %(status)s, %(created_at_utc)s, %(updated_at_utc)s)
        ON DUPLICATE KEY UPDATE
          updated_at_utc = VALUES(updated_at_utc),
          triage_status = VALUES(triage_status),
          notes = COALESCE(notes, VALUES(notes))
        """,
        payload,
        query_name="permission_intel.insert_permission_queue",
    )


def update_oem_permission_seen(permission_string: str, last_seen_at_utc: str) -> None:
    run_sql(
        """
        UPDATE android_permission_dict_oem
        SET last_seen_at_utc = %(last_seen_at_utc)s,
            seen_count = seen_count + 1
        WHERE permission_string = %(permission_string)s
        """,
        {
            "permission_string": permission_string,
            "last_seen_at_utc": last_seen_at_utc,
        },
        query_name="permission_intel.update_oem_permission_seen",
    )


def fetch_signal_catalog_rows() -> list[dict[str, Any]]:
    rows = run_sql(
        """
        SELECT signal_key, display_name, description, default_weight, default_band, stage
        FROM permission_signal_catalog
        """,
        fetch="all",
        dictionary=True,
        query_name="permission_intel.fetch_signal_catalog_rows",
        read_only=True,
    )
    return list(rows or [])


def insert_signal_catalog_row(payload: Mapping[str, Any]) -> None:
    run_sql(
        """
        INSERT INTO permission_signal_catalog
            (signal_key, display_name, description, default_weight, default_band, stage)
        VALUES (%(signal_key)s, %(display_name)s, %(description)s, %(default_weight)s, %(default_band)s, %(stage)s)
        """,
        payload,
        query_name="permission_intel.insert_signal_catalog_row",
    )


def update_signal_catalog_row(payload: Mapping[str, Any]) -> None:
    run_sql(
        """
        UPDATE permission_signal_catalog
        SET display_name = %(display_name)s,
            description = %(description)s,
            default_weight = %(default_weight)s,
            default_band = %(default_band)s,
            stage = %(stage)s,
            updated_at = CURRENT_TIMESTAMP
        WHERE signal_key = %(signal_key)s
        """,
        payload,
        query_name="permission_intel.update_signal_catalog_row",
    )


__all__ = [
    "is_permission_intel_configured",
    "permission_intel_db_available",
    "AOSP_DICT_TABLE",
    "COHORT_EXPECTATIONS_TABLE",
    "GOVERNANCE_ROWS_TABLE",
    "GOVERNANCE_SNAPSHOTS_TABLE",
    "MANAGED_TABLES",
    "OEM_DICT_TABLE",
    "OEM_PREFIX_META_TABLE",
    "OEM_VENDOR_META_TABLE",
    "QUEUE_DICT_TABLE",
    "SIGNAL_CATALOG_TABLE",
    "SIGNAL_MAPPINGS_TABLE",
    "UNKNOWN_DICT_TABLE",
    "describe_target",
    "fetch_aosp_permission_dict_rows",
    "fetch_aosp_permission_name_rows",
    "fetch_aosp_permission_catalog_rows",
    "fetch_oem_permission_dict_rows",
    "fetch_signal_catalog_rows",
    "fetch_vendor_meta_rows",
    "fetch_vendor_prefix_rule_rows",
    "governance_row_count",
    "governance_snapshot_count",
    "insert_permission_queue",
    "insert_signal_catalog_row",
    "intel_table_exists",
    "latest_governance_loaded_at",
    "latest_governance_snapshot",
    "resolve_config",
    "run_sql",
    "session",
    "update_oem_permission_seen",
    "update_signal_catalog_row",
    "upsert_unknown_permission",
]
