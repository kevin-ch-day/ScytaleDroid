"""Dedicated access helpers for the permission-intel logical DB target.

Phase 5 posture:
- require the dedicated permission-intel env namespace
- do not fall back to the primary operational DB
- keep permission-intel reads/writes behind one boundary instead of spreading
  direct SQL against reference/governance tables across the codebase
"""

from __future__ import annotations

import re
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
V1_CATALOG_RELEASE_VIEW = "android_permission_v1_catalog_release"
V1_CURRENT_PERMISSION_VIEW = "android_permission_v1_current_permission"
V1_SCYTALEDROID_PERMISSION_VIEW = "android_permission_v1_scytaledroid_permission"
AUTHORITY_FACT_TABLE = "android_permission_authority_fact"
NON_PERMISSION_FACT_TABLE = "android_permission_non_permission_fact"
TOKEN_ANOMALY_FACT_TABLE = "android_permission_token_anomaly_fact"
CONCEPT_TABLE = "android_permission_concept"
DECLARATION_CONFLICT_TABLE = "api_permission_declaration_conflict"

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

# Freeze/copy inventory for dictionary + governance + signals. Do not add
# deployed v1 views or fact tables here — freeze renames MANAGED_TABLES.
MANAGED_TABLES: tuple[str, ...] = _REFERENCE_TABLES + _GOVERNANCE_TABLES + _SIGNAL_TABLES

# Read surfaces used by current interpretation and the analysis catalog.
# Tracked by preflight; not freeze/copy targets.
INTERPRETATION_SURFACES: tuple[str, ...] = (
    V1_CATALOG_RELEASE_VIEW,
    V1_CURRENT_PERMISSION_VIEW,
    V1_SCYTALEDROID_PERMISSION_VIEW,
    AUTHORITY_FACT_TABLE,
    NON_PERMISSION_FACT_TABLE,
    TOKEN_ANOMALY_FACT_TABLE,
    CONCEPT_TABLE,
    DECLARATION_CONFLICT_TABLE,
)

SUPPORTED_V1_SCHEMA_CONTRACT = "org.android-permission-intel.schema-v1-draft"
SUPPORTED_V1_SCHEMA_VERSION = "1.0.0-draft"
SUPPORTED_V1_SCHEMA_RELEASE_STATUS = "DRAFT"
SUPPORTED_V1_INTERPRETATION_CONTRACTS = frozenset({"1.0.0-draft", "1.1.0-draft"})
V1_REFERENCE_MODE = "DEPLOYED_V1"
_SCHEMA_VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$")
_TRIAGE_STATUSES = frozenset(
    {
        "aosp_missing",
        "app_defined",
        "brand_spoof",
        "gms_known",
        "in_review",
        "launcher_ecosystem",
        "malformed",
        "malicious_dga",
        "new",
        "oem_candidate",
        "resolved_aosp",
        "resolved_oem",
    }
)
_QUEUE_ACTIONS = frozenset({"aosp", "oem", "google", "app_defined", "reject", "defer"})
_QUEUE_STATUSES = frozenset({"queued", "applied", "error", "skipped", "rejected"})


class PermissionIntelSubmissionError(ValueError):
    """A Scytale producer attempted a blank or unsupported PI submission."""


def _required_text(payload: Mapping[str, Any], key: str) -> str:
    value = str(payload.get(key) or "").strip()
    if not value:
        raise PermissionIntelSubmissionError(f"{key} must not be blank")
    return value


def validate_unknown_submission(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize one unknown-ledger submission and reject vocabulary drift."""
    normalized = dict(payload)
    normalized["permission_string"] = _required_text(payload, "permission_string")
    status = _required_text(payload, "triage_status").lower()
    if status not in _TRIAGE_STATUSES:
        raise PermissionIntelSubmissionError(f"unsupported triage_status: {status}")
    normalized["triage_status"] = status
    return normalized


def validate_queue_submission(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize queue vocabulary and require durable producer identity."""
    normalized = validate_unknown_submission(payload)
    action = _required_text(payload, "queue_action").lower()
    status = _required_text(payload, "status").lower()
    if action not in _QUEUE_ACTIONS:
        raise PermissionIntelSubmissionError(f"unsupported queue_action: {action}")
    if status not in _QUEUE_STATUSES:
        raise PermissionIntelSubmissionError(f"unsupported queue status: {status}")
    normalized["queue_action"] = action
    normalized["status"] = status
    normalized["requested_by"] = _required_text(payload, "requested_by")
    normalized["source_system"] = _required_text(payload, "source_system")
    return normalized


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
            return db.execute_with_lastrowid(
                query, params, query_name=effective_name, context=context
            )
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


_INTEL_TABLES_PRESENT: set[str] = set()


def intel_table_exists(table: str) -> bool:
    name = str(table or "")
    if name in _INTEL_TABLES_PRESENT:
        return True
    row = run_sql(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
        (name,),
        fetch="one",
        query_name="permission_intel.intel_table_exists",
        context={"table": name},
        read_only=True,
    )
    present = bool(row and int(row[0] or 0) > 0)
    if present:
        _INTEL_TABLES_PRESENT.add(name)
    return present


def probe_dictionary_read_access() -> bool:
    """Return True when the AOSP dictionary table answers a trivial ``SELECT COUNT(*)``."""

    try:
        row = run_sql(
            f"SELECT COUNT(*) FROM {AOSP_DICT_TABLE}",
            fetch="one",
            query_name="permission_intel.probe_dictionary_read_access",
            read_only=True,
        )
        return bool(row and row[0] is not None)
    except Exception:
        return False


# COALESCE(lifecycle_status, '') wraps the column and prevents the family/lifecycle
# index from being used as a range predicate. NULL is a live dict row.
_AOSP_ACTIVE_LIFECYCLE_SQL = "(lifecycle_status IS NULL OR lifecycle_status <> 'invalid_token')"


def fetch_oem_permission_catalog_rows() -> list[tuple[object, ...]]:
    """Return OEM dictionary rows that carry a non-empty protection level."""

    rows = run_sql(
        """
        SELECT o.permission_string, o.protection_level
        FROM android_permission_dict_oem o
        INNER JOIN android_permission_meta_oem_vendor v
          ON v.vendor_id = o.vendor_id
        WHERE o.protection_level IS NOT NULL
          AND TRIM(o.protection_level) <> ''
        """,
        fetch="all",
        query_name="permission_intel.fetch_oem_permission_catalog_rows",
        read_only=True,
    )
    return list(rows or [])


def fetch_database_definers() -> list[tuple[object, ...]]:
    """Return object definers from the dedicated Permission Intel catalog."""

    rows = run_sql(
        """
        SELECT DISTINCT definer
        FROM (
            SELECT DEFINER AS definer FROM information_schema.views WHERE table_schema = DATABASE()
            UNION ALL SELECT DEFINER FROM information_schema.triggers WHERE trigger_schema = DATABASE()
            UNION ALL SELECT DEFINER FROM information_schema.routines WHERE routine_schema = DATABASE()
            UNION ALL SELECT DEFINER FROM information_schema.events WHERE event_schema = DATABASE()
        ) AS scoped_definers
        WHERE definer IS NOT NULL AND definer != ''
        ORDER BY definer
        """,
        fetch="all",
        query_name="permission_intel.fetch_database_definers",
        read_only=True,
    )
    return list(rows or ())


def fetch_aosp_permission_catalog_rows() -> list[tuple[object, object, object, object]]:
    """Return AOSP dict rows that can overlay the analysis catalog.

    Empty protection_level rows are excluded in SQL so the overlay does not
    ship the full dictionary for Python to discard.
    """

    rows = run_sql(
        f"""
        SELECT constant_value, protection_level, added_in_api_level, deprecated_in_api_level
        FROM android_permission_dict_aosp
        WHERE {_AOSP_ACTIVE_LIFECYCLE_SQL}
          AND protection_level IS NOT NULL
          AND TRIM(protection_level) <> ''
        """,
        fetch="all",
        query_name="permission_intel.fetch_aosp_permission_catalog_rows",
        read_only=True,
    )
    return list(rows or [])


def _schema_version_key(value: object) -> tuple[int, int, int, int, str]:
    text = str(value or "")
    match = _SCHEMA_VERSION_RE.fullmatch(text)
    if match is None:
        raise RuntimeError("Permission Intel v1 schema version interval is malformed")
    prerelease = match.group(4) or ""
    return (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
        0 if prerelease else 1,
        prerelease,
    )


def fetch_v1_catalog_gate() -> dict[str, Any]:
    """Return the one accepted v1 catalog or fail closed on compatibility drift."""
    rows = run_sql(
        """
        SELECT catalog_release_id, schema_contract_id, schema_contract_version,
               compatibility_floor, schema_contract_release_status,
               catalog_digest, source_set_digest, exhaustive_scope,
               catalog_release_status, catalog_import_status, import_receipt_count,
               accepted_at_utc
          FROM android_permission_v1_catalog_release
        """,
        fetch="all",
        dictionary=True,
        query_name="permission_intel.fetch_v1_catalog_gate",
        read_only=True,
    )
    if len(rows or []) != 1:
        raise RuntimeError("Permission Intel v1 requires exactly one accepted catalog")
    row = dict(rows[0])
    if row.get("schema_contract_id") != SUPPORTED_V1_SCHEMA_CONTRACT:
        raise RuntimeError("Permission Intel v1 schema contract is incompatible")
    actual_version = _schema_version_key(row.get("schema_contract_version"))
    supported_version = _schema_version_key(SUPPORTED_V1_SCHEMA_VERSION)
    compatibility_floor = _schema_version_key(row.get("compatibility_floor"))
    if actual_version != supported_version or compatibility_floor > supported_version:
        raise RuntimeError("Permission Intel v1 schema version interval is incompatible")
    if row.get("schema_contract_release_status") != SUPPORTED_V1_SCHEMA_RELEASE_STATUS:
        raise RuntimeError("Permission Intel v1 schema release status is incompatible")
    if row.get("catalog_release_status") != "ACCEPTED":
        raise RuntimeError("Permission Intel v1 catalog is not accepted")
    if (
        row.get("catalog_import_status") != "IMPORTED"
        or int(row.get("import_receipt_count") or 0) < 1
    ):
        raise RuntimeError("Permission Intel v1 catalog receipt is incomplete")
    if not row.get("accepted_at_utc"):
        raise RuntimeError("Permission Intel v1 catalog acceptance timestamp is missing")
    return row


# Equality (not BINARY wrapping) keeps the case-sensitive unique index on
# canonical_permission usable through the deployed views. Exact-case lookup
# still uses BINARY IN on the WHERE clause.
_V1_PERMISSION_SELECT = f"""
        SELECT sp.catalog_release_id, sp.catalog_digest, sp.canonical_permission,
               sp.symbolic_name, sp.namespace, sp.defining_package, sp.authority_class,
               sp.lifecycle, sp.accepted_platform_release, sp.source_provenance_status,
               sp.protection_base, sp.protection_modifiers,
               sp.compatibility_protection_expression,
               p.identity_status, p.feature_dependency, p.permission_group,
               p.background_permission, p.source_snapshot_id
          FROM {V1_SCYTALEDROID_PERMISSION_VIEW} sp
          LEFT JOIN {V1_CURRENT_PERMISSION_VIEW} p
            ON p.canonical_permission = sp.canonical_permission
           AND p.catalog_release_id = sp.catalog_release_id
           AND p.catalog_digest = sp.catalog_digest
"""


def _materialize_v1_permission_rows(
    rows: Sequence[Mapping[str, Any]] | None, gate: Mapping[str, Any]
) -> list[dict[str, Any]]:
    materialized = [
        {
            **dict(row),
            "scope_complete": bool(gate.get("exhaustive_scope")),
            "reference_mode": V1_REFERENCE_MODE,
        }
        for row in rows or []
    ]
    if len(materialized) != len({row.get("canonical_permission") for row in materialized}):
        raise RuntimeError("Permission Intel interpretation returned duplicate identity rows")
    for row in materialized:
        version = row.get("interpretation_contract_version")
        if version is None or str(version).strip() == "":
            continue
        if str(version) not in SUPPORTED_V1_INTERPRETATION_CONTRACTS:
            raise RuntimeError("Permission Intel interpretation contract is unsupported")
    return materialized


def fetch_v1_permission_rows(values: Sequence[str]) -> list[dict[str, Any]]:
    """Return exact-case accepted v1 platform references from deployed views."""
    items_list: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        if value != value.strip():
            raise ValueError("canonical permission must not contain surrounding whitespace")
        items_list.append(value)
    items = tuple(items_list)
    if not items:
        return []
    gate = fetch_v1_catalog_gate()
    placeholders = ",".join(["%s"] * len(items))
    rows = run_sql(
        f"""
        {_V1_PERMISSION_SELECT}
         WHERE BINARY sp.canonical_permission IN ({placeholders})
           AND sp.authority_class IN (
               'AOSP_PUBLIC', 'AOSP_HIDDEN', 'AOSP_INTERNAL', 'AOSP_MODULE'
           )
           AND sp.catalog_release_id = %s
           AND sp.catalog_digest = %s
        """,
        (*items, gate["catalog_release_id"], gate["catalog_digest"]),
        fetch="all",
        dictionary=True,
        query_name="permission_intel.fetch_v1_permission_rows",
        read_only=True,
    )
    return _materialize_v1_permission_rows(rows, gate)


def fetch_v1_permission_catalog_rows() -> list[dict[str, Any]]:
    """Return the accepted v1 Scytale projection from deployed catalog views."""
    gate = fetch_v1_catalog_gate()
    rows = run_sql(
        f"""
        {_V1_PERMISSION_SELECT}
         WHERE sp.authority_class IN (
               'AOSP_PUBLIC', 'AOSP_HIDDEN', 'AOSP_INTERNAL', 'AOSP_MODULE'
           )
           AND sp.catalog_release_id = %s
           AND sp.catalog_digest = %s
        """,
        (gate["catalog_release_id"], gate["catalog_digest"]),
        fetch="all",
        dictionary=True,
        query_name="permission_intel.fetch_v1_permission_catalog_rows",
        read_only=True,
    )
    return _materialize_v1_permission_rows(rows, gate)


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
        WHERE constant_value_norm IN ({placeholders})
          AND {_AOSP_ACTIVE_LIFECYCLE_SQL}
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
          AND {_AOSP_ACTIVE_LIFECYCLE_SQL}
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
          AND {_AOSP_ACTIVE_LIFECYCLE_SQL}
        """,
        items,
        fetch="all",
        query_name="permission_intel.fetch_aosp_permission_name_rows",
        read_only=True,
    )
    return list(rows or [])


def fetch_current_permission_interpretation_rows(
    values: Sequence[str],
) -> list[dict[str, Any]]:
    """Return deployed identity plus legacy evidence for current interpretation.

    This intentionally uses API-0007 views and existing fact tables. It does
    not depend on the undeployed v1.1 candidate views.
    """

    items = tuple(v for v in values if isinstance(v, str) and v.strip())
    if not items:
        return []
    lowered = tuple(sorted({item.lower() for item in items}))
    requested_sql = " UNION ALL ".join("SELECT %s AS lookup_token_norm" for _item in lowered)
    rows = run_sql(
        f"""
        SELECT requested.lookup_token_norm,
               a.constant_value,
               a.name AS legacy_name,
               a.protection_level AS legacy_protection,
               a.hard_restricted, a.soft_restricted,
               a.not_for_third_party_apps, a.is_deprecated,
               a.added_in_api_level, a.deprecated_in_api_level,
               a.source_family_key AS legacy_source_family,
               a.authority_source_type AS legacy_source_type,
               a.lifecycle_status AS legacy_lifecycle,
               p.permission_id, p.canonical_permission, p.authority_class,
               p.lifecycle AS catalog_lifecycle, p.feature_dependency,
               sp.compatibility_protection_expression AS catalog_protection,
               COALESCE(c.unresolved_conflict_count, 0) AS unresolved_conflict_count,
               f.permission_string AS fact_permission_string,
               f.fact_scope, f.authority_source_type AS fact_source_type,
               f.lifecycle_status AS fact_lifecycle, f.defining_package,
               f.protection_level AS fact_protection,
               np.token_class AS non_permission_class,
               ta.anomaly_class, co.concept_status,
               o.permission_string AS oem_permission_string,
               o.vendor_id AS oem_vendor_id,
               ov.vendor_id AS resolved_oem_vendor_id
          FROM ({requested_sql}) requested
          LEFT JOIN android_permission_dict_aosp a
            ON a.constant_value_norm = requested.lookup_token_norm
          LEFT JOIN android_permission_v1_current_permission p
            ON LOWER(p.canonical_permission) = requested.lookup_token_norm
          LEFT JOIN android_permission_v1_scytaledroid_permission sp
            ON sp.canonical_permission = p.canonical_permission
           AND sp.catalog_release_id = p.catalog_release_id
           AND sp.catalog_digest = p.catalog_digest
          LEFT JOIN (
            SELECT permission_id, COUNT(*) AS unresolved_conflict_count
            FROM api_permission_declaration_conflict
            WHERE resolution_status = 'UNRESOLVED'
            GROUP BY permission_id
          ) c ON c.permission_id = p.permission_id
          LEFT JOIN android_permission_authority_fact f
            ON f.permission_string_norm = requested.lookup_token_norm
           AND f.is_current_best = 1
          LEFT JOIN android_permission_non_permission_fact np
            ON np.token_value_norm = requested.lookup_token_norm AND np.is_active = 1
          LEFT JOIN android_permission_token_anomaly_fact ta
            ON ta.token_value_norm = requested.lookup_token_norm AND ta.is_active = 1
          LEFT JOIN android_permission_dict_oem o
            ON o.permission_string_norm = requested.lookup_token_norm
          LEFT JOIN android_permission_meta_oem_vendor ov
            ON ov.vendor_id = o.vendor_id
          LEFT JOIN android_permission_concept co
            ON BINARY co.canonical_token = BINARY a.constant_value
         GROUP BY requested.lookup_token_norm,
                  a.constant_value, a.name, a.protection_level,
                  a.hard_restricted, a.soft_restricted,
                  a.not_for_third_party_apps, a.is_deprecated,
                  a.added_in_api_level, a.deprecated_in_api_level,
                  a.source_family_key, a.authority_source_type,
                  a.lifecycle_status, p.permission_id, p.canonical_permission,
                  p.authority_class, p.lifecycle, p.feature_dependency,
                  sp.compatibility_protection_expression,
                  c.unresolved_conflict_count, f.permission_string,
                  f.fact_scope,
                  f.authority_source_type, f.lifecycle_status,
                  f.defining_package, f.protection_level,
                  np.token_class, ta.anomaly_class, co.concept_status,
                  o.permission_string, o.vendor_id, ov.vendor_id
        """,
        lowered,
        fetch="all",
        dictionary=True,
        query_name="permission_intel.fetch_current_permission_interpretation_rows",
        read_only=True,
    )
    return [dict(row) for row in rows or []]


def fetch_oem_permission_dict_rows(values: Sequence[str]) -> list[tuple[object, ...]]:
    items = tuple(v for v in values if isinstance(v, str) and v)
    if not items:
        return []
    placeholders = ",".join(["%s"] * len(items))
    rows = run_sql(
        f"""
        SELECT o.permission_string,
               o.vendor_id,
               o.display_name,
               o.protection_level,
               o.confidence,
               o.classification_source
        FROM android_permission_dict_oem o
        INNER JOIN android_permission_meta_oem_vendor v
          ON v.vendor_id = o.vendor_id
        WHERE BINARY o.permission_string IN ({placeholders})
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
    payload = validate_unknown_submission(payload)
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
    payload = validate_queue_submission(payload)
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
    "INTERPRETATION_SURFACES",
    "OEM_DICT_TABLE",
    "OEM_PREFIX_META_TABLE",
    "OEM_VENDOR_META_TABLE",
    "QUEUE_DICT_TABLE",
    "SIGNAL_CATALOG_TABLE",
    "SIGNAL_MAPPINGS_TABLE",
    "UNKNOWN_DICT_TABLE",
    "PermissionIntelSubmissionError",
    "SUPPORTED_V1_SCHEMA_CONTRACT",
    "SUPPORTED_V1_SCHEMA_RELEASE_STATUS",
    "SUPPORTED_V1_SCHEMA_VERSION",
    "SUPPORTED_V1_INTERPRETATION_CONTRACTS",
    "V1_REFERENCE_MODE",
    "V1_CATALOG_RELEASE_VIEW",
    "V1_CURRENT_PERMISSION_VIEW",
    "V1_SCYTALEDROID_PERMISSION_VIEW",
    "describe_target",
    "fetch_database_definers",
    "fetch_aosp_permission_dict_rows",
    "fetch_aosp_permission_name_rows",
    "fetch_current_permission_interpretation_rows",
    "fetch_aosp_permission_catalog_rows",
    "fetch_v1_catalog_gate",
    "fetch_v1_permission_catalog_rows",
    "fetch_v1_permission_rows",
    "fetch_oem_permission_dict_rows",
    "fetch_oem_permission_catalog_rows",
    "fetch_signal_catalog_rows",
    "fetch_vendor_meta_rows",
    "fetch_vendor_prefix_rule_rows",
    "governance_row_count",
    "governance_snapshot_count",
    "insert_permission_queue",
    "insert_signal_catalog_row",
    "intel_table_exists",
    "probe_dictionary_read_access",
    "latest_governance_loaded_at",
    "latest_governance_snapshot",
    "resolve_config",
    "run_sql",
    "session",
    "update_oem_permission_seen",
    "update_signal_catalog_row",
    "upsert_unknown_permission",
    "validate_queue_submission",
    "validate_unknown_submission",
]
