"""Ordered schema manifest for deterministic bootstrap."""

from __future__ import annotations

import re
from collections.abc import Iterable

from .analysis import schema as analysis_schema
from .canonical import schema as canonical_schema
from .dynamic import schema as dynamic_schema
from .harvest import device_inventory, dynamic_loading
from .permissions import governance_snapshot, permission_support
from .views import CREATE_V_PAPER_DYNAMIC_COHORT_V1, CREATE_V_STATIC_HANDOFF_V1
from .static_analysis import (
    risk_scores,
    static_findings,
    static_permission_matrix,
    static_permission_risk,
    string_analysis,
)

_CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+`?([a-zA-Z0-9_]+)`?",
    re.IGNORECASE,
)


def _schema_version_stmt() -> str:
    return """
    CREATE TABLE IF NOT EXISTS schema_version (
      version TEXT NOT NULL,
      applied_at_utc TEXT NOT NULL
    );
    """


def _dedupe_create_tables(statements: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for stmt in statements:
        match = _CREATE_TABLE_RE.search(stmt or "")
        if match:
            table = match.group(1).lower()
            if table in seen:
                continue
            seen.add(table)
        ordered.append(stmt)
    return ordered


def ordered_schema_statements() -> list[str]:
    statements: list[str] = []

    statements.append(_schema_version_stmt())

    # Canonical static-analysis schema (ordered list).
    statements.extend(list(getattr(canonical_schema, "_DDL_STATEMENTS", [])))

    # Permission taxonomy and catalogs.
    statements.extend(
        [
            """
            CREATE TABLE IF NOT EXISTS perm_groups (
              group_key VARCHAR(64) NOT NULL,
              display_name VARCHAR(191) NOT NULL,
              description TEXT NULL,
              default_band VARCHAR(16) NULL,
              created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
              PRIMARY KEY (group_key)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            governance_snapshot.CREATE_GOVERNANCE_SNAPSHOTS,
            governance_snapshot.CREATE_GOVERNANCE_ENTRIES,
            permission_support.CREATE_SIGNAL_CATALOG,
            permission_support.CREATE_SIGNAL_MAPPINGS,
            permission_support.CREATE_COHORT_EXPECTATIONS,
            permission_support.CREATE_AUDIT_SNAPSHOTS,
            permission_support.CREATE_AUDIT_APPS,
        ]
    )

    # Static analysis persistence tables not covered by canonical schema.
    statements.extend(
        [
            static_findings.CREATE_FINDINGS_SUMMARY,
            static_findings.CREATE_FINDINGS,
            string_analysis.CREATE_STRING_SUMMARY,
            string_analysis.CREATE_STRING_SAMPLES,
            string_analysis.CREATE_STRING_SELECTED_SAMPLES,
            string_analysis.CREATE_STRING_SAMPLE_SETS,
            string_analysis.CREATE_DOC_HOSTS_TABLE,
            static_permission_matrix.CREATE_TABLE,
            static_permission_risk.CREATE_TABLE_VNEXT,
            risk_scores.CREATE_TABLE,
        ]
    )

    # Device inventory and dynamic loading tables.
    statements.extend(
        [
            device_inventory.CREATE_SNAPSHOTS_TABLE,
            device_inventory.CREATE_INVENTORY_TABLE,
            dynamic_loading.CREATE_TABLE_DYNLOAD_EVENTS,
            dynamic_loading.CREATE_TABLE_REFLECTION,
        ]
    )

    # Dynamic analysis sessions + telemetry (Phase 2).
    statements.extend(list(getattr(dynamic_schema, "_DDL_STATEMENTS", [])))

    # Post-paper analysis registry + derived aggregates (Phase H).
    statements.extend(list(getattr(analysis_schema, "_DDL_STATEMENTS", [])))

    # Canonical static-dynamic handoff view.
    statements.append(CREATE_V_STATIC_HANDOFF_V1)
    statements.append(CREATE_V_PAPER_DYNAMIC_COHORT_V1)

    return _dedupe_create_tables(statements)


__all__ = ["ordered_schema_statements"]
