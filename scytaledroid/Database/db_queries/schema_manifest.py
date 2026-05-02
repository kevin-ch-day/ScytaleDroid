"""Ordered schema manifest for deterministic bootstrap."""

from __future__ import annotations

import re
from collections.abc import Iterable

from .analysis import schema as analysis_schema
from .canonical import schema as canonical_schema
from .dynamic import schema as dynamic_schema
from .harvest import device_inventory, dynamic_loading
from .permissions import governance_snapshot, permission_support
from .static_analysis import (
    risk_scores,
    static_findings,
    static_permission_matrix,
    string_analysis,
)
from .static_analysis.static_permission_risk import (
    CREATE_TABLE_VNEXT as CREATE_STATIC_PERMISSION_RISK_VNEXT,
)
from .views import (
    CREATE_V_ARTIFACT_REGISTRY_INTEGRITY,
    CREATE_V_CURRENT_ARTIFACT_REGISTRY,
    CREATE_V_PAPER_DYNAMIC_COHORT_V1,
    CREATE_V_RUN_IDENTITY,
    CREATE_V_RUN_OVERVIEW,
    CREATE_V_RUNTIME_DYNAMIC_COHORT_STATUS_V1,
    CREATE_V_STATIC_HANDOFF_V1,
    CREATE_V_STATIC_MASVS_FINDINGS_V1,
    CREATE_V_STATIC_MASVS_MATRIX_V1,
    CREATE_V_STATIC_MASVS_SESSION_SUMMARY_V1,
    CREATE_V_STATIC_RISK_SURFACES_V1,
    CREATE_V_WEB_APP_DIRECTORY,
    CREATE_V_WEB_APP_MASVS_LATEST_V1,
    CREATE_V_WEB_APP_STATIC_HANDOFF_READINESS_V1,
    CREATE_V_WEB_RUNTIME_RUN_DETAIL,
    CREATE_V_WEB_RUNTIME_RUN_INDEX,
    CREATE_V_WEB_STATIC_DYNAMIC_APP_SUMMARY,
    CREATE_VW_LATEST_APK_PER_PACKAGE,
    CREATE_VW_LATEST_PERMISSION_RISK,
    CREATE_VW_PERMISSION_AUDIT_LATEST,
    CREATE_VW_STATIC_FINDING_SURFACES_LATEST,
    CREATE_VW_STATIC_RISK_SURFACES_LATEST,
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

    # Permission runtime tables owned by the operational DB.
    # Dedicated permission-intel reference/governance tables are bootstrapped
    # separately and should not be recreated here after the Phase 5 cutover.
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
            CREATE_STATIC_PERMISSION_RISK_VNEXT,
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
    statements.append(CREATE_VW_LATEST_APK_PER_PACKAGE)
    statements.append(CREATE_VW_LATEST_PERMISSION_RISK)
    statements.append(CREATE_VW_PERMISSION_AUDIT_LATEST)
    statements.append(CREATE_V_STATIC_RISK_SURFACES_V1)
    statements.append(CREATE_VW_STATIC_RISK_SURFACES_LATEST)
    statements.append(CREATE_VW_STATIC_FINDING_SURFACES_LATEST)
    statements.append(CREATE_V_RUN_OVERVIEW)
    statements.append(CREATE_V_RUN_IDENTITY)
    statements.append(CREATE_V_STATIC_HANDOFF_V1)
    statements.append(CREATE_V_STATIC_MASVS_FINDINGS_V1)
    statements.append(CREATE_V_STATIC_MASVS_MATRIX_V1)
    statements.append(CREATE_V_STATIC_MASVS_SESSION_SUMMARY_V1)
    statements.append(CREATE_V_RUNTIME_DYNAMIC_COHORT_STATUS_V1)
    statements.append(CREATE_V_PAPER_DYNAMIC_COHORT_V1)
    statements.append(CREATE_V_WEB_APP_DIRECTORY)
    statements.append(CREATE_V_WEB_STATIC_DYNAMIC_APP_SUMMARY)
    statements.append(CREATE_V_WEB_APP_MASVS_LATEST_V1)
    statements.append(CREATE_V_WEB_APP_STATIC_HANDOFF_READINESS_V1)
    statements.append(CREATE_V_WEB_RUNTIME_RUN_INDEX)
    statements.append(CREATE_V_WEB_RUNTIME_RUN_DETAIL)
    statements.append(CREATE_V_ARTIFACT_REGISTRY_INTEGRITY)
    statements.append(CREATE_V_CURRENT_ARTIFACT_REGISTRY)

    return _dedupe_create_tables(statements)


def permission_intel_schema_statements() -> list[str]:
    """Return dedicated permission-intel schema statements.

    These statements belong to the separate ``android_permission_intel`` logical
    database target and are intentionally excluded from the operational schema
    bootstrap manifest.
    """

    return _dedupe_create_tables(
        [
            governance_snapshot.CREATE_GOVERNANCE_SNAPSHOTS,
            governance_snapshot.CREATE_GOVERNANCE_ENTRIES,
            permission_support.CREATE_SIGNAL_CATALOG,
            permission_support.CREATE_SIGNAL_MAPPINGS,
            permission_support.CREATE_COHORT_EXPECTATIONS,
        ]
    )


__all__ = ["ordered_schema_statements", "permission_intel_schema_statements"]
