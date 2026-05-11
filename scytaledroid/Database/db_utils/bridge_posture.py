"""Bridge-table posture contract for Phase 5 cleanup.

This module centralizes the current posture for the remaining bridge/compat
tables so DB tools, docs, and later freeze work can share one explicit view.

**Planning authority for reader locations:** exhaustive inventory lives in
``docs/maintenance/legacy_static_reader_dependency_map.md`` (plus fresh ``rg``).
The ``current_readers`` / ``current_writers`` tuples below are **not** an
exhaustive allowlist — they highlight major call sites for operator orientation
only. Runtime behavior is unchanged by this metadata.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BridgeTablePosture:
    table: str
    posture: str
    owner: str
    rationale: str
    current_writers: tuple[str, ...]
    current_readers: tuple[str, ...]


_BRIDGE_POSTURES: tuple[BridgeTablePosture, ...] = (
    BridgeTablePosture(
        table="runs",
        posture="compat_only_keep",
        owner="compatibility",
        rationale=(
            "Legacy mirror writers removed; table may retain historical rows. "
            "Canonical identity is static_analysis_runs."
        ),
        current_writers=(),
        current_readers=(
            "Database/db_utils/static_reconcile",
            "Database/db_utils/menu_actions.backfill_app_version_target_sdks",
            "Database/db_utils/menus/query_runner",
            "Database/db_utils/health_checks/analysis_integrity",
            "Database/db_utils/health_checks/queries.fetch_latest_run",
            "Database/db_scripts/static_run_audit",
            "StaticAnalysis/cli/execution/db_verification",
            "StaticAnalysis/cli/execution/permission_flow",
            "StaticAnalysis/modules/permissions/audit",
            "StaticAnalysis/cli/flows/run_persistence_queries",
            "scripts/db/audit_static_session.py",
            "scripts/db/session_static_health.py",
            "+ see legacy_static_reader_dependency_map.md §3.1",
        ),
    ),
    BridgeTablePosture(
        table="findings",
        posture="compat_mirror_review",
        owner="compatibility",
        rationale=(
            "Legacy findings mirror is no longer written; canonical store is "
            "static_analysis_findings. Table may hold historical rows."
        ),
        current_writers=(),
        current_readers=(
            "Database/db_utils/static_reconcile",
            "Database/db_utils/menus/query_runner",
            "Database/db_scripts/static_run_audit",
            "StaticAnalysis/cli/execution/db_verification",
            "StaticAnalysis/cli/flows/run_persistence_queries",
            "StaticAnalysis/cli/persistence/reports/masvs_summary_report (fallback)",
            "scripts/db/audit_static_session.py",
            "scripts/db/session_static_health.py",
            "+ see legacy_static_reader_dependency_map.md §3.2",
        ),
    ),
    BridgeTablePosture(
        table="metrics",
        posture="compat_mirror_review",
        owner="compatibility",
        rationale=(
            "Legacy metrics mirror is no longer written by static analysis. "
            "Warning: column metrics.run_id is ambiguous in this codebase — some "
            "queries treat it as static_analysis_runs.id (e.g. risk backfill) and "
            "others as legacy runs.run_id; do not migrate readers mechanically."
        ),
        current_writers=(),
        current_readers=(
            "Database/db_utils/static_reconcile",
            "Database/db_utils/action_groups/risk_actions (join key = sar.id on some paths)",
            "Database/tools/db_schema_snapshot",
            "StaticAnalysis/cli/execution/db_verification",
            "StaticAnalysis/cli/persistence/dep_view",
            "StaticAnalysis/cli/flows/run_persistence_queries",
            "scripts/db/audit_static_session.py",
            "+ see legacy_static_reader_dependency_map.md §3.3 and §6",
        ),
    ),
    BridgeTablePosture(
        table="buckets",
        posture="compat_mirror_review",
        owner="compatibility",
        rationale=(
            "Risk bucket rollups remain bridge-era artifacts and should stay "
            "secondary to canonical scoring/read models."
        ),
        current_writers=(),
        current_readers=(
            "Database/db_utils/static_reconcile",
            "Database/db_queries/views_bridge (v_run_overview DDL)",
            "Database/tools/db_schema_snapshot",
            "StaticAnalysis/cli/execution/db_verification",
            "StaticAnalysis/cli/flows/run_persistence_queries",
            "scripts/db/audit_static_session.py",
            "+ see legacy_static_reader_dependency_map.md §3.4",
        ),
    ),
    BridgeTablePosture(
        table="contributors",
        posture="compat_mirror_review",
        owner="compatibility",
        rationale=(
            "Contributor rows remain useful for transitional diagnostics but "
            "are not a primary canonical contract."
        ),
        current_writers=(),
        current_readers=(
            "Database/db_utils/static_reconcile",
            "Database/db_utils/menus/health_checks_permission.render_scoring_checks",
            "StaticAnalysis/cli/flows/run_persistence_queries",
            "+ see legacy_static_reader_dependency_map.md §3.5",
        ),
    ),
    BridgeTablePosture(
        table="risk_scores",
        posture="derived_review",
        owner="derived",
        rationale=(
            "Risk scores are still used operationally, but they are derived from "
            "canonical/permission surfaces and should not define primary truth."
        ),
        current_writers=(
            "Database/db_utils/action_groups/risk_actions",
            "StaticAnalysis/cli/persistence/permission_risk",
        ),
        current_readers=(
            "Database/db_utils/static_reconcile",
            "Database/db_utils/menus/query_runner",
            "Database/db_utils/health_checks/analysis_integrity",
            "Database/tools/risk_score_audit",
        ),
    ),
    BridgeTablePosture(
        table="correlations",
        posture="freeze_candidate",
        owner="compatibility",
        rationale=(
            "Legacy bridge table is now inactive; canonical correlation results "
            "persist to static_correlation_results instead."
        ),
        current_writers=(),
        current_readers=(),
    ),
)


def list_bridge_postures() -> tuple[BridgeTablePosture, ...]:
    return _BRIDGE_POSTURES


def bridge_posture_map() -> dict[str, BridgeTablePosture]:
    return {row.table: row for row in _BRIDGE_POSTURES}


def bridge_posture_summary() -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in _BRIDGE_POSTURES:
        counts[row.posture] = counts.get(row.posture, 0) + 1
    return counts


__all__ = [
    "BridgeTablePosture",
    "bridge_posture_map",
    "bridge_posture_summary",
    "list_bridge_postures",
]
