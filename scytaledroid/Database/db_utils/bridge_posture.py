"""Bridge-table posture contract for Phase 5 cleanup.

This module centralizes the current posture for the remaining bridge/compat
tables so DB tools, docs, and later freeze work can share one explicit view.
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
        rationale="Still needed for compatibility linkage and reconciliation, but canonical run identity lives in static_analysis_runs.",
        current_writers=(
            "Persistence/db_writer.create_run",
            "StaticAnalysis/cli/persistence/run_writers",
        ),
        current_readers=(
            "Database/db_utils/static_reconcile",
            "Database/db_utils/menu_actions.backfill_app_version_target_sdks",
            "Database/db_utils/menus/query_runner",
            "Database/db_utils/health_checks/analysis_integrity",
        ),
    ),
    BridgeTablePosture(
        table="findings",
        posture="compat_mirror_review",
        owner="compatibility",
        rationale="Canonical findings live in static_analysis_findings, but normalized compat findings are still written and audited.",
        current_writers=("Persistence/db_writer.write_findings",),
        current_readers=(
            "Database/db_utils/static_reconcile",
            "Database/db_utils/menus/query_runner",
        ),
    ),
    BridgeTablePosture(
        table="metrics",
        posture="compat_mirror_review",
        owner="compatibility",
        rationale="Canonical metrics are still surfaced through compat rows for scoring/backfill and should shrink over time.",
        current_writers=("Persistence/db_writer.write_metrics",),
        current_readers=(
            "Database/db_utils/static_reconcile",
            "Database/db_utils/action_groups/risk_actions",
            "Database/tools/db_schema_snapshot",
        ),
    ),
    BridgeTablePosture(
        table="buckets",
        posture="compat_mirror_review",
        owner="compatibility",
        rationale="Risk bucket rollups remain bridge-era artifacts and should stay secondary to canonical scoring/read models.",
        current_writers=("Persistence/db_writer.write_buckets",),
        current_readers=(
            "Database/db_utils/static_reconcile",
            "Database/db_utils/menus/query_runner",
            "Database/tools/db_schema_snapshot",
        ),
    ),
    BridgeTablePosture(
        table="contributors",
        posture="compat_mirror_review",
        owner="compatibility",
        rationale="Contributor rows remain useful for transitional diagnostics but are not a primary canonical contract.",
        current_writers=("Persistence/db_writer.write_contributors",),
        current_readers=(
            "Database/db_utils/static_reconcile",
            "Database/db_utils/menus/health_checks",
        ),
    ),
    BridgeTablePosture(
        table="risk_scores",
        posture="derived_review",
        owner="derived",
        rationale="Risk scores are still used operationally, but they are derived from canonical/permission surfaces and should not define primary truth.",
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
        rationale="Legacy bridge table is now inactive; canonical correlation results persist to static_correlation_results instead.",
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
