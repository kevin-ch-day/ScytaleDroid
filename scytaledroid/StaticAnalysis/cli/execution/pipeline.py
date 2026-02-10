"""Policy helpers for static analysis result orchestration."""

from __future__ import annotations

from scytaledroid.Database.db_core import db_queries as core_q

REQUIRED_PAPER_ARTIFACTS: tuple[str, ...] = (
    "static_baseline_json",
    "static_dynamic_plan_json",
    "static_report",
    "manifest_evidence",
    "dep_snapshot",
    "permission_audit_snapshot",
)


def governance_ready() -> tuple[bool, str | None]:
    try:
        snapshots = core_q.run_sql(
            "SELECT COUNT(*) FROM permission_governance_snapshots",
            fetch="one",
        )
        rows = core_q.run_sql(
            "SELECT COUNT(*) FROM permission_governance_snapshot_rows",
            fetch="one",
        )
    except Exception as exc:
        return False, f"governance_query_failed:{exc}"
    snapshot_count = int(snapshots[0] or 0) if snapshots else 0
    row_count = int(rows[0] or 0) if rows else 0
    if snapshot_count <= 0 or row_count <= 0:
        return False, "governance_missing"
    return True, None


__all__ = ["REQUIRED_PAPER_ARTIFACTS", "governance_ready"]
