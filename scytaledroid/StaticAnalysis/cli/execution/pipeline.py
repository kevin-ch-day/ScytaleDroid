"""Policy helpers for static analysis result orchestration."""

from __future__ import annotations

from scytaledroid.Database.db_core import permission_intel as intel_db

REQUIRED_PAPER_ARTIFACTS: tuple[str, ...] = (
    "static_baseline_json",
    "static_dynamic_plan_json",
    "static_report",
    "manifest_evidence",
    "dep_snapshot",
)


def governance_ready() -> tuple[bool, str | None]:
    try:
        snapshot_count = intel_db.governance_snapshot_count()
        row_count = intel_db.governance_row_count()
    except Exception as exc:
        return False, f"governance_query_failed:{exc}"
    if snapshot_count <= 0 or row_count <= 0:
        return False, "governance_missing"
    return True, None


__all__ = ["REQUIRED_PAPER_ARTIFACTS", "governance_ready"]
