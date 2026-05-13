"""Static run ledger governance counts (canonical / handoff invariants).

Shared by ``scripts/db/check_static_run_governance_posture.py``, Database Tools
menus, and the DB health summary."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

GOVERNANCE_POSTURE_CHECKS: tuple[tuple[str, str], ...] = (
    (
        "failed_canonical_runs",
        """
        SELECT COUNT(*) AS c
        FROM static_analysis_runs
        WHERE UPPER(COALESCE(status, '')) <> 'COMPLETED'
          AND COALESCE(is_canonical, 0) = 1
        """,
    ),
    (
        "failed_missing_run_class",
        """
        SELECT COUNT(*) AS c
        FROM static_analysis_runs
        WHERE UPPER(COALESCE(status, '')) <> 'COMPLETED'
          AND run_class IS NULL
        """,
    ),
    (
        "completed_session_invariant_violations",
        """
        SELECT COUNT(*) AS c
        FROM (
          SELECT sar.session_stamp
          FROM static_analysis_runs sar
          LEFT JOIN v_static_handoff_v1 vh ON vh.static_run_id = sar.id
          WHERE UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
          GROUP BY sar.session_stamp
          HAVING
              COUNT(*) <> COUNT(vh.static_run_id)
              OR COUNT(*) <> SUM(UPPER(TRIM(COALESCE(sar.run_class, ''))) = 'CANONICAL')
              OR COUNT(*) <> SUM(COALESCE(sar.identity_valid, 0) = 1)
        ) x
        """,
    ),
)


@dataclass(frozen=True)
class StaticRunGovernanceCounts:
    failed_canonical_runs: int
    failed_missing_run_class: int
    completed_session_invariant_violations: int

    def non_zero_check_count(self) -> int:
        n = 0
        if self.failed_canonical_runs != 0:
            n += 1
        if self.failed_missing_run_class != 0:
            n += 1
        if self.completed_session_invariant_violations != 0:
            n += 1
        return n


def _row_count_c(row: Any) -> int:
    if isinstance(row, dict):
        return int(row.get("c") or 0)
    if row and row[0] is not None:
        return int(row[0])
    return 0


def fetch_static_run_governance_counts(
    run_sql_fn: Callable[..., Any] | None = None,
) -> StaticRunGovernanceCounts:
    """Run the three invariant queries; raise on DB errors."""

    if run_sql_fn is None:
        from scytaledroid.Database.db_core import run_sql as run_sql_fn  # noqa: PLC0415

    failed_canonical = 0
    failed_run_class = 0
    completed_violations = 0
    for label, sql in GOVERNANCE_POSTURE_CHECKS:
        row = run_sql_fn(
            sql.strip(),
            (),
            fetch="one",
            dictionary=True,
            query_name=f"governance_posture.{label}",
        )
        val = _row_count_c(row)
        if label == "failed_canonical_runs":
            failed_canonical = val
        elif label == "failed_missing_run_class":
            failed_run_class = val
        elif label == "completed_session_invariant_violations":
            completed_violations = val
    return StaticRunGovernanceCounts(
        failed_canonical_runs=failed_canonical,
        failed_missing_run_class=failed_run_class,
        completed_session_invariant_violations=completed_violations,
    )


__all__ = [
    "GOVERNANCE_POSTURE_CHECKS",
    "StaticRunGovernanceCounts",
    "fetch_static_run_governance_counts",
]
