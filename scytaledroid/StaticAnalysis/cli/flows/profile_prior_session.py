"""Latest persisted static session snapshot for a profile cohort (optional DB).

Supports the profile workload screen: evidence readiness versus the current harvested
cohort without duplicating cohort-scale audit prose (see scripts/db/audit_static_session.py).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PriorProfileSessionSnapshot:
    """Counts for ``session_stamp`` + ``scope_label`` (research profile name)."""

    session_stamp: str
    static_runs: int
    findings_count: int
    permissions_count: int
    handoff_rows: int
    dynamic_ready: tuple[int, int]


def _norm_pkg(value: Any) -> str:
    return str(value or "").strip().lower()


def _scalar_count(row: Any) -> int:
    if row is None:
        return 0
    if isinstance(row, dict):
        v = next(iter(row.values()))
        return int(v)
    return int(row[0])


def fetch_prior_profile_session_snapshot(
    scope_label: str,
    expected_packages_lower: frozenset[str],
) -> PriorProfileSessionSnapshot | None:
    """Return aggregate DB evidence for the latest ``session_stamp`` under ``scope_label``.

    ``scope_label`` must match persisted profile cohort names (interactive profile runs).

    Offline / schema mismatch / query errors → ``None`` (caller prints nothing).
    """

    cohort = str(scope_label or "").strip()
    if not cohort or not expected_packages_lower:
        return None

    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils import schema_gate
    except Exception:
        return None

    ok, _, _ = schema_gate.static_schema_gate()
    if not ok:
        return None

    run_sql = core_q.run_sql

    try:
        row = run_sql(
            """
            SELECT session_stamp FROM static_analysis_runs
            WHERE scope_label=%s
            GROUP BY session_stamp
            ORDER BY MAX(id) DESC
            LIMIT 1
            """,
            (cohort,),
            fetch="one",
        )
    except Exception:
        return None

    if not row:
        return None

    if isinstance(row, dict):
        stamp = _norm_pkg(row.get("session_stamp"))
    else:
        stamp = _norm_pkg(row[0])
    if not stamp:
        return None

    try:
        n_runs = _scalar_count(
            run_sql(
                "SELECT COUNT(*) FROM static_analysis_runs WHERE session_stamp=%s AND scope_label=%s",
                (stamp, cohort),
                fetch="one",
            )
        )
        n_find = _scalar_count(
            run_sql(
                """
                SELECT COUNT(*) FROM static_analysis_findings f
                INNER JOIN static_analysis_runs r ON r.id = f.run_id
                WHERE r.session_stamp=%s AND r.scope_label=%s
                """,
                (stamp, cohort),
                fetch="one",
            )
        )
        n_perm = _scalar_count(
            run_sql(
                """
                SELECT COUNT(*) FROM static_permission_matrix m
                WHERE m.run_id IN (
                  SELECT id FROM static_analysis_runs WHERE session_stamp=%s AND scope_label=%s
                )
                """,
                (stamp, cohort),
                fetch="one",
            )
        )
        n_hand = _scalar_count(
            run_sql(
                """
                SELECT COUNT(*) FROM v_static_handoff_v1 h
                INNER JOIN static_analysis_runs r ON r.id = h.static_run_id
                WHERE r.session_stamp=%s AND r.scope_label=%s
                """,
                (stamp, cohort),
                fetch="one",
            )
        )

        pkg_rows = run_sql(
            """
            SELECT DISTINCT h.package_name_lc AS p FROM v_static_handoff_v1 h
            INNER JOIN static_analysis_runs r ON r.id = h.static_run_id
            WHERE r.session_stamp=%s AND r.scope_label=%s
            """,
            (stamp, cohort),
            fetch="all",
        )
    except Exception:
        return None

    hop: set[str] = set()
    if pkg_rows:
        for prow in pkg_rows:
            if isinstance(prow, dict):
                pv = prow.get("p")
                if pv is None:
                    pv = next(iter(prow.values())) if prow else None
                key = _norm_pkg(pv)
            else:
                key = _norm_pkg(prow[0] if prow else "")
            if key:
                hop.add(key)

    ready_ct = sum(1 for pkg in expected_packages_lower if pkg in hop)
    total_ct = len(expected_packages_lower)

    return PriorProfileSessionSnapshot(
        session_stamp=stamp,
        static_runs=n_runs,
        findings_count=n_find,
        permissions_count=n_perm,
        handoff_rows=n_hand,
        dynamic_ready=(ready_ct, total_ct),
    )


def format_audit_session_command(session_stamp: str) -> str:
    """Copy/paste ``PYTHONPATH=.`` audit command (repo root). ``session_stamp`` is shell-unsafe if it contains quotes."""

    stamp = str(session_stamp or "").strip()
    if not stamp:
        return "PYTHONPATH=. python scripts/db/audit_static_session.py --session <session_stamp>"
    return f"PYTHONPATH=. python scripts/db/audit_static_session.py --session {stamp}"


__all__ = [
    "PriorProfileSessionSnapshot",
    "fetch_prior_profile_session_snapshot",
    "format_audit_session_command",
]
