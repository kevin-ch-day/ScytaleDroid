"""Read-only helpers for the legacy static mirror five (diagnostics only).

Canonical static truth is ``static_analysis_*``. The legacy mirror family
(``runs``, legacy ``findings``, ``metrics``, ``buckets``, ``contributors``) is
optional compatibility / reconcile / historical data — see
``docs/maintenance/legacy_static_reader_dependency_map.md``.

Do **not** use these helpers for canonical persistence or gates.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeAlias

from scytaledroid.Database.db_utils import diagnostics

# Tables audited together in ``scripts/db/audit_static_session.py`` legacy block.
LEGACY_MIRROR_TABLES_AUDIT: tuple[str, ...] = ("runs", "metrics", "buckets", "findings")

# Legacy mirror five for DB schema snapshot ``legacy_mirror_table_presence`` (includes ``contributors``).
LEGACY_MIRROR_TABLES_SNAPSHOT: tuple[str, ...] = ("runs", "findings", "metrics", "buckets", "contributors")

# Subset used by session health / legacy findings counts (``runs`` + legacy ``findings`` only).
LEGACY_MIRROR_RUNS_FINDINGS: tuple[str, ...] = ("runs", "findings")

RunSql: TypeAlias = Callable[..., Any]


def legacy_mirror_table_presence_audit() -> dict[str, bool]:
    """Return ``table_name → exists`` for the legacy mirror set used by session audit scripts."""

    return diagnostics.check_required_tables(list(LEGACY_MIRROR_TABLES_AUDIT))


def legacy_mirror_runs_findings_presence() -> dict[str, bool]:
    """Presence for ``runs`` + legacy ``findings`` (session health script pattern)."""

    return diagnostics.check_required_tables(list(LEGACY_MIRROR_RUNS_FINDINGS))


def _scalar_count(
    run_sql: RunSql,
    sql: str,
    params: tuple[object, ...],
) -> tuple[int | None, str]:
    try:
        row = run_sql(sql, params, fetch="one")
        if row is None:
            return 0, "OK"
        val = row[0] if not isinstance(row, dict) else next(iter(row.values()))
        return int(val or 0), "OK"
    except Exception as exc:  # pragma: no cover - live DB
        return None, f"ERROR: {exc}"


def legacy_runs_count_by_session_stamp(
    run_sql: RunSql,
    session_stamp: str,
) -> tuple[int | None, str]:
    """Count legacy ``runs`` rows for a ``session_stamp`` (mirror session discriminator)."""

    return _scalar_count(
        run_sql,
        "SELECT COUNT(*) FROM runs WHERE session_stamp=%s",
        (session_stamp,),
    )


def legacy_findings_count_via_runs_session_stamp(
    run_sql: RunSql,
    session_stamp: str,
) -> tuple[int | None, str]:
    """Count legacy ``findings`` rows keyed through ``runs.session_stamp``."""

    return _scalar_count(
        run_sql,
        """
        SELECT COUNT(*) FROM findings f
        INNER JOIN runs lr ON lr.run_id = f.run_id
        WHERE lr.session_stamp=%s
        """,
        (session_stamp,),
    )


def legacy_findings_count_via_static_run_id(
    run_sql: RunSql,
    session_stamp: str,
) -> tuple[int | None, str]:
    """Count legacy ``findings`` rows where ``findings.static_run_id`` links to SAR ``session_stamp``."""

    return _scalar_count(
        run_sql,
        """
        SELECT COUNT(*) FROM findings f
        WHERE f.static_run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp=%s)
        """,
        (session_stamp,),
    )


__all__ = [
    "LEGACY_MIRROR_TABLES_AUDIT",
    "LEGACY_MIRROR_TABLES_SNAPSHOT",
    "LEGACY_MIRROR_RUNS_FINDINGS",
    "legacy_runs_count_by_session_stamp",
    "legacy_findings_count_via_runs_session_stamp",
    "legacy_findings_count_via_static_run_id",
    "legacy_mirror_runs_findings_presence",
    "legacy_mirror_table_presence_audit",
]
