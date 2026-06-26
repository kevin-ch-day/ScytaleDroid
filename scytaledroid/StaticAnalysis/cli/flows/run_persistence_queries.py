"""Database query helpers for static persistence audit summaries.

Session identifiers (read carefully):

- **Canonical SAR** rows on ``static_analysis_runs`` are filtered by ``session_label`` in this module
  (see ``_canonical_direct_counts``, ``_static_run_status_counts``, ``reconcile_static_session``).
- **Compatibility / session surfaces** use ``session_stamp`` with the same string in typical CLI flows:
  legacy ``runs`` and the still-active permission-posture ``risk_scores`` table, plus
  ``static_findings_summary``, ``static_string_summary``, ``static_session_run_links``, and
  ``static_session_rollups``. When label and stamp diverge, only the canonical SAR path is guaranteed
  correct here.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils.static_reconcile import reconcile_static_session

type AuditSummary = dict[str, object]
type Row = Sequence[object]


def _summary_section(summary: AuditSummary, key: str) -> AuditSummary:
    """Return a mutable dict section from the audit summary."""
    section = summary.get(key)
    if isinstance(section, Mapping):
        return dict(section)
    return {}


def _rows(sql: str, params: tuple[object, ...]) -> list[Row]:
    """Return sequence-like rows for a SELECT query."""
    raw_rows = core_q.run_sql(sql, params, fetch="all") or []

    rows: list[Row] = []
    for row in raw_rows:
        if isinstance(row, Sequence) and not isinstance(row, str):
            rows.append(row)

    return rows


def _cell(row: Row, index: int, default: object = None) -> object:
    """Safely return a row cell by index."""
    try:
        return row[index]
    except IndexError:
        return default


def _int_value(value: object, default: int = 0) -> int:
    """Convert a database value to int without raising."""
    try:
        return int(value or default)
    except Exception:
        return default


def _scalar_count(sql: str, params: tuple[object, ...]) -> int:
    """Return an integer count from a scalar SQL query."""
    rows = _rows(sql, params)
    if not rows:
        return 0
    return _int_value(_cell(rows[0], 0, 0))


def _row_count(sql: str, params: tuple[object, ...]) -> int:
    """Return row count for a SELECT query."""
    return len(_rows(sql, params))


def _preview(values: set[str], *, limit: int = 10) -> list[str]:
    """Return a bounded sorted preview for audit output."""
    return sorted(values)[:limit]


def _static_run_status_counts(session_label: str) -> dict[str, int]:
    """Return static run status counts for ``static_analysis_runs.session_label``."""
    status_rows = _rows(
        """
        SELECT status, COUNT(*)
        FROM static_analysis_runs
        WHERE session_label=%s
        GROUP BY status
        """,
        (session_label,),
    )

    status_counts: dict[str, int] = {}

    for row in status_rows:
        token = str(_cell(row, 0, "") or "").strip().upper()
        if not token:
            continue
        status_counts[token] = _int_value(_cell(row, 1, 0))

    return status_counts


def _apply_reconcile_summary(summary: AuditSummary, session_label: str) -> None:
    """Overlay canonical reconciliation results onto an audit summary."""
    try:
        reconcile = reconcile_static_session(session_label)
    except Exception as exc:
        summary["reconciliation_error"] = str(exc)
        return

    status_counts: dict[str, int] = {}
    if reconcile.completed_runs:
        status_counts["COMPLETED"] = reconcile.completed_runs
    if reconcile.started_runs:
        status_counts["STARTED"] = reconcile.started_runs
    if reconcile.failed_runs:
        status_counts["FAILED"] = reconcile.failed_runs

    summary["canonical"] = {
        "run_statuses": status_counts,
        "baseline_runs": reconcile.completed_runs,
        "handoff_paths": reconcile.handoff_paths,
        "findings": reconcile.canonical_findings,
        "permission_matrix": reconcile.canonical_permission_matrix,
        "permission_risk": reconcile.canonical_permission_risk,
        "findings_summary_packages": reconcile.findings_summary_packages,
        "string_summary_packages": reconcile.string_summary_packages,
    }

    summary["bridge"] = {
        "runs": reconcile.legacy_runs_packages,
        "risk_scores": reconcile.legacy_risk_packages,
        "secondary_compat_mirror_packages": reconcile.secondary_compat_mirror_packages,
        "metrics_packages": reconcile.legacy_metrics_mirror_packages,
        "buckets_packages": reconcile.legacy_buckets_mirror_packages,
        "contributors_packages": reconcile.legacy_contributors_mirror_packages,
        "session_links": reconcile.session_run_links,
        "session_rollups": reconcile.session_rollups,
    }

    summary["reconciliation"] = {
        "missing_findings_summary_packages": _preview(reconcile.missing_findings_summary),
        "missing_findings_summary_count": len(reconcile.missing_findings_summary),
        "missing_string_summary_packages": _preview(reconcile.missing_string_summary),
        "missing_string_summary_count": len(reconcile.missing_string_summary),
        "missing_legacy_runs_packages": _preview(reconcile.missing_legacy_runs),
        "missing_legacy_runs_count": len(reconcile.missing_legacy_runs),
        "missing_legacy_risk_packages": _preview(reconcile.missing_risk_scores),
        "missing_legacy_risk_count": len(reconcile.missing_risk_scores),
        "missing_secondary_compat_mirror_count": reconcile.missing_secondary_compat_mirror_count,
        "bridge_only_runs_packages": _preview(reconcile.bridge_only_runs),
        "bridge_only_runs_count": len(reconcile.bridge_only_runs),
        "bridge_only_risk_packages": _preview(reconcile.bridge_only_risk_scores),
        "bridge_only_risk_count": len(reconcile.bridge_only_risk_scores),
    }


def _canonical_direct_counts(session_label: str) -> AuditSummary:
    """Return direct-table canonical audit counts.

    ``static_analysis_runs`` is keyed here by ``session_label``; session-scoped summary tables
    such as ``static_findings_summary`` / ``static_string_summary`` are keyed by ``session_stamp``
    and reuse the same token in current CLI flows.
    """
    return {
        "run_statuses": _static_run_status_counts(session_label),
        "baseline_runs": _scalar_count(
            """
            SELECT COUNT(*)
            FROM static_analysis_runs
            WHERE session_label=%s AND is_canonical=1
            """,
            (session_label,),
        ),
        "handoff_paths": _scalar_count(
            """
            SELECT COUNT(*)
            FROM static_analysis_runs
            WHERE session_label=%s
              AND static_handoff_json_path IS NOT NULL
            """,
            (session_label,),
        ),
        "findings": _scalar_count(
            """
            SELECT COUNT(*)
            FROM static_analysis_findings f
            INNER JOIN static_analysis_runs sar ON sar.id = f.run_id
            WHERE sar.session_label=%s
            """,
            (session_label,),
        ),
        "permission_matrix": _scalar_count(
            """
            SELECT COUNT(*)
            FROM static_permission_matrix spm
            INNER JOIN static_analysis_runs sar ON sar.id = spm.run_id
            WHERE sar.session_label=%s
            """,
            (session_label,),
        ),
        "permission_risk": _scalar_count(
            """
            SELECT COUNT(*)
            FROM static_permission_risk_vnext pr
            INNER JOIN static_analysis_runs sar ON sar.id = pr.run_id
            WHERE sar.session_label=%s
            """,
            (session_label,),
        ),
        "findings_summary_packages": _row_count(
            """
            SELECT package_name
            FROM static_findings_summary
            WHERE session_stamp=%s
            """,
            (session_label,),
        ),
        "string_summary_packages": _row_count(
            """
            SELECT package_name
            FROM static_string_summary
            WHERE session_stamp=%s
            """,
            (session_label,),
        ),
    }


def _secondary_compat_package_rows(runs_session_stamp: str) -> tuple[list[Row], list[Row], list[Row], list[Row]]:
    """Return package rows mirrored into secondary compatibility tables (``runs.session_stamp``)."""
    findings_rows = _rows(
        """
        SELECT DISTINCT lr.package
        FROM findings f
        JOIN runs lr ON lr.run_id = f.run_id
        WHERE lr.session_stamp=%s
        """,
        (runs_session_stamp,),
    )
    metrics_rows = _rows(
        """
        SELECT DISTINCT lr.package
        FROM metrics m
        JOIN runs lr ON lr.run_id = m.run_id
        WHERE lr.session_stamp=%s
        """,
        (runs_session_stamp,),
    )
    buckets_rows = _rows(
        """
        SELECT DISTINCT lr.package
        FROM buckets b
        JOIN runs lr ON lr.run_id = b.run_id
        WHERE lr.session_stamp=%s
        """,
        (runs_session_stamp,),
    )
    contributors_rows = _rows(
        """
        SELECT DISTINCT lr.package
        FROM contributors c
        JOIN runs lr ON lr.run_id = c.run_id
        WHERE lr.session_stamp=%s
        """,
        (runs_session_stamp,),
    )

    return findings_rows, metrics_rows, buckets_rows, contributors_rows


def _bridge_direct_counts(*, session_label: str, runs_session_stamp: str) -> AuditSummary:
    """Return direct-table bridge/compat audit counts.

    ``session_label`` keys canonical ``static_analysis_runs`` selection elsewhere. ``runs_session_stamp`` keys
    ``static_session_*`` link/rollup rows and legacy
    ``runs`` / compat mirror probes (often the same string as ``session_label`` in CLI flows).
    """
    findings_rows, metrics_rows, buckets_rows, contributors_rows = _secondary_compat_package_rows(
        runs_session_stamp
    )

    return {
        "runs": _row_count(
            """
            SELECT package
            FROM runs
            WHERE session_stamp=%s
            """,
            (runs_session_stamp,),
        ),
        "risk_scores": _row_count(
            """
            SELECT package_name
            FROM risk_scores
            WHERE session_stamp=%s
            """,
            (runs_session_stamp,),
        ),
        "secondary_compat_mirror_packages": max(
            len(findings_rows),
            len(metrics_rows),
            len(buckets_rows),
            len(contributors_rows),
        ),
        "metrics_packages": len(metrics_rows),
        "buckets_packages": len(buckets_rows),
        "contributors_packages": len(contributors_rows),
        "session_links": _scalar_count(
            """
            SELECT COUNT(*)
            FROM static_session_run_links
            WHERE session_stamp=%s
            """,
            (runs_session_stamp,),
        ),
        "session_rollups": _scalar_count(
            """
            SELECT COUNT(*)
            FROM static_session_rollups
            WHERE session_stamp=%s
            """,
            (runs_session_stamp,),
        ),
    }


def _apply_direct_summary_fallback(summary: AuditSummary, session_label: str) -> None:
    """Populate audit summary directly from tables when reconciliation is unavailable.

    ``session_label`` is the canonical static session selector (``static_analysis_runs.session_label``).
    Bridge/session-link counts reuse the same string as ``session_stamp`` on legacy mirrors and
    ``static_session_*`` tables;
    if your deployment separates label from stamp, pass reconciled data instead of relying on this fallback.
    """
    try:
        canonical = _summary_section(summary, "canonical")
        canonical.update(_canonical_direct_counts(session_label))
        summary["canonical"] = canonical

        bridge = _summary_section(summary, "bridge")
        bridge.update(
            _bridge_direct_counts(session_label=session_label, runs_session_stamp=session_label)
        )
        summary["bridge"] = bridge

    except Exception:
        pass


__all__ = [
    "_apply_direct_summary_fallback",
    "_apply_reconcile_summary",
    "_summary_section",
]
