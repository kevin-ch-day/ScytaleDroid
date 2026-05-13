"""SQL + helpers for ``check_evidence_latest_write_posture`` (recent static findings)."""

from __future__ import annotations

from typing import Any

__all__ = [
    "sql_recent_findings_total",
    "sql_recent_hash_missing_payload",
    "sql_recent_inline_violations_when_disabled",
    "sql_recent_unresolved_on_latest_surface",
    "fetch_recent_posture",
]


def sql_recent_findings_total(hours: int) -> str:
    h = max(1, min(int(hours), 24 * 365))
    return f"""
SELECT COUNT(*) AS c
FROM static_analysis_findings
WHERE created_at >= (NOW() - INTERVAL {h} HOUR)
""".strip()


def sql_recent_hash_missing_payload(hours: int) -> str:
    h = max(1, min(int(hours), 24 * 365))
    return f"""
SELECT COUNT(*) AS c
FROM static_analysis_findings f
LEFT JOIN static_finding_evidence_payloads ep
  ON ep.evidence_hash = f.evidence_hash
WHERE f.created_at >= (NOW() - INTERVAL {h} HOUR)
  AND f.evidence_hash IS NOT NULL
  AND TRIM(f.evidence_hash) <> ''
  AND ep.evidence_hash IS NULL
""".strip()


def sql_recent_inline_violations_when_disabled(hours: int) -> str:
    """When inline is disabled, rows with a payload hash should not retain inline JSON."""
    h = max(1, min(int(hours), 24 * 365))
    return f"""
SELECT COUNT(*) AS c
FROM static_analysis_findings f
WHERE f.created_at >= (NOW() - INTERVAL {h} HOUR)
  AND f.evidence_hash IS NOT NULL
  AND TRIM(f.evidence_hash) <> ''
  AND f.evidence IS NOT NULL
""".strip()


def sql_recent_unresolved_on_latest_surface(hours: int) -> str:
    """Findings on ``vw_static_finding_surfaces_latest`` runs with hash but no resolvable evidence."""
    h = max(1, min(int(hours), 24 * 365))
    return f"""
SELECT COUNT(*) AS c
FROM static_analysis_findings f
INNER JOIN vw_static_finding_surfaces_latest l
  ON l.static_run_id = f.run_id
LEFT JOIN static_finding_evidence_payloads ep
  ON ep.evidence_hash = f.evidence_hash
WHERE f.created_at >= (NOW() - INTERVAL {h} HOUR)
  AND f.evidence_hash IS NOT NULL
  AND TRIM(f.evidence_hash) <> ''
  AND COALESCE(f.evidence, JSON_EXTRACT(ep.evidence_json, '$')) IS NULL
""".strip()


def _scalar(core_q: Any, sql: str, *, query_name: str) -> int:
    row = core_q.run_sql(sql, (), fetch="one", dictionary=True, query_name=query_name)
    if not row:
        return 0
    v = row.get("c")
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def fetch_recent_posture(core_q: Any, *, hours: int) -> dict[str, int]:
    return {
        "recent_findings_total": _scalar(
            core_q, sql_recent_findings_total(hours), query_name="evidence_latest_write.total"
        ),
        "recent_hash_missing_payload": _scalar(
            core_q,
            sql_recent_hash_missing_payload(hours),
            query_name="evidence_latest_write.hash_missing_payload",
        ),
        "recent_inline_rows_with_hash": _scalar(
            core_q,
            sql_recent_inline_violations_when_disabled(hours),
            query_name="evidence_latest_write.inline_with_hash",
        ),
        "recent_unresolved_on_latest_surface": _scalar(
            core_q,
            sql_recent_unresolved_on_latest_surface(hours),
            query_name="evidence_latest_write.unresolved_web_shape",
        ),
    }
