"""Read helpers for the static/dynamic cross-analysis reporting view."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.summary_surfaces import preferred_static_dynamic_summary_relation


def _as_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        if isinstance(value, Decimal):
            return int(value)
        return int(value)
    except Exception:
        return None


def _as_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        if isinstance(value, Decimal):
            return float(value)
        return float(value)
    except Exception:
        return None


def fetch_cross_analysis_summary_rows(
    *,
    profile_key: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Return rows from the transitional static/dynamic summary view."""
    source_relation = preferred_static_dynamic_summary_relation(runner=core_q.run_sql)

    clauses: list[str] = []
    params: list[Any] = []
    if profile_key:
        clauses.append("profile_key = %s")
        params.append(profile_key)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    limit_sql = ""
    if limit is not None:
        limit_sql = "LIMIT %s"
        params.append(int(limit))

    rows = core_q.run_sql(
        f"""
        SELECT
          package_name,
          app_label,
          category,
          profile_key,
          profile_label,
          latest_static_run_id,
          latest_dynamic_run_id,
          latest_feature_dynamic_run_id,
          static_source_state,
          permission_audit_grade,
          latest_dynamic_grade,
          dynamic_run_profile,
          dynamic_interaction_level,
          dynamic_feature_state,
          dynamic_feature_recency_state,
          regime_final_label,
          summary_state,
          dynamic_bytes_per_sec,
          dynamic_packets_per_sec
        FROM {source_relation}
        {where_sql}
        ORDER BY app_label
        {limit_sql}
        """,
        tuple(params),
        fetch="all_dict",
        query_name="reporting.fetch_cross_analysis_summary_rows",
    ) or []

    normalized: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["latest_static_run_id"] = _as_int(row.get("latest_static_run_id"))
        item["latest_dynamic_run_id"] = str(row.get("latest_dynamic_run_id") or "") or None
        item["latest_feature_dynamic_run_id"] = str(row.get("latest_feature_dynamic_run_id") or "") or None
        item["dynamic_bytes_per_sec"] = _as_float(row.get("dynamic_bytes_per_sec"))
        item["dynamic_packets_per_sec"] = _as_float(row.get("dynamic_packets_per_sec"))
        normalized.append(item)
    return normalized


def current_cross_analysis_summary_source() -> str:
    """Return the current DB relation name used for cross-analysis summary reads."""

    return preferred_static_dynamic_summary_relation(runner=core_q.run_sql)
