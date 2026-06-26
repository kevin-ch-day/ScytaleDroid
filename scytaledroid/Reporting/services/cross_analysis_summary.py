"""Read helpers for the static/dynamic cross-analysis reporting view."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_func.research_cohorts import (
    ALPHA_COHORT_KEY,
    resolve_research_cohort_context,
    resolve_research_cohort_packages,
)
from scytaledroid.Database.summary_surfaces import (
    preferred_static_dynamic_summary_relation,
    static_dynamic_summary_relation_has_required_runtime_columns,
)


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
    cohort_key: str | None = ALPHA_COHORT_KEY,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Return rows from the transitional static/dynamic summary view."""
    if not profile_key and not cohort_key:
        cohort_ctx = resolve_research_cohort_context()
        profile_key = str(cohort_ctx.get("profile_key") or "") or None
        cohort_key = str(cohort_ctx.get("cohort_key") or "") or None
    source_relation = preferred_static_dynamic_summary_relation(runner=core_q.run_sql)
    has_runtime_columns = static_dynamic_summary_relation_has_required_runtime_columns(
        source_relation,
        runner=core_q.run_sql,
    )

    clauses: list[str] = []
    params: list[Any] = []
    packages = resolve_research_cohort_packages(cohort_key, fallback_profile_key=profile_key)
    if packages:
        placeholders = ", ".join(["%s"] * len(packages))
        clauses.append(f"LOWER(summary.package_name) COLLATE utf8mb4_general_ci IN ({placeholders})")
        params.extend(packages)
    elif profile_key:
        clauses.append("summary.profile_key = %s")
        params.append(profile_key)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    limit_sql = ""
    if limit is not None:
        limit_sql = "LIMIT %s"
        params.append(int(limit))

    runtime_select = """
          summary.dynamic_technical_validity_state,
          summary.dynamic_quota_state,
          summary.dynamic_cohort_eligibility_state"""
    runtime_join = ""
    if not has_runtime_columns:
        runtime_select = """
          ctx.technical_validity_state AS dynamic_technical_validity_state,
          ctx.quota_state AS dynamic_quota_state,
          ctx.cohort_eligibility_state AS dynamic_cohort_eligibility_state"""
        runtime_join = """
        LEFT JOIN v_dynamic_run_context_v1 ctx
          ON ctx.dynamic_run_id = summary.latest_dynamic_run_id"""

    rows = core_q.run_sql(
        f"""
        SELECT
          summary.package_name,
          summary.app_label,
          summary.category,
          summary.profile_key,
          summary.profile_label,
          summary.latest_static_run_id,
          summary.latest_dynamic_run_id,
          summary.latest_feature_dynamic_run_id,
          summary.static_source_state,
          summary.permission_audit_grade,
          summary.latest_dynamic_grade,
          summary.dynamic_run_profile,
          summary.dynamic_interaction_level,
          summary.dynamic_feature_state,
          summary.dynamic_feature_recency_state,
          summary.regime_final_label,
          summary.summary_state,
          summary.dynamic_bytes_per_sec,
          summary.dynamic_packets_per_sec,
{runtime_select}
        FROM {source_relation} summary
{runtime_join}
        {where_sql}
        ORDER BY summary.app_label
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
        item["dynamic_technical_validity_state"] = str(row.get("dynamic_technical_validity_state") or "") or None
        item["dynamic_quota_state"] = str(row.get("dynamic_quota_state") or "") or None
        item["dynamic_cohort_eligibility_state"] = str(row.get("dynamic_cohort_eligibility_state") or "") or None
        normalized.append(item)
    return normalized


def current_cross_analysis_summary_source() -> str:
    """Return the current DB relation name used for cross-analysis summary reads."""

    return preferred_static_dynamic_summary_relation(runner=core_q.run_sql)
