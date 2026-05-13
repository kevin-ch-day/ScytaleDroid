"""Read-only ``artifact_registry`` cleanup candidate classification (no DML/DDL).

Maps ``v_artifact_registry_integrity`` rows into operator policy buckets for
``docs/maintenance/artifact_registry_cleanup_track.md``. Numeric ``INTERVAL``
values are clamped before interpolation (no user SQL fragments).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

CATEGORY_ACTIONS: dict[str, str] = {
    "linked_keep": "No action — linked to static_analysis_runs or dynamic_sessions.",
    "dangling_recent_keep": "Cooling-off: do not delete; re-check after migrations complete.",
    "dangling_old_export_first": "Export audit CSV/JSON before any registry delete; paths may still matter.",
    "dangling_db_only_candidate": "Registry-only delete candidate after export (no host_path to preserve).",
    "dangling_file_present_review": "Human review: host_path set; verify evidence value before registry delete.",
    "dynamic_dangling_review": "Correlate with dynamic evidence dirs / session history before delete.",
    "static_nonnumeric_run_id_review": "Legacy or mis-keyed static run_id; investigate before bulk delete.",
    "static_numeric_missing_sar_candidate": "Mid-age SAR gap + blank host_path; export then registry delete candidate.",
    "unknown_link_review": "Unexpected link_state/run_type mix; inspect manually.",
}


def _clamp_interval_days(value: int, *, lo: int = 1, hi: int = 3650) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        v = lo
    return max(lo, min(v, hi))


def classified_from_clause(*, recent_days: int, old_days: int) -> tuple[str, str]:
    """Return (sql_fragment, alias) for ``FROM ( <subquery> ) alias``."""

    rd = _clamp_interval_days(recent_days, hi=365)
    od = _clamp_interval_days(old_days, hi=4000)
    if od <= rd:
        od = rd + 1

    # age_bucket uses same rd/od as integrity report style.
    sql = f"""
    (
      SELECT
        v.artifact_id,
        v.run_id,
        v.run_type,
        v.link_state,
        v.artifact_type,
        v.host_path,
        v.created_at_utc,
        CASE
          WHEN v.created_at_utc IS NULL THEN 'null_created_at'
          WHEN v.created_at_utc >= (NOW() - INTERVAL {rd} DAY) THEN '0-7d'
          WHEN v.created_at_utc < (NOW() - INTERVAL {od} DAY) THEN '90d+'
          ELSE '7-90d'
        END AS age_bucket,
        CASE
          WHEN TRIM(COALESCE(v.host_path, '')) = '' THEN 'blank_host'
          ELSE 'host_path_set'
        END AS host_path_presence,
        CASE
          WHEN v.run_id REGEXP '^[0-9]+$' THEN 'numeric_run_id'
          ELSE 'non_numeric_run_id'
        END AS static_run_id_shape,
        CASE
          WHEN v.link_state = 'linked' THEN 'linked_keep'
          WHEN v.run_type = 'static' AND v.run_id NOT REGEXP '^[0-9]+$' THEN 'static_nonnumeric_run_id_review'
          WHEN v.run_type = 'dynamic' AND v.link_state = 'dangling_dynamic_run' THEN 'dynamic_dangling_review'
          WHEN v.run_type = 'static'
               AND v.run_id REGEXP '^[0-9]+$'
               AND NOT EXISTS (
                 SELECT 1 FROM static_analysis_runs sar
                 WHERE sar.id = CAST(v.run_id AS UNSIGNED)
               ) THEN
            CASE
              WHEN v.created_at_utc IS NULL THEN
                CASE
                  WHEN TRIM(COALESCE(v.host_path, '')) = '' THEN 'dangling_db_only_candidate'
                  ELSE 'dangling_file_present_review'
                END
              WHEN v.created_at_utc >= (NOW() - INTERVAL {rd} DAY) THEN 'dangling_recent_keep'
              WHEN v.created_at_utc < (NOW() - INTERVAL {od} DAY) THEN
                CASE
                  WHEN TRIM(COALESCE(v.host_path, '')) = '' THEN 'dangling_db_only_candidate'
                  ELSE 'dangling_old_export_first'
                END
              WHEN TRIM(COALESCE(v.host_path, '')) = '' THEN 'static_numeric_missing_sar_candidate'
              ELSE 'dangling_file_present_review'
            END
          ELSE 'unknown_link_review'
        END AS cleanup_category
      FROM v_artifact_registry_integrity v
    ) c
    """
    return sql.strip(), "c"


def collect_cleanup_candidate_report(
    run_sql: Callable[..., Any],
    *,
    recent_days: int = 7,
    old_days: int = 90,
    run_type_filter: str | None = None,
    path_sample_limit: int = 0,
) -> dict[str, Any]:
    """Run read-only aggregates; optional ``Path.is_file()`` probes (no deletes)."""

    rd = _clamp_interval_days(recent_days)
    od = _clamp_interval_days(old_days)
    if od <= rd:
        od = rd + 1

    from_clause, _alias = classified_from_clause(recent_days=rd, old_days=od)
    rt_filter = ""
    params_base: list[Any] = []
    if run_type_filter and str(run_type_filter).strip().lower() in {"static", "dynamic"}:
        rt_filter = " WHERE c.run_type = %s "
        params_base.append(str(run_type_filter).strip().lower())

    summary_sql = f"""
        SELECT
          c.cleanup_category,
          c.run_type,
          c.link_state,
          c.artifact_type,
          c.age_bucket,
          c.host_path_presence,
          c.static_run_id_shape,
          COUNT(*) AS row_count,
          MIN(c.created_at_utc) AS created_min,
          MAX(c.created_at_utc) AS created_max
        FROM {from_clause}
        {rt_filter}
        GROUP BY
          c.cleanup_category,
          c.run_type,
          c.link_state,
          c.artifact_type,
          c.age_bucket,
          c.host_path_presence,
          c.static_run_id_shape
        ORDER BY row_count DESC, c.cleanup_category, c.run_type, c.artifact_type
    """

    rows = run_sql(
        summary_sql,
        tuple(params_base),
        fetch="all",
        dictionary=True,
        query_name="artifact_registry_cleanup.summary",
    ) or []

    tops_sql = f"""
        SELECT c.cleanup_category, c.run_id, COUNT(*) AS cnt
        FROM {from_clause}
        {rt_filter}
        GROUP BY c.cleanup_category, c.run_id
        ORDER BY c.cleanup_category, cnt DESC, c.run_id
    """
    top_rows = run_sql(
        tops_sql,
        tuple(params_base),
        fetch="all",
        dictionary=True,
        query_name="artifact_registry_cleanup.tops",
    ) or []

    top_by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in top_rows:
        if not isinstance(row, dict):
            continue
        cat = str(row.get("cleanup_category") or "")
        if len(top_by_category[cat]) < 12:
            top_by_category[cat].append(
                {"run_id": str(row.get("run_id") or ""), "count": int(row.get("cnt") or 0)}
            )

    totals_sql = f"""
        SELECT c.cleanup_category, COUNT(*) AS row_count
        FROM {from_clause}
        {rt_filter}
        GROUP BY c.cleanup_category
        ORDER BY row_count DESC
    """
    totals_raw = run_sql(
        totals_sql,
        tuple(params_base),
        fetch="all",
        dictionary=True,
        query_name="artifact_registry_cleanup.totals",
    ) or []
    totals_by_category = [
        {
            "cleanup_category": str(r.get("cleanup_category") or ""),
            "row_count": int(r.get("row_count") or 0),
            "candidate_action": CATEGORY_ACTIONS.get(str(r.get("cleanup_category") or ""), "—"),
        }
        for r in totals_raw
        if isinstance(r, dict)
    ]

    path_probe: dict[str, Any] | None = None
    lim = max(0, min(int(path_sample_limit), 5000))
    if lim > 0:
        if rt_filter.strip():
            probe_where = f"{rt_filter.strip()} AND "
        else:
            probe_where = "WHERE "
        probe_sql = f"""
            SELECT c.artifact_id, c.cleanup_category, c.run_type, c.host_path
            FROM {from_clause}
            {probe_where}c.cleanup_category IN ('dangling_file_present_review', 'dangling_old_export_first')
              AND TRIM(COALESCE(c.host_path, '')) <> ''
            ORDER BY c.created_at_utc DESC
            LIMIT {lim}
        """
        sample = run_sql(
            probe_sql,
            tuple(params_base),
            fetch="all",
            dictionary=True,
            query_name="artifact_registry_cleanup.path_sample",
        ) or []
        present = missing = errors = 0
        examples: list[dict[str, Any]] = []
        for row in sample:
            if not isinstance(row, dict):
                continue
            aid = row.get("artifact_id")
            cat = str(row.get("cleanup_category") or "")
            rt = str(row.get("run_type") or "")
            hp = str(row.get("host_path") or "").strip()
            if not hp:
                errors += 1
                continue
            try:
                exists = Path(hp).is_file()
            except OSError:
                exists = False
                errors += 1
                continue
            if exists:
                present += 1
            else:
                missing += 1
            if len(examples) < 8:
                examples.append(
                    {
                        "artifact_id": int(aid) if aid is not None else None,
                        "cleanup_category": cat,
                        "run_type": rt,
                        "host_path": hp[:200],
                        "host_path_exists": exists,
                    }
                )
        path_probe = {
            "sampled_rows": len(sample),
            "host_path_exists_true": present,
            "host_path_exists_false": missing,
            "host_path_probe_errors": errors,
            "examples": examples,
        }

    return {
        "recent_days_window": rd,
        "old_days_threshold": od,
        "run_type_filter": run_type_filter,
        "totals_by_category": totals_by_category,
        "summary_dimensions": [dict(r) for r in rows if isinstance(r, dict)],
        "top_run_ids_by_category": {k: v for k, v in top_by_category.items()},
        "path_probe": path_probe,
    }


def format_text_report(data: Mapping[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# artifact_registry cleanup candidates (read-only)")
    lines.append("")
    lines.append(
        f"Parameters: recent_window={data.get('recent_days_window')}d "
        f"(dangling_recent_keep), old_threshold={data.get('old_days_threshold')}d "
        f"(export/db-only split for static numeric missing SAR)."
    )
    if data.get("run_type_filter"):
        lines.append(f"run_type filter: {data.get('run_type_filter')}")
    lines.append("")
    lines.append("## Totals by cleanup_category")
    for row in data.get("totals_by_category") or []:
        cat = str(row.get("cleanup_category") or "")
        lines.append(f"  {cat}\trows={row.get('row_count')}")
        lines.append(f"    action: {row.get('candidate_action')}")
    lines.append("")
    lines.append("## Breakdown (category × run_type × link_state × artifact_type × age × host × run_id shape)")
    for row in data.get("summary_dimensions") or []:
        if not isinstance(row, Mapping):
            continue
        lines.append(
            "\t".join(
                [
                    str(row.get("cleanup_category") or ""),
                    str(row.get("run_type") or ""),
                    str(row.get("link_state") or ""),
                    str(row.get("artifact_type") or ""),
                    str(row.get("age_bucket") or ""),
                    str(row.get("host_path_presence") or ""),
                    str(row.get("static_run_id_shape") or ""),
                    f"rows={int(row.get('row_count') or 0)}",
                    f"min={row.get('created_min')}",
                    f"max={row.get('created_max')}",
                ]
            )
        )
    lines.append("")
    lines.append("## Top run_id values (up to 12 per category)")
    for cat, items in sorted((data.get("top_run_ids_by_category") or {}).items()):
        lines.append(f"  [{cat}]")
        for it in items:
            lines.append(f"    {it.get('run_id')}\t{it.get('count')}")
    lines.append("")
    probe = data.get("path_probe")
    lines.append("## host_path sample (file-backed categories only)")
    if not probe:
        lines.append("  (skipped; use --path-sample N)")
    else:
        lines.append(f"  sampled_rows={probe.get('sampled_rows')}")
        lines.append(f"  exists_true={probe.get('host_path_exists_true')}")
        lines.append(f"  exists_false={probe.get('host_path_exists_false')}")
        lines.append(f"  probe_errors={probe.get('host_path_probe_errors')}")
        for ex in probe.get("examples") or []:
            lines.append(f"    {ex}")
    lines.append("")
    lines.append("Notes:")
    lines.append(
        "  This report is SELECT-only. For **scoped** old-dangling deletes (receipt + --apply), use "
        "scripts/db/prune_artifact_registry_dangling.py; see docs/maintenance/artifact_registry_cleanup_track.md."
    )
    lines.append(
        "  Workspace maintenance → prune artifact_registry remains a blunt instrument: it deletes **all** "
        "non-linked rows after prompts — avoid for catalog-wide debt."
    )
    lines.append(
        "  Longer-term RFC: optional session_stamp on artifact_registry; indexes tuned for cleanup "
        "queries once measured in production."
    )
    return "\n".join(lines) + "\n"


__all__ = [
    "CATEGORY_ACTIONS",
    "collect_cleanup_candidate_report",
    "format_text_report",
]
