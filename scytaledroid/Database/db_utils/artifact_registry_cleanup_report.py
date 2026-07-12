"""Read-only ``artifact_registry`` cleanup candidate classification (no DML/DDL).

Maps ``v_artifact_registry_integrity`` rows into operator policy buckets for
``docs/maintenance/artifact_registry_cleanup_track.md``. Numeric ``INTERVAL``
values are clamped before interpolation (no user SQL fragments).
"""

from __future__ import annotations

from collections import Counter, defaultdict
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
    "static_truly_detached_candidate": "Static registry-only delete candidate; use prune_artifact_registry_static_detached.py (receipt + --apply).",
    "static_file_present_detached_review": "Static host file still exists without canonical linkage; review evidence value before registry delete.",
    "static_legacy_overlap_missing_file": "Static host file is missing but legacy runs overlap remains; retire legacy session debt first.",
    "static_legacy_overlap_file_present_review": "Static legacy-overlap row still has a present host file; blocked pending legacy session + file review.",
    "static_canonical_residue_review": "Static row still overlaps canonical tables; investigate residue before any registry delete.",
    "static_malformed_run_id_review": "Static row has malformed/non-numeric run identity; inspect manually before cleanup.",
    "static_unknown_review": "Static dangling row did not match a known reason bucket; inspect manually.",
    "unknown_link_review": "Unexpected link_state/run_type mix; inspect manually.",
}

SAFE_PRUNE_CATEGORIES: frozenset[str] = frozenset(
    {
        "dangling_db_only_candidate",
        "static_numeric_missing_sar_candidate",
        "static_truly_detached_candidate",
    }
)
REVIEW_BLOCKED_CATEGORIES: frozenset[str] = frozenset(
    {
        "dangling_recent_keep",
        "dangling_old_export_first",
        "dangling_file_present_review",
        "dynamic_dangling_review",
        "static_nonnumeric_run_id_review",
        "static_file_present_detached_review",
        "static_legacy_overlap_missing_file",
        "static_legacy_overlap_file_present_review",
        "static_canonical_residue_review",
        "static_malformed_run_id_review",
        "static_unknown_review",
        "unknown_link_review",
    }
)

_STATIC_PRIMARY_REASON_TO_CLEANUP_CATEGORY: dict[str, str] = {
    "truly_detached": "static_truly_detached_candidate",
    "file_present_db_detached": "static_file_present_detached_review",
    "legacy_mirror_only_file_missing": "static_legacy_overlap_missing_file",
    "legacy_mirror_only_with_file": "static_legacy_overlap_file_present_review",
    "canonical_db_residue": "static_canonical_residue_review",
    "malformed_static_run_id": "static_malformed_run_id_review",
    "unknown_needs_review": "static_unknown_review",
}


def _collect_static_dangling_summary(run_sql: Callable[..., Any], *, repo_root: Path) -> Mapping[str, Any]:
    from .artifact_registry_static_dangling import collect_artifact_registry_static_dangling_report

    return collect_artifact_registry_static_dangling_report(run_sql, repo_root=repo_root)


def _collect_static_session_retirement_summary(
    run_sql: Callable[..., Any],
    *,
    repo_root: Path,
) -> Mapping[str, Any]:
    from .artifact_registry_static_session_retirement import collect_static_session_retirement_report

    return collect_static_session_retirement_report(run_sql, repo_root=repo_root)


def _clamp_interval_days(value: int, *, lo: int = 1, hi: int = 3650) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        v = lo
    return max(lo, min(v, hi))


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _static_cleanup_category_from_reason(reason: Any) -> str:
    key = _norm_text(reason)
    return _STATIC_PRIMARY_REASON_TO_CLEANUP_CATEGORY.get(key, "static_unknown_review")


def _rebuild_totals_by_category(summary_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    for row in summary_rows:
        if not isinstance(row, Mapping):
            continue
        category = str(row.get("cleanup_category") or "")
        counter[category] += int(row.get("row_count") or 0)
    return [
        {
            "cleanup_category": category,
            "row_count": int(row_count),
            "candidate_action": CATEGORY_ACTIONS.get(category, "—"),
        }
        for category, row_count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    ]


def _build_cleanup_summary_counts(totals_by_category: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "total_rows": 0,
        "linked_keep_rows": 0,
        "safe_prune_candidate_rows": 0,
        "review_or_blocked_rows": 0,
        "other_rows": 0,
    }
    for row in totals_by_category:
        category = str(row.get("cleanup_category") or "")
        row_count = int(row.get("row_count") or 0)
        counts["total_rows"] += row_count
        if category == "linked_keep":
            counts["linked_keep_rows"] += row_count
        elif category in SAFE_PRUNE_CATEGORIES:
            counts["safe_prune_candidate_rows"] += row_count
        elif category in REVIEW_BLOCKED_CATEGORIES:
            counts["review_or_blocked_rows"] += row_count
        else:
            counts["other_rows"] += row_count
    return counts


def _build_static_dangling_summary_dimensions(static_report: Mapping[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    grouped: dict[tuple[str, str, str, str, str, str, str], dict[str, Any]] = {}
    category_counts: Counter[str] = Counter()
    rows = static_report.get("static_dangling_rows") or []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        cleanup_category = _static_cleanup_category_from_reason(row.get("primary_reason"))
        artifact_type = str(row.get("artifact_type") or "")
        age_bucket = str(row.get("age_bucket") or "")
        host_path_presence = "blank_host" if not _norm_text(row.get("host_path")) else "host_path_set"
        static_run_id_shape = "numeric_run_id" if row.get("resolved_static_run_id") is not None else "non_numeric_run_id"
        key = (
            cleanup_category,
            str(row.get("run_type") or ""),
            str(row.get("link_state") or ""),
            artifact_type,
            age_bucket,
            host_path_presence,
            static_run_id_shape,
        )
        current = grouped.setdefault(
            key,
            {
                "cleanup_category": cleanup_category,
                "run_type": str(row.get("run_type") or ""),
                "link_state": str(row.get("link_state") or ""),
                "artifact_type": artifact_type,
                "age_bucket": age_bucket,
                "host_path_presence": host_path_presence,
                "static_run_id_shape": static_run_id_shape,
                "row_count": 0,
                "created_min": None,
                "created_max": None,
            },
        )
        current["row_count"] = int(current.get("row_count") or 0) + 1
        created = _norm_text(row.get("created_at_utc")) or None
        if created:
            if not current["created_min"] or created < str(current["created_min"]):
                current["created_min"] = created
            if not current["created_max"] or created > str(current["created_max"]):
                current["created_max"] = created
        category_counts[cleanup_category] += 1
    summary_rows = list(grouped.values())
    summary_rows.sort(
        key=lambda row: (
            -int(row.get("row_count") or 0),
            str(row.get("cleanup_category") or ""),
            str(row.get("artifact_type") or ""),
        )
    )
    return summary_rows, dict(sorted(category_counts.items()))


def _build_static_dangling_top_run_ids(static_report: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    runs = static_report.get("static_dangling_runs") or []
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in runs:
        if not isinstance(row, Mapping):
            continue
        cleanup_category = _static_cleanup_category_from_reason(
            row.get("dominant_primary_reason") or row.get("primary_reason")
        )
        grouped[cleanup_category].append(
            {
                "run_id": str(row.get("resolved_static_run_id") or ""),
                "count": int(row.get("row_count") or 0),
            }
        )
    for category, items in grouped.items():
        out[category] = sorted(items, key=lambda item: (-int(item.get("count") or 0), str(item.get("run_id") or "")))[:12]
    return dict(out)


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
    repo_root: Path | None = None,
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

    static_report: Mapping[str, Any] | None = None
    static_diagnostics_summary: dict[str, Any] | None = None

    if not run_type_filter or str(run_type_filter).strip().lower() == "static":
        try:
            resolved_repo_root = (repo_root or Path.cwd()).resolve()
            static_report = _collect_static_dangling_summary(
                run_sql,
                repo_root=resolved_repo_root,
            )
            retirement_report = _collect_static_session_retirement_summary(
                run_sql,
                repo_root=resolved_repo_root,
            )
            static_summary = (
                static_report.get("summary")
                if isinstance(static_report.get("summary"), Mapping)
                else {}
            )
            retirement_summary = (
                retirement_report.get("summary")
                if isinstance(retirement_report.get("summary"), Mapping)
                else {}
            )
            static_cleanup_dimensions, static_cleanup_category_counts = _build_static_dangling_summary_dimensions(static_report)
            static_diagnostics_summary = {
                "dangling_static_registry_rows": int(static_summary.get("dangling_static_registry_rows") or 0),
                "linked_static_registry_rows": int(static_summary.get("linked_static_registry_rows") or 0),
                "distinct_static_run_count": int(static_summary.get("distinct_static_run_count") or 0),
                "distinct_recovered_package_count": int(static_summary.get("distinct_recovered_package_count") or 0),
                "runs_with_recovered_manifest_context": int(static_summary.get("runs_with_recovered_manifest_context") or 0),
                "complete_core_bundle_run_count": int(static_summary.get("complete_core_bundle_run_count") or 0),
                "partial_core_bundle_run_count": int(static_summary.get("partial_core_bundle_run_count") or 0),
                "runs_with_duplicate_artifact_types": int(static_summary.get("runs_with_duplicate_artifact_types") or 0),
                "primary_reason_counts": dict(static_summary.get("primary_reason_counts") or {}),
                "reason_flag_counts": dict(static_summary.get("reason_flag_counts") or {}),
                "cleanup_category_counts": static_cleanup_category_counts,
                "blocked_session_count": int(retirement_summary.get("blocked_session_count") or 0),
                "blocked_registry_rows": int(retirement_summary.get("blocked_registry_rows") or 0),
                "blocked_sessions": list(retirement_summary.get("blocked_sessions") or []),
                "candidate_session_count": int(retirement_summary.get("candidate_session_count") or 0),
                "candidate_registry_rows": int(retirement_summary.get("candidate_registry_rows") or 0),
                "recommended_candidate_order": list(retirement_summary.get("recommended_candidate_order") or []),
            }
        except Exception as exc:
            static_report = None
            static_diagnostics_summary = {"error": f"{type(exc).__name__}: {exc}"}
            static_cleanup_dimensions = []
    else:
        static_cleanup_dimensions = []

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
    summary_rows = [dict(row) for row in rows if isinstance(row, dict)]

    if static_cleanup_dimensions:
        summary_rows = [
            row
            for row in summary_rows
            if not (
                str(row.get("run_type") or "") == "static"
                and str(row.get("link_state") or "") == "dangling_static_run"
            )
        ]
        summary_rows.extend(static_cleanup_dimensions)

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

    if static_cleanup_dimensions and static_report:
        for category, items in _build_static_dangling_top_run_ids(static_report).items():
            top_by_category[category] = items
    totals_by_category = _rebuild_totals_by_category(summary_rows)
    summary_counts = _build_cleanup_summary_counts(totals_by_category)
    allowed_categories = {str(row.get("cleanup_category") or "") for row in totals_by_category}
    top_by_category = {category: items for category, items in top_by_category.items() if category in allowed_categories}

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
        "summary_counts": summary_counts,
        "totals_by_category": totals_by_category,
        "summary_dimensions": summary_rows,
        "top_run_ids_by_category": {k: v for k, v in top_by_category.items()},
        "path_probe": path_probe,
        "static_diagnostics_summary": static_diagnostics_summary,
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
    summary = data.get("summary_counts")
    if isinstance(summary, Mapping):
        lines.append("## Summary")
        lines.append(f"  total_rows={summary.get('total_rows')}")
        lines.append(f"  linked_keep_rows={summary.get('linked_keep_rows')}")
        lines.append(f"  safe_prune_candidate_rows={summary.get('safe_prune_candidate_rows')}")
        lines.append(f"  review_or_blocked_rows={summary.get('review_or_blocked_rows')}")
        other = int(summary.get("other_rows") or 0)
        if other:
            lines.append(f"  other_rows={other}")
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
    static_diag = data.get("static_diagnostics_summary")
    if isinstance(static_diag, Mapping):
        lines.append("")
        lines.append("## Static dangling focus")
        if static_diag.get("error"):
            lines.append(f"  static diagnostics unavailable: {static_diag.get('error')}")
        else:
            reason_counts = static_diag.get("primary_reason_counts")
            if isinstance(reason_counts, Mapping) and reason_counts:
                lines.append(
                    "  primary reasons: "
                    + ", ".join(f"{key}={reason_counts[key]}" for key in sorted(reason_counts))
                )
            cleanup_counts = static_diag.get("cleanup_category_counts")
            if isinstance(cleanup_counts, Mapping) and cleanup_counts:
                lines.append(
                    "  cleanup categories: "
                    + ", ".join(f"{key}={cleanup_counts[key]}" for key in sorted(cleanup_counts))
                )
            lines.append(
                "  detached runs: "
                f"{static_diag.get('distinct_static_run_count', 0)} "
                f"(recovered packages={static_diag.get('distinct_recovered_package_count', 0)})"
            )
            lines.append(
                "  recovered manifest context: "
                f"{static_diag.get('runs_with_recovered_manifest_context', 0)} run(s)"
            )
            lines.append(
                "  core bundle status: "
                f"complete={static_diag.get('complete_core_bundle_run_count', 0)} "
                f"partial={static_diag.get('partial_core_bundle_run_count', 0)} "
                f"duplicates={static_diag.get('runs_with_duplicate_artifact_types', 0)}"
            )
            lines.append(
                "  blocked legacy sessions: "
                f"{static_diag.get('blocked_session_count', 0)} "
                f"(registry_rows={static_diag.get('blocked_registry_rows', 0)})"
            )
            blocked_sessions = static_diag.get("blocked_sessions")
            if isinstance(blocked_sessions, list) and blocked_sessions:
                lines.append("  blocked session stamps: " + ", ".join(str(item) for item in blocked_sessions[:8]))
            lines.append(
                "  candidate legacy sessions: "
                f"{static_diag.get('candidate_session_count', 0)} "
                f"(registry_rows={static_diag.get('candidate_registry_rows', 0)})"
            )
            candidate_order = static_diag.get("recommended_candidate_order")
            if isinstance(candidate_order, list) and candidate_order:
                lines.append("  recommended candidate order: " + ", ".join(str(item) for item in candidate_order[:8]))
    lines.append("")
    lines.append("Notes:")
    lines.append(
        "  This report is SELECT-only. For **scoped** old-dangling deletes (receipt + --apply), use "
        "scripts/db/prune_artifact_registry_dangling.py. For static-only truly detached rows, inspect first with "
        "scripts/db/report_artifact_registry_static_detached.py, then use "
        "scripts/db/prune_artifact_registry_static_detached.py if the proposal is still clean; "
        "see docs/maintenance/artifact_registry_cleanup_track.md."
    )
    lines.append(
        "  For static rows blocked because host files still exist, stage review with "
        "scripts/db/report_artifact_registry_static_file_present_detached.py and "
        "scripts/db/report_artifact_registry_static_blocked_file_presence.py before any prune decision. "
        "Exact-hash file-present rows can then use "
        "scripts/db/prune_artifact_registry_static_file_present_resolved.py with --expected-count."
    )
    lines.append(
        "  Workspace maintenance → prune artifact_registry remains a blunt instrument: it deletes **all** "
        "non-linked rows after prompts — avoid for catalog-wide debt."
    )
    lines.append(
        "  artifact_registry.session_stamp is now the preferred static session marker for new/backfilled rows; "
        "dynamic rows may still be null because dynamic_sessions does not expose a cohort-style session_stamp."
    )
    return "\n".join(lines) + "\n"


__all__ = [
    "CATEGORY_ACTIONS",
    "collect_cleanup_candidate_report",
    "format_text_report",
]
