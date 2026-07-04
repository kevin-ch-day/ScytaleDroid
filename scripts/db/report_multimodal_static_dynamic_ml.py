#!/usr/bin/env python3
"""Read-only fused static + dynamic + PCAP behavioral analysis.

This report keeps the same evidence-governed boundaries as the dynamic PCAP audit:
- no DB writes
- no payload inspection
- reproducible CSV / JSON outputs under output/audit/
- current dynamic evidence is fused with latest static risk / finding surfaces

The goal is not to replace run-governance truth. It adds an analyst-facing layer
that can answer: which apps combine heavier static risk surfaces with broader
runtime network behavior, and which current apps look most important to study next.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any, Mapping, Sequence

import random

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.db import report_dynamic_pcap_behavior_ml as dynamic_ml

FUSED_RUN_FIELDS: tuple[str, ...] = (
    "dynamic_run_id",
    "package_name",
    "app_label",
    "stats_eligible",
    "countable",
    "quota_state",
    "technical_validity_state",
    "interaction_mode",
    "run_profile",
    "static_run_id",
    "matched_static_surface_run_id",
    "static_match_mode",
    "profile_key",
    "profile_label",
    "category",
    "permission_audit_grade",
    "permission_audit_score_capped",
    "permission_run_grade",
    "permission_run_score",
    "permission_run_dangerous_count",
    "permission_run_signature_count",
    "permission_run_vendor_count",
    "static_high",
    "static_med",
    "static_low",
    "static_info",
    "static_findings_total",
    "static_risk_load",
    "pcap_bytes",
    "packet_count",
    "duration_s",
    "bytes_per_second",
    "packets_per_second",
    "domain_count",
    "unique_service_families",
    "unique_ja4_count",
    "top1_ja4_share",
    "third_party_share",
    "adtech_share",
    "service_families_observed",
)

APP_ROLLUP_FIELDS: tuple[str, ...] = (
    "app_label",
    "package_name",
    "sample_scope",
    "profile_key",
    "profile_label",
    "category",
    "runs_total",
    "countable_runs",
    "supplemental_runs",
    "baseline_runs",
    "interactive_runs",
    "exact_match_runs",
    "fallback_runs",
    "exact_match_fraction",
    "sample_hygiene",
    "static_run_id",
    "permission_audit_grade",
    "permission_audit_score_capped",
    "permission_run_grade",
    "permission_run_score",
    "static_high",
    "static_med",
    "static_low",
    "static_info",
    "static_findings_total",
    "static_risk_load",
    "median_domain_count",
    "median_unique_service_families",
    "median_unique_ja4_count",
    "median_third_party_share",
    "median_adtech_share",
    "median_top1_ja4_share",
    "median_pcap_bytes",
    "median_packets_per_second",
    "service_families_observed",
    "static_risk_score",
    "runtime_breadth_score",
    "fused_pressure_score",
    "risk_behavior_quadrant",
    "priority_band",
    "interpretation",
)

CORRELATION_FIELDS: tuple[str, ...] = (
    "static_metric",
    "dynamic_metric",
    "apps_compared",
    "spearman_rho",
    "rho_bootstrap_ci_low",
    "rho_bootstrap_ci_high",
    "permutation_p_value",
    "direction",
    "stability_note",
    "interpretation",
)

PRIORITY_FIELDS: tuple[str, ...] = (
    "rank",
    "app_label",
    "package_name",
    "priority_band",
    "fused_pressure_score",
    "static_risk_score",
    "runtime_breadth_score",
    "risk_behavior_quadrant",
    "permission_audit_grade",
    "static_findings_total",
    "median_unique_ja4_count",
    "median_domain_count",
    "median_third_party_share",
    "median_adtech_share",
    "interpretation",
)

PRIORITY_STABILITY_FIELDS: tuple[str, ...] = (
    "sample_scope",
    "package_name",
    "app_label",
    "observed_rank",
    "median_bootstrap_rank",
    "rank_ci_low",
    "rank_ci_high",
    "mean_bootstrap_fused_score",
    "score_ci_low",
    "score_ci_high",
    "top1_probability",
    "top3_probability",
    "high_priority_probability",
    "stability_note",
)

SAMPLE_HYGIENE_FIELDS: tuple[str, ...] = (
    "app_label",
    "package_name",
    "stats_eligible_runs",
    "countable_runs",
    "supplemental_runs",
    "exact_match_runs",
    "fallback_runs",
    "exact_match_fraction",
    "observed_dynamic_static_run_ids",
    "latest_static_surface_run_id",
    "sample_hygiene",
    "recapture_needed",
    "recommendation",
)

FALLBACK_DETAIL_FIELDS: tuple[str, ...] = (
    "dynamic_run_id",
    "package_name",
    "app_label",
    "countable",
    "quota_state",
    "interaction_mode",
    "run_profile",
    "static_run_id",
    "matched_static_surface_run_id",
    "static_match_mode",
    "recommendation",
)

CLUSTER_FIELDS: tuple[str, ...] = (
    "cluster_id",
    "app_label",
    "package_name",
    "nearest_neighbor",
    "nearest_neighbor_similarity",
    "cluster_basis",
)

SIMILARITY_FIELDS: tuple[str, ...] = (
    "package_name",
    "app_label",
    "other_package_name",
    "other_app_label",
    "cosine_similarity",
)

CLASSIFICATION_FIELDS: tuple[str, ...] = (
    "target",
    "feature_set",
    "samples",
    "correct",
    "accuracy",
    "accuracy_ci_low",
    "accuracy_ci_high",
    "classes_observed",
    "notes",
)

CLASSIFICATION_PREDICTIONS_FIELDS: tuple[str, ...] = (
    "target",
    "feature_set",
    "package_name",
    "app_label",
    "actual_label",
    "predicted_label",
    "correct",
    "nearest_label_distance",
)

FEATURE_IMPORTANCE_FIELDS: tuple[str, ...] = (
    "target",
    "feature_name",
    "importance_score",
    "interpretation",
)

FUSED_MODEL_FEATURES: tuple[str, ...] = (
    "permission_audit_score_capped",
    "permission_run_score",
    "static_risk_load",
    "static_findings_total",
    "median_domain_count",
    "median_unique_service_families",
    "median_unique_ja4_count",
    "median_third_party_share",
    "median_adtech_share",
    "median_top1_ja4_share",
    "median_pcap_bytes",
    "median_packets_per_second",
)

RUNTIME_ONLY_MODEL_FEATURES: tuple[str, ...] = (
    "median_domain_count",
    "median_unique_service_families",
    "median_unique_ja4_count",
    "median_third_party_share",
    "median_adtech_share",
    "median_top1_ja4_share",
    "median_pcap_bytes",
    "median_packets_per_second",
)


def fused_run_fieldnames() -> tuple[str, ...]:
    return FUSED_RUN_FIELDS


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only fused static + dynamic + PCAP analysis over current governed evidence.",
    )
    parser.add_argument(
        "--package",
        action="append",
        default=[],
        help="Optional package filter. Repeatable.",
    )
    parser.add_argument(
        "--output-dir",
        help="Optional output directory. Defaults under output/audit/multimodal_static_dynamic_ml/<stamp>/",
    )
    parser.add_argument(
        "--recompute-exact-tls",
        action="store_true",
        help="Recompute exact TLS summaries from local PCAP files instead of trusting persisted summaries.",
    )
    parser.add_argument(
        "--stdout-json",
        action="store_true",
        help="Print full summary JSON to stdout.",
    )
    return parser


def _default_output_dir() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return _REPO_ROOT / "output" / "audit" / "multimodal_static_dynamic_ml" / stamp


def _sql_filter(packages: Sequence[str]) -> tuple[str, tuple[str, ...]]:
    normalized = tuple(sorted({dynamic_ml._norm_text(value).lower() for value in packages if dynamic_ml._norm_text(value)}))
    if not normalized:
        return "", ()
    placeholders = ", ".join(["%s"] * len(normalized))
    return f"WHERE LOWER(TRIM(ws.package_name)) IN ({placeholders})", normalized


def _load_static_surfaces(packages: Sequence[str]) -> list[dict[str, Any]]:
    from scytaledroid.Database.db_core import db_queries as core_q

    where_sql, params = _sql_filter(packages)
    query = f"""
        SELECT
          ws.package_name,
          ws.app_label,
          ws.category,
          ws.profile_key,
          ws.profile_label,
          ws.latest_static_run_id AS static_run_id,
          ws.permission_audit_grade,
          ws.permission_audit_score_capped,
          ws.static_high,
          ws.static_med,
          ws.static_low,
          ws.static_info,
          rs.permission_run_grade,
          rs.permission_run_score,
          rs.permission_run_dangerous_count,
          rs.permission_run_signature_count,
          rs.permission_run_vendor_count,
          fs.canonical_findings_total
        FROM v_web_static_dynamic_app_summary ws
        LEFT JOIN vw_static_risk_surfaces_latest rs
          ON rs.package_name = ws.package_name
         AND rs.static_run_id = ws.latest_static_run_id
        LEFT JOIN vw_static_finding_surfaces_latest fs
          ON fs.package_name = ws.package_name
         AND fs.static_run_id = ws.latest_static_run_id
        {where_sql}
        ORDER BY ws.package_name
    """
    return core_q.run_sql(
        query,
        params,
        fetch="all",
        dictionary=True,
        query_name="dynamic.multimodal_ml.static_surfaces",
    ) or []


def _static_risk_load(row: Mapping[str, Any]) -> float:
    high = float(dynamic_ml._safe_float(row.get("static_high")) or 0.0)
    med = float(dynamic_ml._safe_float(row.get("static_med")) or 0.0)
    low = float(dynamic_ml._safe_float(row.get("static_low")) or 0.0)
    info = float(dynamic_ml._safe_float(row.get("static_info")) or 0.0)
    return (high * 3.0) + (med * 2.0) + low + (info * 0.25)


def _effective_permission_grade(row: Mapping[str, Any]) -> str:
    return (
        dynamic_ml._norm_text(row.get("permission_audit_grade"))
        or dynamic_ml._norm_text(row.get("permission_run_grade"))
    )


def _effective_permission_score(row: Mapping[str, Any]) -> float | None:
    audit_score = dynamic_ml._safe_float(row.get("permission_audit_score_capped"))
    if audit_score is not None:
        return audit_score
    return dynamic_ml._safe_float(row.get("permission_run_score"))


def _choose_static_surface(
    feature_row: Mapping[str, Any],
    by_package: Mapping[str, Mapping[str, Any]],
    by_package_static_run: Mapping[tuple[str, int], Mapping[str, Any]],
) -> tuple[Mapping[str, Any] | None, str]:
    package_name = dynamic_ml._norm_text(feature_row.get("package_name")).lower()
    static_run_id = dynamic_ml._safe_int(feature_row.get("static_run_id"))
    if package_name and static_run_id is not None:
        exact = by_package_static_run.get((package_name, static_run_id))
        if exact:
            return exact, "exact_latest"
    if package_name:
        latest = by_package.get(package_name)
        if latest:
            return latest, "package_latest_fallback"
    return None, "missing_static_surface"


def _build_fused_run_rows(
    feature_rows: Sequence[Mapping[str, Any]],
    static_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    by_package = {
        dynamic_ml._norm_text(row.get("package_name")).lower(): row
        for row in static_rows
        if dynamic_ml._norm_text(row.get("package_name"))
    }
    by_package_static_run = {
        (dynamic_ml._norm_text(row.get("package_name")).lower(), int(dynamic_ml._safe_int(row.get("static_run_id")))):
        row
        for row in static_rows
        if dynamic_ml._norm_text(row.get("package_name")) and dynamic_ml._safe_int(row.get("static_run_id")) is not None
    }
    out: list[dict[str, Any]] = []
    for row in feature_rows:
        static_row, match_mode = _choose_static_surface(row, by_package, by_package_static_run)
        static_risk_load = _static_risk_load(static_row or {})
        first_party_domain_count = dynamic_ml._safe_int(row.get("first_party_domain_count"))
        third_party_domain_count = dynamic_ml._safe_int(row.get("third_party_domain_count"))
        unresolved_domain_count = dynamic_ml._safe_int(row.get("unresolved_domain_count"))
        third_party_share = dynamic_ml._safe_float(row.get("third_party_share"))
        row_total = (
            int(first_party_domain_count or 0)
            + int(third_party_domain_count or 0)
            + int(unresolved_domain_count or 0)
        )
        if third_party_share is None and row_total > 0 and third_party_domain_count is not None:
            third_party_share = float(third_party_domain_count) / float(row_total)
        permission_grade = _effective_permission_grade(static_row or {})
        permission_score = _effective_permission_score(static_row or {})
        out.append(
            {
                "dynamic_run_id": dynamic_ml._norm_text(row.get("dynamic_run_id")),
                "package_name": dynamic_ml._norm_text(row.get("package_name")).lower(),
                "app_label": dynamic_ml._norm_text(row.get("app_label")),
                "stats_eligible": dynamic_ml._safe_int(row.get("stats_eligible")),
                "countable": dynamic_ml._safe_int(row.get("countable")),
                "quota_state": dynamic_ml._norm_text(row.get("quota_state")),
                "technical_validity_state": dynamic_ml._norm_text(row.get("technical_validity_state")),
                "interaction_mode": dynamic_ml._norm_text(row.get("interaction_mode")),
                "run_profile": dynamic_ml._norm_text(row.get("run_profile")),
                "static_run_id": dynamic_ml._safe_int(row.get("static_run_id")),
                "matched_static_surface_run_id": dynamic_ml._safe_int((static_row or {}).get("static_run_id")),
                "static_match_mode": match_mode,
                "profile_key": dynamic_ml._norm_text((static_row or {}).get("profile_key")),
                "profile_label": dynamic_ml._norm_text((static_row or {}).get("profile_label")),
                "category": dynamic_ml._norm_text((static_row or {}).get("category")),
                "permission_audit_grade": permission_grade,
                "permission_audit_score_capped": permission_score,
                "permission_run_grade": dynamic_ml._norm_text((static_row or {}).get("permission_run_grade")),
                "permission_run_score": dynamic_ml._safe_float((static_row or {}).get("permission_run_score")),
                "permission_run_dangerous_count": dynamic_ml._safe_int((static_row or {}).get("permission_run_dangerous_count")),
                "permission_run_signature_count": dynamic_ml._safe_int((static_row or {}).get("permission_run_signature_count")),
                "permission_run_vendor_count": dynamic_ml._safe_int((static_row or {}).get("permission_run_vendor_count")),
                "static_high": dynamic_ml._safe_float((static_row or {}).get("static_high")),
                "static_med": dynamic_ml._safe_float((static_row or {}).get("static_med")),
                "static_low": dynamic_ml._safe_float((static_row or {}).get("static_low")),
                "static_info": dynamic_ml._safe_float((static_row or {}).get("static_info")),
                "static_findings_total": dynamic_ml._safe_float((static_row or {}).get("canonical_findings_total")),
                "static_risk_load": static_risk_load,
                "pcap_bytes": dynamic_ml._safe_int(row.get("pcap_bytes")),
                "packet_count": dynamic_ml._safe_int(row.get("packet_count")),
                "duration_s": dynamic_ml._safe_float(row.get("duration_s")),
                "bytes_per_second": dynamic_ml._safe_float(row.get("bytes_per_second")),
                "packets_per_second": dynamic_ml._safe_float(row.get("packets_per_second")),
                "domain_count": dynamic_ml._safe_int(row.get("domain_count")),
                "unique_service_families": dynamic_ml._safe_int(row.get("unique_service_families")),
                "unique_ja4_count": dynamic_ml._safe_int(row.get("unique_ja4_count")),
                "top1_ja4_share": dynamic_ml._safe_float(row.get("top1_ja4_share")),
                "third_party_share": third_party_share,
                "adtech_share": dynamic_ml._safe_float(row.get("adtech_share")),
                "service_families_observed": dynamic_ml._norm_text(row.get("service_families_observed")),
            }
        )
    return out


def _avg(values: Sequence[float | None]) -> float | None:
    usable = [float(value) for value in values if value is not None]
    if not usable:
        return None
    return sum(usable) / float(len(usable))


def _assign_quadrant(static_score: float | None, runtime_score: float | None, *, static_cut: float, runtime_cut: float) -> str:
    if static_score is None or runtime_score is None:
        return "insufficient"
    if static_score >= static_cut and runtime_score >= runtime_cut:
        return "high_static_high_runtime"
    if static_score >= static_cut and runtime_score < runtime_cut:
        return "high_static_low_runtime"
    if static_score < static_cut and runtime_score >= runtime_cut:
        return "low_static_high_runtime"
    return "low_static_low_runtime"


def _priority_band(score: float | None, scores: Sequence[float]) -> str:
    if score is None or not scores:
        return "unscored"
    ordered = sorted(scores)
    high_cut = ordered[max(0, int(math.floor((len(ordered) - 1) * 0.75)))]
    med_cut = ordered[max(0, int(math.floor((len(ordered) - 1) * 0.40)))]
    if score >= high_cut:
        return "high"
    if score >= med_cut:
        return "medium"
    return "lower"


def _interpret_quadrant(quadrant: str) -> str:
    if quadrant == "high_static_high_runtime":
        return "high static pressure with broad runtime behavior"
    if quadrant == "high_static_low_runtime":
        return "permission-heavy surface with concentrated runtime behavior"
    if quadrant == "low_static_high_runtime":
        return "lighter static surface but broad runtime/service spread"
    if quadrant == "low_static_low_runtime":
        return "comparatively narrower static and runtime surface"
    return "insufficient fused evidence"


def _group_stats_eligible_rows(fused_rows: Sequence[Mapping[str, Any]]) -> dict[str, list[Mapping[str, Any]]]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in fused_rows:
        package_name = dynamic_ml._norm_text(row.get("package_name")).lower()
        if not package_name:
            continue
        if dynamic_ml._safe_int(row.get("stats_eligible")) != 1:
            continue
        grouped[package_name].append(row)
    return grouped


def _sample_hygiene_label(*, exact_runs: int, fallback_runs: int) -> str:
    total = exact_runs + fallback_runs
    if total <= 0:
        return "empty"
    if fallback_runs == 0:
        return "strict_exact_only"
    if exact_runs == 0:
        return "fallback_only"
    return "mixed_exact_fallback"


def _build_preliminary_rollups(
    grouped: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    sample_scope: str,
) -> list[dict[str, Any]]:
    preliminary: list[dict[str, Any]] = []
    for package_name in sorted(grouped):
        stats_rows = list(grouped[package_name])
        if not stats_rows:
            continue
        first = stats_rows[0]
        countable_rows = [row for row in stats_rows if dynamic_ml._safe_int(row.get("countable")) == 1]
        supplemental_rows = [row for row in stats_rows if dynamic_ml._norm_text(row.get("quota_state")) == "SUPPLEMENTAL_VALID"]
        baseline_rows = [row for row in stats_rows if dynamic_ml._norm_text(row.get("interaction_mode")) == "baseline"]
        interactive_rows = [row for row in stats_rows if dynamic_ml._norm_text(row.get("interaction_mode")) != "baseline"]
        exact_rows = [row for row in stats_rows if dynamic_ml._norm_text(row.get("static_match_mode")) == "exact_latest"]
        fallback_rows = [row for row in stats_rows if dynamic_ml._norm_text(row.get("static_match_mode")) == "package_latest_fallback"]

        families: list[str] = []
        for row in stats_rows:
            families.extend(
                [value.strip() for value in dynamic_ml._norm_text(row.get("service_families_observed")).split(",") if value.strip()]
            )
        unique_families = ", ".join(sorted(dict.fromkeys(families)))

        preliminary.append(
            {
                "app_label": dynamic_ml._norm_text(first.get("app_label")),
                "package_name": package_name,
                "sample_scope": sample_scope,
                "profile_key": dynamic_ml._norm_text(first.get("profile_key")),
                "profile_label": dynamic_ml._norm_text(first.get("profile_label")),
                "category": dynamic_ml._norm_text(first.get("category")),
                "runs_total": len(stats_rows),
                "countable_runs": len(countable_rows),
                "supplemental_runs": len(supplemental_rows),
                "baseline_runs": len(baseline_rows),
                "interactive_runs": len(interactive_rows),
                "exact_match_runs": len(exact_rows),
                "fallback_runs": len(fallback_rows),
                "exact_match_fraction": (float(len(exact_rows)) / float(len(stats_rows))) if stats_rows else None,
                "sample_hygiene": _sample_hygiene_label(exact_runs=len(exact_rows), fallback_runs=len(fallback_rows)),
                "static_run_id": dynamic_ml._safe_int(first.get("matched_static_surface_run_id")) or dynamic_ml._safe_int(first.get("static_run_id")),
                "permission_audit_grade": dynamic_ml._norm_text(first.get("permission_audit_grade")),
                "permission_audit_score_capped": dynamic_ml._safe_float(first.get("permission_audit_score_capped")),
                "permission_run_grade": dynamic_ml._norm_text(first.get("permission_run_grade")),
                "permission_run_score": dynamic_ml._safe_float(first.get("permission_run_score")),
                "static_high": dynamic_ml._safe_float(first.get("static_high")),
                "static_med": dynamic_ml._safe_float(first.get("static_med")),
                "static_low": dynamic_ml._safe_float(first.get("static_low")),
                "static_info": dynamic_ml._safe_float(first.get("static_info")),
                "static_findings_total": dynamic_ml._safe_float(first.get("static_findings_total")),
                "static_risk_load": dynamic_ml._safe_float(first.get("static_risk_load")),
                "median_domain_count": dynamic_ml._median_iqr([float(row["domain_count"]) for row in stats_rows if row.get("domain_count") is not None])[0],
                "median_unique_service_families": dynamic_ml._median_iqr([float(row["unique_service_families"]) for row in stats_rows if row.get("unique_service_families") is not None])[0],
                "median_unique_ja4_count": dynamic_ml._median_iqr([float(row["unique_ja4_count"]) for row in stats_rows if row.get("unique_ja4_count") is not None])[0],
                "median_third_party_share": dynamic_ml._median_iqr([float(row["third_party_share"]) for row in stats_rows if row.get("third_party_share") is not None])[0],
                "median_adtech_share": dynamic_ml._median_iqr([float(row["adtech_share"]) for row in stats_rows if row.get("adtech_share") is not None])[0],
                "median_top1_ja4_share": dynamic_ml._median_iqr([float(row["top1_ja4_share"]) for row in stats_rows if row.get("top1_ja4_share") is not None])[0],
                "median_pcap_bytes": dynamic_ml._median_iqr([float(row["pcap_bytes"]) for row in stats_rows if row.get("pcap_bytes") is not None])[0],
                "median_packets_per_second": dynamic_ml._median_iqr([float(row["packets_per_second"]) for row in stats_rows if row.get("packets_per_second") is not None])[0],
                "service_families_observed": unique_families,
            }
        )
    return preliminary


def _score_rollups(preliminary: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    preliminary = [dict(row) for row in preliminary]
    if not preliminary:
        return []
    static_vectors = {
        row["package_name"]: [
            float(row.get("permission_audit_score_capped") or 0.0),
            float(row.get("permission_run_score") or 0.0),
            float(row.get("static_risk_load") or 0.0),
            float(row.get("static_findings_total") or 0.0),
            float(row.get("static_high") or 0.0),
        ]
        for row in preliminary
    }
    runtime_vectors = {
        row["package_name"]: [
            float(row.get("median_domain_count") or 0.0),
            float(row.get("median_unique_service_families") or 0.0),
            float(row.get("median_unique_ja4_count") or 0.0),
            float(row.get("median_pcap_bytes") or 0.0),
            float(row.get("median_packets_per_second") or 0.0),
            float(row.get("median_third_party_share") or 0.0),
            float(row.get("median_adtech_share") or 0.0),
            float(1.0 - min(max(float(row.get("median_top1_ja4_share") or 0.0), 0.0), 1.0)),
        ]
        for row in preliminary
    }
    static_scaled = dynamic_ml._robust_scale_vectors(static_vectors)
    runtime_scaled = dynamic_ml._robust_scale_vectors(runtime_vectors)

    static_scores: list[float] = []
    runtime_scores: list[float] = []
    fused_scores: list[float] = []
    for row in preliminary:
        package_name = row["package_name"]
        static_score = _avg(static_scaled.get(package_name, []))
        runtime_score = _avg(runtime_scaled.get(package_name, []))
        fused_score = _avg(list(static_scaled.get(package_name, [])) + list(runtime_scaled.get(package_name, [])))
        row["static_risk_score"] = static_score
        row["runtime_breadth_score"] = runtime_score
        row["fused_pressure_score"] = fused_score
        if static_score is not None:
            static_scores.append(static_score)
        if runtime_score is not None:
            runtime_scores.append(runtime_score)
        if fused_score is not None:
            fused_scores.append(fused_score)

    static_cut = float(median(static_scores)) if static_scores else 0.0
    runtime_cut = float(median(runtime_scores)) if runtime_scores else 0.0
    for row in preliminary:
        quadrant = _assign_quadrant(
            dynamic_ml._safe_float(row.get("static_risk_score")),
            dynamic_ml._safe_float(row.get("runtime_breadth_score")),
            static_cut=static_cut,
            runtime_cut=runtime_cut,
        )
        row["risk_behavior_quadrant"] = quadrant
        row["priority_band"] = _priority_band(dynamic_ml._safe_float(row.get("fused_pressure_score")), fused_scores)
        row["interpretation"] = _interpret_quadrant(quadrant)
    return preliminary


def _build_fused_app_rollups(fused_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped = _group_stats_eligible_rows(fused_rows)
    return _score_rollups(_build_preliminary_rollups(grouped, sample_scope="all_governed"))


def _filter_fused_rows_by_match_mode(
    fused_rows: Sequence[Mapping[str, Any]],
    *,
    allowed_modes: set[str],
) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in fused_rows
        if dynamic_ml._norm_text(row.get("static_match_mode")) in allowed_modes
    ]


def _build_strict_exact_app_rollups(fused_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    exact_rows = _filter_fused_rows_by_match_mode(fused_rows, allowed_modes={"exact_latest"})
    grouped = _group_stats_eligible_rows(exact_rows)
    return _score_rollups(_build_preliminary_rollups(grouped, sample_scope="strict_exact"))


def _recapture_recommendation(sample_hygiene: str) -> tuple[str, str]:
    if sample_hygiene == "strict_exact_only":
        return "no", "already exact-match aligned"
    if sample_hygiene == "mixed_exact_fallback":
        return "yes", "recollect newer runtime evidence to replace fallback-governed rows"
    if sample_hygiene == "fallback_only":
        return "yes", "capture or reindex runtime evidence against the newest static surface before paper-grade fusion"
    return "unknown", "insufficient stats-eligible fused rows"


def _build_sample_hygiene_rows(fused_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped = _group_stats_eligible_rows(fused_rows)
    rows: list[dict[str, Any]] = []
    for package_name in sorted(grouped):
        stats_rows = list(grouped[package_name])
        exact_rows = [row for row in stats_rows if dynamic_ml._norm_text(row.get("static_match_mode")) == "exact_latest"]
        fallback_rows = [row for row in stats_rows if dynamic_ml._norm_text(row.get("static_match_mode")) == "package_latest_fallback"]
        countable_rows = [row for row in stats_rows if dynamic_ml._safe_int(row.get("countable")) == 1]
        supplemental_rows = [row for row in stats_rows if dynamic_ml._norm_text(row.get("quota_state")) == "SUPPLEMENTAL_VALID"]
        sample_hygiene = _sample_hygiene_label(exact_runs=len(exact_rows), fallback_runs=len(fallback_rows))
        recapture_needed, recommendation = _recapture_recommendation(sample_hygiene)
        dynamic_static_ids = sorted(
            {
                int(static_run_id)
                for row in stats_rows
                if (static_run_id := dynamic_ml._safe_int(row.get("static_run_id"))) is not None
            }
        )
        latest_static_surface_run_id = next(
            (
                int(static_run_id)
                for row in stats_rows
                if (static_run_id := dynamic_ml._safe_int(row.get("matched_static_surface_run_id"))) is not None
            ),
            None,
        )
        rows.append(
            {
                "app_label": dynamic_ml._norm_text(stats_rows[0].get("app_label")),
                "package_name": package_name,
                "stats_eligible_runs": len(stats_rows),
                "countable_runs": len(countable_rows),
                "supplemental_runs": len(supplemental_rows),
                "exact_match_runs": len(exact_rows),
                "fallback_runs": len(fallback_rows),
                "exact_match_fraction": (float(len(exact_rows)) / float(len(stats_rows))) if stats_rows else None,
                "observed_dynamic_static_run_ids": ",".join(str(value) for value in dynamic_static_ids),
                "latest_static_surface_run_id": latest_static_surface_run_id,
                "sample_hygiene": sample_hygiene,
                "recapture_needed": recapture_needed,
                "recommendation": recommendation,
            }
        )
    return rows


def _build_fallback_detail_rows(fused_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in fused_rows:
        if dynamic_ml._norm_text(row.get("static_match_mode")) != "package_latest_fallback":
            continue
        rows.append(
            {
                "dynamic_run_id": dynamic_ml._norm_text(row.get("dynamic_run_id")),
                "package_name": dynamic_ml._norm_text(row.get("package_name")),
                "app_label": dynamic_ml._norm_text(row.get("app_label")),
                "countable": dynamic_ml._safe_int(row.get("countable")),
                "quota_state": dynamic_ml._norm_text(row.get("quota_state")),
                "interaction_mode": dynamic_ml._norm_text(row.get("interaction_mode")),
                "run_profile": dynamic_ml._norm_text(row.get("run_profile")),
                "static_run_id": dynamic_ml._safe_int(row.get("static_run_id")),
                "matched_static_surface_run_id": dynamic_ml._safe_int(row.get("matched_static_surface_run_id")),
                "static_match_mode": dynamic_ml._norm_text(row.get("static_match_mode")),
                "recommendation": "refresh runtime/static alignment before exact-fusion claims",
            }
        )
    return rows


def _sample_hygiene_state(sample_hygiene_rows: Sequence[Mapping[str, Any]]) -> str:
    if not sample_hygiene_rows:
        return "no_stats_eligible_rows"
    exact_apps = sum(1 for row in sample_hygiene_rows if dynamic_ml._norm_text(row.get("sample_hygiene")) == "strict_exact_only")
    mixed_apps = sum(1 for row in sample_hygiene_rows if dynamic_ml._norm_text(row.get("sample_hygiene")) == "mixed_exact_fallback")
    fallback_apps = sum(1 for row in sample_hygiene_rows if dynamic_ml._norm_text(row.get("sample_hygiene")) == "fallback_only")
    if exact_apps == 0 and mixed_apps == 0 and fallback_apps > 0:
        return "strict_exact_absent"
    if exact_apps > 0 and mixed_apps == 0 and fallback_apps == 0:
        return "strict_exact_only"
    if mixed_apps > 0:
        return "mixed_alignment"
    return "partial_alignment"


def _fused_claim_posture(sample_hygiene_state: str) -> str:
    if sample_hygiene_state == "strict_exact_only":
        return "paper_ready_exact_fusion"
    if sample_hygiene_state == "strict_exact_absent":
        return "descriptive_fallback_only"
    if sample_hygiene_state == "mixed_alignment":
        return "mixed_alignment_descriptive"
    if sample_hygiene_state == "partial_alignment":
        return "partial_alignment_descriptive"
    return "insufficient_alignment"


def _rankdata(values: Sequence[float]) -> list[float]:
    indexed = sorted(enumerate(values), key=lambda item: item[1])
    ranks = [0.0] * len(values)
    idx = 0
    while idx < len(indexed):
        end = idx
        while end + 1 < len(indexed) and indexed[end + 1][1] == indexed[idx][1]:
            end += 1
        avg_rank = (idx + end + 2) / 2.0
        for pos in range(idx, end + 1):
            original_index = indexed[pos][0]
            ranks[original_index] = avg_rank
        idx = end + 1
    return ranks


def _pearson(x_values: Sequence[float], y_values: Sequence[float]) -> float | None:
    if len(x_values) != len(y_values) or len(x_values) < 2:
        return None
    x_mean = sum(x_values) / float(len(x_values))
    y_mean = sum(y_values) / float(len(y_values))
    num = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, y_values))
    den_x = math.sqrt(sum((x - x_mean) ** 2 for x in x_values))
    den_y = math.sqrt(sum((y - y_mean) ** 2 for y in y_values))
    if den_x <= 1e-12 or den_y <= 1e-12:
        return None
    return num / (den_x * den_y)


def _spearman_rho(x_values: Sequence[float], y_values: Sequence[float]) -> float | None:
    if len(x_values) != len(y_values) or len(x_values) < 3:
        return None
    return _pearson(_rankdata(list(x_values)), _rankdata(list(y_values)))


def _correlation_note(rho: float | None) -> str:
    if rho is None:
        return "insufficient paired apps"
    magnitude = abs(rho)
    if magnitude >= 0.70:
        strength = "strong"
    elif magnitude >= 0.40:
        strength = "moderate"
    elif magnitude >= 0.20:
        strength = "weak"
    else:
        strength = "minimal"
    if rho > 0:
        return f"{strength} positive monotonic association"
    if rho < 0:
        return f"{strength} negative monotonic association"
    return "no monotonic association"


def _bootstrap_spearman_ci(
    x_values: Sequence[float],
    y_values: Sequence[float],
    *,
    seed: int = 1337,
    n_resamples: int = 4000,
    confidence_level: float = 0.95,
) -> tuple[float | None, float | None]:
    if len(x_values) != len(y_values) or len(x_values) < 4:
        return None, None
    rng = random.Random(seed)
    sample_size = len(x_values)
    estimates: list[float] = []
    for _ in range(n_resamples):
        indices = [rng.randrange(sample_size) for _ in range(sample_size)]
        sampled_x = [x_values[idx] for idx in indices]
        sampled_y = [y_values[idx] for idx in indices]
        rho = _spearman_rho(sampled_x, sampled_y)
        if rho is not None and not math.isnan(rho):
            estimates.append(float(rho))
    if len(estimates) < max(100, n_resamples // 10):
        return None, None
    estimates.sort()
    alpha = max(0.0, min(1.0, 1.0 - confidence_level))
    lower_idx = int((alpha / 2.0) * (len(estimates) - 1))
    upper_idx = int((1.0 - alpha / 2.0) * (len(estimates) - 1))
    return estimates[lower_idx], estimates[upper_idx]


def _spearman_permutation_p_value(
    x_values: Sequence[float],
    y_values: Sequence[float],
    *,
    seed: int = 1337,
    n_resamples: int = 4000,
) -> float | None:
    if len(x_values) != len(y_values) or len(x_values) < 4:
        return None
    observed = _spearman_rho(x_values, y_values)
    if observed is None:
        return None
    rng = random.Random(seed)
    observed_abs = abs(float(observed))
    exceed = 0
    usable = 0
    base_y = list(y_values)
    for _ in range(n_resamples):
        permuted = base_y[:]
        rng.shuffle(permuted)
        rho = _spearman_rho(x_values, permuted)
        if rho is None or math.isnan(rho):
            continue
        usable += 1
        if abs(float(rho)) >= observed_abs:
            exceed += 1
    if usable == 0:
        return None
    return float(exceed + 1) / float(usable + 1)


def _correlation_stability_note(
    rho: float | None,
    ci_low: float | None,
    ci_high: float | None,
    permutation_p_value: float | None,
) -> str:
    if rho is None:
        return "insufficient sample"
    if ci_low is None or ci_high is None:
        return "point estimate only"
    crosses_zero = ci_low <= 0.0 <= ci_high
    if permutation_p_value is not None and permutation_p_value <= 0.05 and not crosses_zero:
        return "directionally stable in this sample"
    if permutation_p_value is not None and permutation_p_value <= 0.10:
        return "suggestive but not stable"
    if crosses_zero:
        return "wide interval; direction unstable"
    return "exploratory effect"


def _build_correlation_rows(
    app_rollups: Sequence[Mapping[str, Any]],
    *,
    n_resamples: int = 4000,
) -> list[dict[str, Any]]:
    static_metrics = (
        "permission_audit_score_capped",
        "permission_run_score",
        "static_risk_load",
        "static_findings_total",
        "static_high",
    )
    dynamic_metrics = (
        "median_domain_count",
        "median_unique_service_families",
        "median_unique_ja4_count",
        "median_third_party_share",
        "median_adtech_share",
        "runtime_breadth_score",
        "median_top1_ja4_share",
    )
    out: list[dict[str, Any]] = []
    for static_metric in static_metrics:
        for dynamic_metric in dynamic_metrics:
            paired = [
                (
                    float(row[static_metric]),
                    float(row[dynamic_metric]),
                )
                for row in app_rollups
                if row.get(static_metric) is not None and row.get(dynamic_metric) is not None
            ]
            x_values = [pair[0] for pair in paired]
            y_values = [pair[1] for pair in paired]
            rho = _spearman_rho(x_values, y_values)
            ci_low, ci_high = _bootstrap_spearman_ci(x_values, y_values, n_resamples=n_resamples)
            permutation_p = _spearman_permutation_p_value(x_values, y_values, n_resamples=n_resamples)
            direction = "positive" if rho and rho > 0 else "negative" if rho and rho < 0 else "neutral"
            out.append(
                {
                    "static_metric": static_metric,
                    "dynamic_metric": dynamic_metric,
                    "apps_compared": len(paired),
                    "spearman_rho": rho,
                    "rho_bootstrap_ci_low": ci_low,
                    "rho_bootstrap_ci_high": ci_high,
                    "permutation_p_value": permutation_p,
                    "direction": direction,
                    "stability_note": _correlation_stability_note(rho, ci_low, ci_high, permutation_p),
                    "interpretation": _correlation_note(rho),
                }
            )
    out.sort(key=lambda row: abs(float(row.get("spearman_rho") or 0.0)), reverse=True)
    return out


def _build_priority_rows(app_rollups: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(
        app_rollups,
        key=lambda row: (
            float(row.get("fused_pressure_score") or -999.0),
            float(row.get("runtime_breadth_score") or -999.0),
            float(row.get("static_risk_score") or -999.0),
        ),
        reverse=True,
    )
    out: list[dict[str, Any]] = []
    for idx, row in enumerate(ordered, start=1):
        out.append(
            {
                "rank": idx,
                "app_label": row.get("app_label"),
                "package_name": row.get("package_name"),
                "priority_band": row.get("priority_band"),
                "fused_pressure_score": row.get("fused_pressure_score"),
                "static_risk_score": row.get("static_risk_score"),
                "runtime_breadth_score": row.get("runtime_breadth_score"),
                "risk_behavior_quadrant": row.get("risk_behavior_quadrant"),
                "permission_audit_grade": row.get("permission_audit_grade"),
                "static_findings_total": row.get("static_findings_total"),
                "median_unique_ja4_count": row.get("median_unique_ja4_count"),
                "median_domain_count": row.get("median_domain_count"),
                "median_third_party_share": row.get("median_third_party_share"),
                "median_adtech_share": row.get("median_adtech_share"),
                "interpretation": row.get("interpretation"),
            }
        )
    return out


def _bootstrap_priority_stability(
    fused_rows: Sequence[Mapping[str, Any]],
    priority_rows: Sequence[Mapping[str, Any]],
    *,
    sample_scope: str,
    seed: int = 1337,
    n_resamples: int = 800,
) -> list[dict[str, Any]]:
    grouped = _group_stats_eligible_rows(fused_rows)
    if not grouped or not priority_rows:
        return []

    observed_rank = {
        dynamic_ml._norm_text(row.get("package_name")): int(row.get("rank") or 0)
        for row in priority_rows
        if dynamic_ml._norm_text(row.get("package_name"))
    }
    labels = {
        dynamic_ml._norm_text(row.get("package_name")): dynamic_ml._norm_text(row.get("app_label"))
        for row in priority_rows
        if dynamic_ml._norm_text(row.get("package_name"))
    }
    rng = random.Random(seed)
    rank_samples: dict[str, list[int]] = defaultdict(list)
    score_samples: dict[str, list[float]] = defaultdict(list)
    top1_counts: dict[str, int] = defaultdict(int)
    top3_counts: dict[str, int] = defaultdict(int)
    high_priority_counts: dict[str, int] = defaultdict(int)

    for _ in range(n_resamples):
        sampled_rows: list[Mapping[str, Any]] = []
        for package_name, rows in grouped.items():
            row_list = list(rows)
            sampled_rows.extend(row_list[rng.randrange(len(row_list))] for _ in range(len(row_list)))
        sampled_rollups = _build_fused_app_rollups(sampled_rows)
        sampled_priority = _build_priority_rows(sampled_rollups)
        for row in sampled_priority:
            package_name = dynamic_ml._norm_text(row.get("package_name"))
            rank = int(row.get("rank") or 0)
            score = dynamic_ml._safe_float(row.get("fused_pressure_score"))
            rank_samples[package_name].append(rank)
            if score is not None:
                score_samples[package_name].append(float(score))
            if rank == 1:
                top1_counts[package_name] += 1
            if rank <= 3:
                top3_counts[package_name] += 1
            if dynamic_ml._norm_text(row.get("priority_band")) == "high":
                high_priority_counts[package_name] += 1

    def _percentile(sorted_values: Sequence[float], q: float) -> float | None:
        if not sorted_values:
            return None
        idx = max(0, min(len(sorted_values) - 1, int(round(q * (len(sorted_values) - 1)))))
        return float(sorted_values[idx])

    out: list[dict[str, Any]] = []
    for package_name in sorted(observed_rank, key=lambda name: observed_rank[name]):
        ranks = sorted(rank_samples.get(package_name, []))
        scores = sorted(score_samples.get(package_name, []))
        median_rank = dynamic_ml._median_iqr([float(value) for value in ranks])[0]
        mean_score = (sum(scores) / float(len(scores))) if scores else None
        top1_prob = (top1_counts.get(package_name, 0) / float(n_resamples)) if n_resamples > 0 else None
        top3_prob = (top3_counts.get(package_name, 0) / float(n_resamples)) if n_resamples > 0 else None
        high_prob = (high_priority_counts.get(package_name, 0) / float(n_resamples)) if n_resamples > 0 else None
        rank_ci_low = _percentile(ranks, 0.025)
        rank_ci_high = _percentile(ranks, 0.975)
        score_ci_low = _percentile(scores, 0.025)
        score_ci_high = _percentile(scores, 0.975)
        if top1_prob is not None and top1_prob >= 0.70:
            note = "stable top-ranked app"
        elif high_prob is not None and high_prob >= 0.80:
            note = "consistently high priority"
        elif top3_prob is not None and top3_prob >= 0.70:
            note = "usually top-three"
        else:
            note = "rank sensitive to resampling"
        out.append(
            {
                "sample_scope": sample_scope,
                "package_name": package_name,
                "app_label": labels.get(package_name, package_name),
                "observed_rank": observed_rank[package_name],
                "median_bootstrap_rank": median_rank,
                "rank_ci_low": rank_ci_low,
                "rank_ci_high": rank_ci_high,
                "mean_bootstrap_fused_score": mean_score,
                "score_ci_low": score_ci_low,
                "score_ci_high": score_ci_high,
                "top1_probability": top1_prob,
                "top3_probability": top3_prob,
                "high_priority_probability": high_prob,
                "stability_note": note,
            }
        )
    return out


def _build_similarity_outputs(app_rollups: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    raw_vectors = {
        dynamic_ml._norm_text(row.get("package_name")): [
            float(row.get("permission_audit_score_capped") or 0.0),
            float(row.get("permission_run_score") or 0.0),
            float(row.get("static_risk_load") or 0.0),
            float(row.get("static_findings_total") or 0.0),
            float(row.get("median_domain_count") or 0.0),
            float(row.get("median_unique_service_families") or 0.0),
            float(row.get("median_unique_ja4_count") or 0.0),
            float(row.get("median_third_party_share") or 0.0),
            float(row.get("median_adtech_share") or 0.0),
            float(row.get("median_packets_per_second") or 0.0),
        ]
        for row in app_rollups
        if dynamic_ml._norm_text(row.get("package_name"))
    }
    scaled = dynamic_ml._robust_scale_vectors(raw_vectors)
    by_pkg = {dynamic_ml._norm_text(row.get("package_name")): row for row in app_rollups}
    similarities: dict[tuple[str, str], float] = {}
    similarity_rows: list[dict[str, Any]] = []
    packages = sorted(scaled)
    for idx, package_name in enumerate(packages):
        for other in packages[idx + 1:]:
            score = dynamic_ml._cosine_similarity(scaled[package_name], scaled[other])
            if score is None:
                continue
            similarities[(package_name, other)] = score
            similarity_rows.append(
                {
                    "package_name": package_name,
                    "app_label": dynamic_ml._norm_text(by_pkg[package_name].get("app_label")),
                    "other_package_name": other,
                    "other_app_label": dynamic_ml._norm_text(by_pkg[other].get("app_label")),
                    "cosine_similarity": score,
                }
            )
    cluster_map = dynamic_ml._connected_component_clusters(similarities, threshold=0.82)
    cluster_rows: list[dict[str, Any]] = []
    for package_name in packages:
        nearest_neighbor = ""
        nearest_score = None
        for other in packages:
            if other == package_name:
                continue
            key = (package_name, other) if (package_name, other) in similarities else (other, package_name)
            score = similarities.get(key)
            if score is None:
                continue
            if nearest_score is None or score > nearest_score:
                nearest_neighbor = other
                nearest_score = score
        cluster_rows.append(
            {
                "cluster_id": cluster_map.get(package_name, 0),
                "app_label": dynamic_ml._norm_text(by_pkg[package_name].get("app_label")),
                "package_name": package_name,
                "nearest_neighbor": nearest_neighbor,
                "nearest_neighbor_similarity": nearest_score,
                "cluster_basis": "robust-scaled cosine similarity over fused static+runtime medians",
            }
        )
    return similarity_rows, cluster_rows


def _risk_bucket(row: Mapping[str, Any]) -> str:
    grade = dynamic_ml._norm_text(row.get("permission_audit_grade")).upper()
    if grade in {"D", "F"}:
        return "higher_static_risk"
    if grade in {"A", "B"}:
        return "lower_static_risk"
    if grade == "C":
        return "moderate_static_risk"
    return ""


def _vector_for_row(row: Mapping[str, Any], features: Sequence[str]) -> list[float]:
    return [float(row.get(name) or 0.0) for name in features]


def _feature_median(values: Sequence[float]) -> float:
    return float(median(values)) if values else 0.0


def _feature_iqr(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 1.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    lower = ordered[:mid]
    upper = ordered[-mid:] if mid else ordered
    q1 = _feature_median(lower or ordered)
    q3 = _feature_median(upper or ordered)
    iqr = q3 - q1
    return iqr if abs(iqr) > 1e-9 else 1.0


def _fit_robust_scaler(rows: Sequence[Mapping[str, Any]], features: Sequence[str]) -> dict[str, tuple[float, float]]:
    scaler: dict[str, tuple[float, float]] = {}
    for feature in features:
        values = [float(row.get(feature) or 0.0) for row in rows]
        scaler[feature] = (_feature_median(values), _feature_iqr(values))
    return scaler


def _transform_vector(row: Mapping[str, Any], features: Sequence[str], scaler: Mapping[str, tuple[float, float]]) -> list[float]:
    out: list[float] = []
    for feature in features:
        median_value, iqr_value = scaler.get(feature, (0.0, 1.0))
        raw = float(row.get(feature) or 0.0)
        out.append((raw - median_value) / iqr_value)
    return out


def _euclidean_distance(left: Sequence[float], right: Sequence[float]) -> float:
    return math.sqrt(sum((a - b) ** 2 for a, b in zip(left, right)))


def _nearest_centroid_loocv(
    rows: Sequence[Mapping[str, Any]],
    *,
    label_field: str,
    target_name: str,
    features: Sequence[str],
    feature_set_name: str,
    note: str,
    exact_ci: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    usable = [row for row in rows if dynamic_ml._norm_text(row.get(label_field))]
    label_set = sorted({dynamic_ml._norm_text(row.get(label_field)) for row in usable if dynamic_ml._norm_text(row.get(label_field))})
    if len(usable) < 3 or len(label_set) < 2:
        return [], {
            "target": target_name,
            "feature_set": feature_set_name,
            "samples": len(usable),
            "correct": 0,
            "accuracy": None,
            "accuracy_ci_low": None,
            "accuracy_ci_high": None,
            "classes_observed": ", ".join(label_set),
            "notes": note if len(label_set) >= 2 else f"{note}; insufficient label diversity",
        }

    predictions: list[dict[str, Any]] = []
    correct = 0
    for idx, test_row in enumerate(usable):
        train_rows = [row for pos, row in enumerate(usable) if pos != idx]
        scaler = _fit_robust_scaler(train_rows, features)
        train_vectors_by_label: dict[str, list[list[float]]] = defaultdict(list)
        for row in train_rows:
            label = dynamic_ml._norm_text(row.get(label_field))
            train_vectors_by_label[label].append(_transform_vector(row, features, scaler))
        centroids: dict[str, list[float]] = {}
        for label, vectors in train_vectors_by_label.items():
            centroids[label] = [
                sum(values[col] for values in vectors) / float(len(vectors))
                for col in range(len(features))
            ]
        test_vector = _transform_vector(test_row, features, scaler)
        ranked = sorted(
            (
                (_euclidean_distance(test_vector, centroid), label)
                for label, centroid in centroids.items()
            ),
            key=lambda item: (item[0], item[1]),
        )
        if not ranked:
            continue
        predicted = ranked[0][1]
        actual = dynamic_ml._norm_text(test_row.get(label_field))
        is_correct = predicted == actual
        if is_correct:
            correct += 1
        predictions.append(
            {
                "target": target_name,
                "feature_set": feature_set_name,
                "package_name": dynamic_ml._norm_text(test_row.get("package_name")),
                "app_label": dynamic_ml._norm_text(test_row.get("app_label")),
                "actual_label": actual,
                "predicted_label": predicted,
                "correct": 1 if is_correct else 0,
                "nearest_label_distance": ranked[0][0],
            }
        )
    accuracy = (float(correct) / float(len(predictions))) if predictions else None
    ci_low = None
    ci_high = None
    if predictions:
        if exact_ci:
            from scipy.stats import binomtest

            ci = binomtest(correct, len(predictions)).proportion_ci(confidence_level=0.95, method="exact")
            ci_low = float(ci.low)
            ci_high = float(ci.high)
        else:
            ci_low, ci_high = _wilson_proportion_ci(correct, len(predictions))
    summary = {
        "target": target_name,
        "feature_set": feature_set_name,
        "samples": len(predictions),
        "correct": correct,
        "accuracy": accuracy,
        "accuracy_ci_low": ci_low,
        "accuracy_ci_high": ci_high,
        "classes_observed": ", ".join(label_set),
        "notes": note,
    }
    return predictions, summary


def _wilson_proportion_ci(successes: int, total: int, *, z: float = 1.96) -> tuple[float | None, float | None]:
    if total <= 0:
        return None, None
    p_hat = float(successes) / float(total)
    denom = 1.0 + (z * z / float(total))
    centre = p_hat + (z * z / (2.0 * float(total)))
    margin = z * math.sqrt((p_hat * (1.0 - p_hat) + (z * z / (4.0 * float(total)))) / float(total))
    return max(0.0, (centre - margin) / denom), min(1.0, (centre + margin) / denom)


def _feature_separation_scores(
    rows: Sequence[Mapping[str, Any]],
    *,
    label_field: str,
    target_name: str,
    features: Sequence[str],
    feature_set_name: str,
) -> list[dict[str, Any]]:
    usable = [row for row in rows if dynamic_ml._norm_text(row.get(label_field))]
    labels = sorted({dynamic_ml._norm_text(row.get(label_field)) for row in usable if dynamic_ml._norm_text(row.get(label_field))})
    if len(usable) < 3 or len(labels) < 2:
        return []

    out: list[dict[str, Any]] = []
    for feature in features:
        overall_values = [float(row.get(feature) or 0.0) for row in usable]
        overall_mean = sum(overall_values) / float(len(overall_values))
        between = 0.0
        within = 0.0
        for label in labels:
            class_values = [float(row.get(feature) or 0.0) for row in usable if dynamic_ml._norm_text(row.get(label_field)) == label]
            if not class_values:
                continue
            class_mean = sum(class_values) / float(len(class_values))
            between += len(class_values) * ((class_mean - overall_mean) ** 2)
            within += sum((value - class_mean) ** 2 for value in class_values)
        score = between / within if within > 1e-12 else (between if between > 0 else 0.0)
        if score >= 1.5:
            note = "strong separation"
        elif score >= 0.5:
            note = "moderate separation"
        elif score > 0:
            note = "weak separation"
        else:
            note = "no observed separation"
        out.append(
            {
                "target": target_name,
                "feature_name": feature,
                "importance_score": score,
                "interpretation": f"{feature_set_name}: {note}",
            }
        )
    out.sort(key=lambda row: float(row.get("importance_score") or 0.0), reverse=True)
    return out


def _build_classification_outputs(
    app_rollups: Sequence[Mapping[str, Any]],
    *,
    exact_ci: bool = True,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    summaries: list[dict[str, Any]] = []
    predictions: list[dict[str, Any]] = []
    feature_scores: list[dict[str, Any]] = []

    target_specs = (
        (
            "profile_key",
            "profile_key_fused",
            FUSED_MODEL_FEATURES,
            "fused_static_runtime",
            "leave-one-out nearest-centroid over robust-scaled fused static+runtime features",
        ),
        (
            "profile_key",
            "profile_key_runtime_only",
            RUNTIME_ONLY_MODEL_FEATURES,
            "runtime_only",
            "leave-one-out nearest-centroid over robust-scaled runtime-only features",
        ),
        (
            "risk_bucket",
            "risk_bucket_runtime_only",
            RUNTIME_ONLY_MODEL_FEATURES,
            "runtime_only",
            "leave-one-out nearest-centroid over robust-scaled runtime-only features to avoid static-grade leakage",
        ),
    )
    for label_field, target_name, features, feature_set_name, note in target_specs:
        augmented_rows: list[dict[str, Any]] = []
        for row in app_rollups:
            record = dict(row)
            if label_field == "risk_bucket":
                record[label_field] = _risk_bucket(row)
            augmented_rows.append(record)
        pred_rows, summary = _nearest_centroid_loocv(
            augmented_rows,
            label_field=label_field,
            target_name=target_name,
            features=features,
            feature_set_name=feature_set_name,
            note=note,
            exact_ci=exact_ci,
        )
        predictions.extend(pred_rows)
        summaries.append(summary)
        feature_scores.extend(
            _feature_separation_scores(
                augmented_rows,
                label_field=label_field,
                target_name=target_name,
                features=features,
                feature_set_name=feature_set_name,
            )
        )
    return summaries, predictions, feature_scores


def _build_findings_markdown(
    summary: Mapping[str, Any],
    app_rollups: Sequence[Mapping[str, Any]],
    strict_exact_rollups: Sequence[Mapping[str, Any]],
    sample_hygiene_rows: Sequence[Mapping[str, Any]],
    correlations: Sequence[Mapping[str, Any]],
    priority_rows: Sequence[Mapping[str, Any]],
    priority_stability_rows: Sequence[Mapping[str, Any]],
    classification_rows: Sequence[Mapping[str, Any]],
    feature_scores: Sequence[Mapping[str, Any]],
) -> str:
    lines: list[str] = []
    lines.append("# Multimodal Static + Runtime Findings")
    lines.append("")
    lines.append("This report fuses latest static risk surfaces with governed runtime PCAP/domain/TLS behavior. It remains payload-free and read-only.")
    lines.append("")
    lines.append("## Coverage")
    lines.append("")
    lines.append(f"- Fused runs: {summary.get('fused_runs', 0)}")
    lines.append(f"- Stats-eligible fused runs: {summary.get('stats_eligible_fused_runs', 0)}")
    lines.append(f"- Apps with fused rollups: {summary.get('apps_with_fused_rollups', 0)}")
    lines.append(f"- Exact static matches: {summary.get('exact_static_matches', 0)}")
    lines.append(f"- Package-latest static fallbacks: {summary.get('package_latest_static_fallbacks', 0)}")
    lines.append(f"- Strict exact-match apps: {summary.get('strict_exact_apps_with_rollups', 0)}")
    lines.append(f"- Fused claim posture: {summary.get('fused_claim_posture', 'insufficient_alignment')}")
    lines.append("")
    if int(summary.get("strict_exact_apps_with_rollups", 0) or 0) == 0:
        lines.append("## Current Sample Warning")
        lines.append("")
        lines.append("- There are no strict exact-match current static/dynamic app rollups in this snapshot.")
        lines.append("- All fused app-level results in this report are package-latest fallback interpretations against newer static surfaces.")
        lines.append("- Treat these results as governed and comparable within this report, but not as exact current-build-aligned fusion.")
        lines.append("")
    fallback_apps = [row for row in sample_hygiene_rows if dynamic_ml._norm_text(row.get("recapture_needed")) == "yes"]
    if fallback_apps:
        lines.append("## Static / Runtime Alignment Gaps")
        lines.append("")
        for row in fallback_apps[:8]:
            lines.append(
                f"- {row.get('app_label')}: stats_eligible={row.get('stats_eligible_runs')}, "
                f"exact={row.get('exact_match_runs')}, fallback={row.get('fallback_runs')}, "
                f"dynamic_static_runs={row.get('observed_dynamic_static_run_ids')}, "
                f"latest_static_surface={row.get('latest_static_surface_run_id')} "
                f"({row.get('recommendation')})"
            )
        lines.append("")
    lines.append("## Priority Apps")
    lines.append("")
    for row in priority_rows[:5]:
        lines.append(
            f"- {row.get('app_label')}: fused={row.get('fused_pressure_score')}, "
            f"quadrant={row.get('risk_behavior_quadrant')}, "
            f"static_findings={row.get('static_findings_total')}, "
            f"JA4 median={row.get('median_unique_ja4_count')}, "
            f"domains median={row.get('median_domain_count')}"
        )
    lines.append("")
    if priority_stability_rows:
        lines.append("## Priority Stability")
        lines.append("")
        for row in priority_stability_rows[:5]:
            lines.append(
                f"- {row.get('app_label')}: observed_rank={row.get('observed_rank')}, "
                f"bootstrap_rank95=[{row.get('rank_ci_low')}, {row.get('rank_ci_high')}], "
                f"top1_prob={row.get('top1_probability')}, top3_prob={row.get('top3_probability')}, "
                f"high_priority_prob={row.get('high_priority_probability')} ({row.get('stability_note')})"
            )
        lines.append("")
    if strict_exact_rollups:
        lines.append("## Strict Exact-Match Subset")
        lines.append("")
        for row in strict_exact_rollups[:5]:
            lines.append(
                f"- {row.get('app_label')}: runs={row.get('runs_total')}, exact_fraction={row.get('exact_match_fraction')}, "
                f"fused={row.get('fused_pressure_score')}, quadrant={row.get('risk_behavior_quadrant')}"
            )
        lines.append("")
    lines.append("## Strongest Static / Runtime Correlations")
    lines.append("")
    for row in correlations[:5]:
        lines.append(
            f"- {row.get('static_metric')} vs {row.get('dynamic_metric')}: "
            f"rho={row.get('spearman_rho')}, "
            f"bootstrap95=[{row.get('rho_bootstrap_ci_low')}, {row.get('rho_bootstrap_ci_high')}], "
            f"perm_p={row.get('permutation_p_value')}, n={row.get('apps_compared')}, "
            f"{row.get('interpretation')} ({row.get('stability_note')})"
        )
    lines.append("")
    lines.append("## Supervised Evaluation")
    lines.append("")
    for row in classification_rows:
        lines.append(
            f"- {row.get('target')}: samples={row.get('samples')}, correct={row.get('correct')}, "
            f"accuracy={row.get('accuracy')} "
            f"[95% exact CI {row.get('accuracy_ci_low')}..{row.get('accuracy_ci_high')}], "
            f"classes={row.get('classes_observed')}, notes={row.get('notes')}"
        )
    lines.append("")
    if feature_scores:
        lines.append("## Strongest Separating Fused Features")
        lines.append("")
        for row in feature_scores[:6]:
            lines.append(
                f"- {row.get('target')} / {row.get('feature_name')}: score={row.get('importance_score')}, {row.get('interpretation')}"
            )
        lines.append("")
    lines.append("## Caveats")
    lines.append("")
    lines.append("- Latest static surfaces are used for fusion; they are matched exactly by static_run_id when possible, otherwise by package-latest fallback.")
    lines.append("- Cross-app correlations are reported as descriptive effect sizes only; the app-level sample is small, so these should not be treated as stable population estimates.")
    lines.append("- Leave-one-out classification over 10 apps is exploratory model-checking, not a production-grade generalization claim.")
    lines.append("- TLS/domain/service behavior remains descriptive; it complements static risk posture but does not prove maliciousness.")
    lines.append("- Low-signal and supplemental runs remain visible but do not override governance/countability semantics.")
    return "\n".join(lines) + "\n"


def generate_report(
    *,
    packages: Sequence[str] | None = None,
    output_dir: Path | None = None,
    recompute_exact_tls: bool = False,
) -> dict[str, Any]:
    package_filter = list(packages or [])
    output_root = output_dir or _default_output_dir()
    output_root.mkdir(parents=True, exist_ok=True)

    run_rows = dynamic_ml._load_run_rows(package_filter)
    domain_rows = dynamic_ml._load_domain_service_rows(package_filter)
    service_by_run, _ = dynamic_ml._aggregate_service_stats(domain_rows)
    feature_rows, _ = dynamic_ml._build_run_feature_matrix(
        run_rows,
        service_by_run,
        recompute_exact_tls=recompute_exact_tls,
    )
    static_rows = _load_static_surfaces(package_filter)
    fused_run_rows = _build_fused_run_rows(feature_rows, static_rows)
    app_rollups = _build_fused_app_rollups(fused_run_rows)
    strict_exact_rollups = _build_strict_exact_app_rollups(fused_run_rows)
    sample_hygiene_rows = _build_sample_hygiene_rows(fused_run_rows)
    fallback_detail_rows = _build_fallback_detail_rows(fused_run_rows)
    correlations = _build_correlation_rows(app_rollups)
    priority_rows = _build_priority_rows(app_rollups)
    priority_stability_rows = _bootstrap_priority_stability(fused_run_rows, priority_rows, sample_scope="all_governed")
    strict_exact_priority_rows = _build_priority_rows(strict_exact_rollups)
    strict_exact_priority_stability_rows = _bootstrap_priority_stability(
        _filter_fused_rows_by_match_mode(fused_run_rows, allowed_modes={"exact_latest"}),
        strict_exact_priority_rows,
        sample_scope="strict_exact",
    )
    similarity_rows, cluster_rows = _build_similarity_outputs(app_rollups)
    classification_rows, classification_predictions, feature_scores = _build_classification_outputs(app_rollups)

    dynamic_ml._write_csv(output_root / "fused_run_feature_matrix.csv", fused_run_rows, FUSED_RUN_FIELDS)
    dynamic_ml._write_csv(output_root / "fused_app_rollup.csv", app_rollups, APP_ROLLUP_FIELDS)
    dynamic_ml._write_csv(output_root / "strict_exact_app_rollup.csv", strict_exact_rollups, APP_ROLLUP_FIELDS)
    dynamic_ml._write_csv(output_root / "sample_hygiene_summary.csv", sample_hygiene_rows, SAMPLE_HYGIENE_FIELDS)
    dynamic_ml._write_csv(output_root / "fallback_run_details.csv", fallback_detail_rows, FALLBACK_DETAIL_FIELDS)
    dynamic_ml._write_csv(output_root / "static_dynamic_correlations.csv", correlations, CORRELATION_FIELDS)
    dynamic_ml._write_csv(output_root / "priority_candidates.csv", priority_rows, PRIORITY_FIELDS)
    dynamic_ml._write_csv(output_root / "priority_stability.csv", priority_stability_rows, PRIORITY_STABILITY_FIELDS)
    dynamic_ml._write_csv(output_root / "strict_exact_priority_candidates.csv", strict_exact_priority_rows, PRIORITY_FIELDS)
    dynamic_ml._write_csv(output_root / "strict_exact_priority_stability.csv", strict_exact_priority_stability_rows, PRIORITY_STABILITY_FIELDS)
    dynamic_ml._write_csv(output_root / "fused_app_similarity.csv", similarity_rows, SIMILARITY_FIELDS)
    dynamic_ml._write_csv(output_root / "fused_app_clusters.csv", cluster_rows, CLUSTER_FIELDS)
    dynamic_ml._write_csv(output_root / "classification_summary.csv", classification_rows, CLASSIFICATION_FIELDS)
    dynamic_ml._write_csv(output_root / "classification_predictions.csv", classification_predictions, CLASSIFICATION_PREDICTIONS_FIELDS)
    dynamic_ml._write_csv(output_root / "feature_separation_scores.csv", feature_scores, FEATURE_IMPORTANCE_FIELDS)

    sample_hygiene_state = _sample_hygiene_state(sample_hygiene_rows)
    summary = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "packages_filtered": sorted({dynamic_ml._norm_text(value).lower() for value in package_filter if dynamic_ml._norm_text(value)}) or None,
        "fused_runs": len(fused_run_rows),
        "stats_eligible_fused_runs": sum(1 for row in fused_run_rows if dynamic_ml._safe_int(row.get("stats_eligible")) == 1),
        "apps_with_fused_rollups": len(app_rollups),
        "strict_exact_apps_with_rollups": len(strict_exact_rollups),
        "sample_hygiene_state": sample_hygiene_state,
        "fused_claim_posture": _fused_claim_posture(sample_hygiene_state),
        "exact_static_matches": sum(1 for row in fused_run_rows if dynamic_ml._norm_text(row.get("static_match_mode")) == "exact_latest"),
        "package_latest_static_fallbacks": sum(1 for row in fused_run_rows if dynamic_ml._norm_text(row.get("static_match_mode")) == "package_latest_fallback"),
        "missing_static_surface_rows": sum(1 for row in fused_run_rows if dynamic_ml._norm_text(row.get("static_match_mode")) == "missing_static_surface"),
        "apps_requiring_recapture": sum(1 for row in sample_hygiene_rows if dynamic_ml._norm_text(row.get("recapture_needed")) == "yes"),
        "fallback_only_apps": sum(1 for row in sample_hygiene_rows if dynamic_ml._norm_text(row.get("sample_hygiene")) == "fallback_only"),
        "high_priority_apps": [row.get("package_name") for row in priority_rows if dynamic_ml._norm_text(row.get("priority_band")) == "high"],
        "top_priority_app": priority_rows[0].get("package_name") if priority_rows else None,
        "top_priority_app_stability": priority_stability_rows[0] if priority_stability_rows else None,
        "classification_targets": {
            row["target"]: {
                "samples": row.get("samples"),
                "accuracy": row.get("accuracy"),
                "accuracy_ci_low": row.get("accuracy_ci_low"),
                "accuracy_ci_high": row.get("accuracy_ci_high"),
                "classes_observed": row.get("classes_observed"),
            }
            for row in classification_rows
        },
        "output_files": {
            "summary_json": str((output_root / "summary.json").resolve()),
            "fused_run_feature_matrix_csv": str((output_root / "fused_run_feature_matrix.csv").resolve()),
            "fused_app_rollup_csv": str((output_root / "fused_app_rollup.csv").resolve()),
            "strict_exact_app_rollup_csv": str((output_root / "strict_exact_app_rollup.csv").resolve()),
            "sample_hygiene_summary_csv": str((output_root / "sample_hygiene_summary.csv").resolve()),
            "fallback_run_details_csv": str((output_root / "fallback_run_details.csv").resolve()),
            "static_dynamic_correlations_csv": str((output_root / "static_dynamic_correlations.csv").resolve()),
            "priority_candidates_csv": str((output_root / "priority_candidates.csv").resolve()),
            "priority_stability_csv": str((output_root / "priority_stability.csv").resolve()),
            "strict_exact_priority_candidates_csv": str((output_root / "strict_exact_priority_candidates.csv").resolve()),
            "strict_exact_priority_stability_csv": str((output_root / "strict_exact_priority_stability.csv").resolve()),
            "fused_app_similarity_csv": str((output_root / "fused_app_similarity.csv").resolve()),
            "fused_app_clusters_csv": str((output_root / "fused_app_clusters.csv").resolve()),
            "classification_summary_csv": str((output_root / "classification_summary.csv").resolve()),
            "classification_predictions_csv": str((output_root / "classification_predictions.csv").resolve()),
            "feature_separation_scores_csv": str((output_root / "feature_separation_scores.csv").resolve()),
            "multimodal_findings_md": str((output_root / "multimodal_findings.md").resolve()),
        },
    }
    (output_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (output_root / "multimodal_findings.md").write_text(
        _build_findings_markdown(
            summary,
            app_rollups,
            strict_exact_rollups,
            sample_hygiene_rows,
            correlations,
            priority_rows,
            priority_stability_rows,
            classification_rows,
            feature_scores,
        ),
        encoding="utf-8",
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    summary = generate_report(
        packages=args.package,
        output_dir=output_dir,
        recompute_exact_tls=bool(args.recompute_exact_tls),
    )
    if args.stdout_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(json.dumps({"summary_json": summary["output_files"]["summary_json"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
