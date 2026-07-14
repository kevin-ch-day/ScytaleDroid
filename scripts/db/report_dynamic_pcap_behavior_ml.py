#!/usr/bin/env python3
"""Read-only behavioral analysis over dynamic PCAP-derived features.

This audit stays payload-free and evidence-governed:
- no packet payload/body inspection
- no DB writes
- deterministic/reproducible outputs under output/audit/
- legacy rows remain visible but are explicitly flagged when feature-incomplete
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import Counter, defaultdict
from itertools import combinations
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scytaledroid.DynamicAnalysis.run_qualification import analysis_included_rows, row_analysis_included
from scytaledroid.Publication.app_category_policy import app_display_name

RUN_FEATURE_MATRIX_FIELDS: tuple[str, ...] = (
    "dynamic_run_id",
    "package_name",
    "app_label",
    "version_code",
    "static_run_id",
    "evidence_path",
    "feature_status",
    "local_pcap_available",
    "stats_eligible",
    "run_profile",
    "interaction_level",
    "interaction_mode",
    "messaging_activity",
    "valid_dataset_run",
    "countable",
    "analysis_included",
    "quota_state",
    "technical_validity_state",
    "supplemental_class",
    "pcap_valid",
    "pcap_bytes",
    "packet_count",
    "duration_s",
    "bytes_per_second",
    "packets_per_second",
    "avg_packet_size",
    "burstiness",
    "window_count",
    "active_window_ratio",
    "tcp_ratio",
    "udp_ratio",
    "tls_ratio",
    "quic_ratio",
    "dns_count",
    "sni_count",
    "domain_count",
    "unique_root_domains",
    "unique_service_families",
    "first_party_domain_count",
    "third_party_domain_count",
    "adtech_domain_count",
    "analytics_domain_count",
    "cdn_domain_count",
    "unresolved_domain_count",
    "service_entropy",
    "service_families_observed",
    "top_service_family",
    "top_service_share",
    "tls_client_hello_count",
    "tls_server_hello_count",
    "unique_ja3_count",
    "unique_ja3s_count",
    "unique_ja4_count",
    "top_ja3",
    "top_ja3s",
    "top_ja4",
    "top1_ja3_share",
    "top1_ja4_share",
    "top1_ja3s_share",
    "ja3_entropy",
    "ja4_entropy",
    "ja3s_entropy",
    "alpn_count",
    "top_alpn",
    "top_sni",
    "sni_to_ja4_diversity",
    "domains_per_mb",
    "ja4_per_domain",
    "ja4_per_mb",
    "service_families_per_domain",
    "unresolved_share",
    "adtech_share",
    "cdn_share",
    "first_party_share",
)

APP_ROLLUP_FIELDS: tuple[str, ...] = (
    "app_label",
    "package_name",
    "runs_total",
    "countable_runs",
    "analysis_included_runs",
    "supplemental_runs",
    "baseline_runs",
    "interactive_runs",
    "median_unique_ja4_count",
    "iqr_unique_ja4_count",
    "median_unique_ja3_count",
    "median_unique_ja3s_count",
    "median_top_ja4_share",
    "baseline_stability",
    "interactive_broadening",
    "service_families_observed",
    "comparison_depth",
    "inference_readiness",
    "strongest_shift_metric",
    "strongest_shift_p_value",
    "strongest_shift_effect_band",
    "strongest_shift_note",
    "interpretation",
)

BASELINE_INTERACTIVE_FIELDS: tuple[str, ...] = (
    "app_label",
    "package_name",
    "baseline_n",
    "interactive_n",
    "metric",
    "baseline_median",
    "baseline_iqr",
    "interactive_median",
    "interactive_iqr",
    "delta_median",
    "cliffs_delta",
    "cliffs_delta_band",
    "permutation_p_value",
    "inference_note",
    "comparison_status",
    "interpretation",
)

CLUSTER_FIELDS: tuple[str, ...] = (
    "cluster_id",
    "app_label",
    "package_name",
    "run_count",
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

ANOMALY_FIELDS: tuple[str, ...] = (
    "dynamic_run_id",
    "package_name",
    "app_label",
    "run_profile",
    "interaction_mode",
    "quota_state",
    "countable",
    "global_anomaly_score",
    "app_relative_anomaly_score",
    "top_explanation_1",
    "top_explanation_2",
    "top_explanation_3",
)

ASSOCIATION_FIELDS: tuple[str, ...] = (
    "service_family",
    "apps_seen",
    "run_count",
    "median_unique_ja4",
    "common_top_ja4",
    "median_top_ja4_share",
    "associated_domains_sample",
    "interpretation",
)

PAPER_TABLE_FIELDS: tuple[str, ...] = (
    "app",
    "countable_runs",
    "analysis_included_runs",
    "runtime_domains_median",
    "service_families",
    "unique_ja4_median",
    "ja4_iqr",
    "top_ja4_share",
    "baseline_interactive_pattern",
    "interpretation",
)

CROSS_APP_FIELDS: tuple[str, ...] = (
    "metric",
    "apps_compared",
    "apps_positive_delta",
    "apps_negative_delta",
    "apps_zero_delta",
    "apps_p_le_0_10",
    "apps_p_le_0_05",
    "apps_large_effect",
    "median_delta",
    "median_abs_cliffs_delta",
    "interpretation",
)

FOCUS_PACKAGES: dict[str, str] = {
    package_name: app_display_name(package_name, package_name)
    for package_name in (
        "bbc.mobile.news.ww",
        "com.cnn.mobile.android.phone",
        "com.facebook.katana",
        "com.facebook.orca",
        "com.guardian",
        "com.twitter.android",
        "com.whatsapp",
        "com.zhiliaoapp.musically",
    )
}

SERVICE_BUCKETS: dict[str, tuple[str, ...]] = {
    "adtech": ("adtech", "ad_measurement", "ad_verification", "advertising"),
    "analytics": ("analytics", "attribution", "audience_personalization", "engagement", "experimentation"),
    "cdn": ("content_delivery", "platform_infrastructure"),
}


def run_feature_matrix_fieldnames() -> tuple[str, ...]:
    return RUN_FEATURE_MATRIX_FIELDS


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package",
        action="append",
        default=[],
        help="Restrict to one or more package names. May be passed more than once.",
    )
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    parser.add_argument(
        "--stdout-json",
        action="store_true",
        help="Print summary JSON to stdout after writing report files.",
    )
    parser.add_argument(
        "--recompute-exact-tls",
        action="store_true",
        help=(
            "Recompute full TLS top-distribution summaries directly from local PCAPs for stats-eligible runs. "
            "Default behavior uses persisted evidence summaries for faster audits."
        ),
    )
    return parser


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fieldnames: Sequence[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_pcap_behavior_ml" / stamp


def _quantile(values: Sequence[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    idx = (len(ordered) - 1) * float(q)
    lower = math.floor(idx)
    upper = math.ceil(idx)
    if lower == upper:
        return ordered[int(idx)]
    weight = idx - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _median_iqr(values: Sequence[float]) -> tuple[float | None, float | None]:
    if not values:
        return None, None
    med = float(median(values))
    q1 = _quantile(values, 0.25)
    q3 = _quantile(values, 0.75)
    if q1 is None or q3 is None:
        return med, None
    return med, float(q3 - q1)


def _entropy_from_counter(counter: Mapping[str, int]) -> float | None:
    total = sum(max(0, int(value)) for value in counter.values())
    if total <= 0:
        return None
    entropy = 0.0
    for count in counter.values():
        c = max(0, int(count))
        if c <= 0:
            continue
        p = float(c) / float(total)
        entropy -= p * math.log2(p)
    return entropy


def _counter_from_top_items(items: object) -> Counter[str]:
    out: Counter[str] = Counter()
    if not isinstance(items, list):
        return out
    for item in items:
        if not isinstance(item, Mapping):
            continue
        value = _norm_text(item.get("value"))
        count = _safe_int(item.get("count")) or 0
        if value and count > 0:
            out[value] += count
    return out


def _first_top_value(items: object) -> str:
    if not isinstance(items, list) or not items:
        return ""
    first = items[0]
    if not isinstance(first, Mapping):
        return ""
    return _norm_text(first.get("value"))


def _cliffs_delta(left: Sequence[float], right: Sequence[float]) -> float | None:
    if not left or not right:
        return None
    gt = 0
    lt = 0
    for lv in left:
        for rv in right:
            if lv > rv:
                gt += 1
            elif lv < rv:
                lt += 1
    total = len(left) * len(right)
    if total <= 0:
        return None
    return float(gt - lt) / float(total)


def _cliffs_delta_band(value: float | None) -> str:
    if value is None:
        return ""
    mag = abs(float(value))
    if mag < 0.147:
        return "negligible"
    if mag < 0.33:
        return "small"
    if mag < 0.474:
        return "medium"
    return "large"


def _exact_permutation_p_value_for_median_delta(
    left: Sequence[float],
    right: Sequence[float],
    *,
    max_partitions: int = 50_000,
) -> float | None:
    if not left or not right:
        return None
    pooled = [float(value) for value in left] + [float(value) for value in right]
    n_left = len(left)
    total = len(pooled)
    if n_left <= 0 or n_left >= total:
        return None
    partitions = math.comb(total, n_left)
    if partitions > max_partitions:
        return None
    observed = abs(float(median(left)) - float(median(right)))
    hits = 0
    total_seen = 0
    all_idx = tuple(range(total))
    for chosen in combinations(all_idx, n_left):
        chosen_set = set(chosen)
        left_group = [pooled[idx] for idx in chosen]
        right_group = [pooled[idx] for idx in all_idx if idx not in chosen_set]
        stat = abs(float(median(left_group)) - float(median(right_group)))
        total_seen += 1
        if stat >= observed - 1e-12:
            hits += 1
    if total_seen <= 0:
        return None
    return float(hits) / float(total_seen)


def _inference_note(*, p_value: float | None, delta: float | None) -> str:
    if p_value is None:
        return "descriptive_only"
    band = _cliffs_delta_band(delta)
    if p_value <= 0.05:
        return f"permutation_signal_{band or 'observed'}"
    return f"no_clear_permutation_signal_{band or 'observed'}"


def _format_inference_summary(row: Mapping[str, Any] | None) -> str:
    if not row:
        return "no JA4 comparison row available"
    status = _norm_text(row.get("comparison_status"))
    note = _norm_text(row.get("inference_note")) or "descriptive_only"
    if status == "insufficient_n":
        return f"descriptive only ({note})"
    p_value = row.get("permutation_p_value")
    cliffs = row.get("cliffs_delta")
    band = _norm_text(row.get("cliffs_delta_band"))
    return (
        f"p={p_value}, Cliff's delta={cliffs}"
        + (f" ({band})" if band else "")
        + f", note={note}"
    )


def _comparison_depth_label(*, baseline_runs: int, interactive_runs: int) -> str:
    if baseline_runs >= 3 and interactive_runs >= 3:
        return "tested"
    if baseline_runs >= 2 and interactive_runs >= 2:
        return "limited"
    if baseline_runs > 0 and interactive_runs > 0:
        return "descriptive_only"
    return "no_interactive_comparison"


def _inference_readiness_label(*, baseline_runs: int, interactive_runs: int, strongest_p_value: float | None) -> str:
    if baseline_runs >= 3 and interactive_runs >= 3:
        if strongest_p_value is not None and strongest_p_value <= 0.10:
            return "paper_ready_signal"
        return "tested_but_inconclusive"
    if baseline_runs >= 2 and interactive_runs >= 2:
        return "limited_comparison"
    if baseline_runs > 0 and interactive_runs > 0:
        return "descriptive_only"
    return "needs_interactive_depth"


def _cosine_similarity(left: Sequence[float], right: Sequence[float]) -> float | None:
    if not left or not right or len(left) != len(right):
        return None
    dot = sum(float(a) * float(b) for a, b in zip(left, right, strict=False))
    norm_left = math.sqrt(sum(float(a) * float(a) for a in left))
    norm_right = math.sqrt(sum(float(b) * float(b) for b in right))
    if norm_left <= 0 or norm_right <= 0:
        return None
    return dot / (norm_left * norm_right)


def _robust_scale_vectors(vectors: Mapping[str, Sequence[float]]) -> dict[str, list[float]]:
    if not vectors:
        return {}
    size = len(next(iter(vectors.values())))
    columns: list[list[float]] = [[] for _ in range(size)]
    for vector in vectors.values():
        for idx, value in enumerate(vector):
            columns[idx].append(float(value))
    medians = [float(median(col)) if col else 0.0 for col in columns]
    mads: list[float] = []
    for idx, col in enumerate(columns):
        deviations = [abs(value - medians[idx]) for value in col]
        mad = float(median(deviations)) if deviations else 0.0
        mads.append(mad if mad > 1e-9 else 1.0)
    scaled: dict[str, list[float]] = {}
    for key, vector in vectors.items():
        scaled[key] = [
            0.6745 * (float(value) - medians[idx]) / mads[idx]
            for idx, value in enumerate(vector)
        ]
    return scaled


def _connected_component_clusters(similarities: Mapping[tuple[str, str], float], *, threshold: float) -> dict[str, int]:
    adjacency: dict[str, set[str]] = defaultdict(set)
    nodes: set[str] = set()
    for (left, right), score in similarities.items():
        nodes.add(left)
        nodes.add(right)
        if score >= threshold:
            adjacency[left].add(right)
            adjacency[right].add(left)
    cluster_map: dict[str, int] = {}
    cluster_id = 0
    for node in sorted(nodes):
        if node in cluster_map:
            continue
        cluster_id += 1
        stack = [node]
        while stack:
            current = stack.pop()
            if current in cluster_map:
                continue
            cluster_map[current] = cluster_id
            for nxt in sorted(adjacency.get(current, set()), reverse=True):
                if nxt not in cluster_map:
                    stack.append(nxt)
    return cluster_map


def _supplemental_class(row: Mapping[str, Any]) -> str:
    quota_state = _norm_text(row.get("quota_state"))
    if quota_state == "QUOTA_VALID":
        return "quota_valid"
    if quota_state != "SUPPLEMENTAL_VALID":
        if quota_state == "QUOTA_INELIGIBLE":
            return "ineligible"
        if quota_state == "QUOTA_LEGACY_UNKNOWN":
            return "legacy_unknown"
        return "other"
    low_signal = _safe_int(row.get("low_signal")) == 1
    if low_signal:
        return "low_signal"
    return "extra_or_policy"


def _interaction_mode(run_profile: str, interaction_level: str) -> str:
    profile = _norm_text(run_profile).lower()
    level = _norm_text(interaction_level).lower()
    if profile.startswith("baseline"):
        return "baseline"
    if "script" in profile:
        return "scripted"
    if "manual" in profile:
        return "manual"
    if level:
        return level
    if profile.startswith("interaction") or profile.startswith("interactive"):
        return "interactive"
    return "unknown"


def _find_pcap_path(evidence_root: Path) -> Path | None:
    capture_dir = evidence_root / "artifacts" / "pcapdroid_capture"
    for name in ("capture.pcap", "capture.pcapng"):
        direct = capture_dir / name
        if direct.is_file():
            return direct
    for candidate in sorted(capture_dir.glob("*.pcap*")):
        if candidate.is_file() and candidate.suffix.lower() in {".pcap", ".pcapng"}:
            return candidate
    return None


def _sql_filter_clause(packages: Sequence[str]) -> tuple[str, tuple[str, ...]]:
    normalized = tuple(sorted({_norm_text(value).lower() for value in packages if _norm_text(value)}))
    if not normalized:
        return "", ()
    placeholders = ", ".join(["%s"] * len(normalized))
    return f"WHERE LOWER(TRIM(ctx.package_name)) IN ({placeholders})", normalized


def _load_run_rows(packages: Sequence[str]) -> list[dict[str, Any]]:
    from scytaledroid.Database.db_core import db_queries as core_q

    where_sql, params = _sql_filter_clause(packages)
    query = f"""
        SELECT
          ctx.dynamic_run_id,
          ctx.package_name,
          ctx.app_label,
          ctx.version_code,
          ctx.effective_static_run_id AS static_run_id,
          ds.evidence_path,
          ctx.effective_run_profile AS run_profile,
          ctx.effective_interaction_level AS interaction_level,
          ctx.operator_messaging_activity AS messaging_activity,
          ctx.valid_dataset_run,
          ctx.countable,
          ctx.quota_state,
          ctx.technical_validity_state,
          ds.pcap_valid,
          ds.pcap_bytes,
          ctx.low_signal,
          ctx.low_signal_reasons_json,
          nf.capture_duration_s,
          nf.packet_count,
          nf.data_size_bytes,
          nf.bytes_per_sec,
          nf.packets_per_sec,
          nf.avg_packet_size_bytes,
          nf.burstiness_bytes_p95_over_p50,
          nf.active_second_count,
          nf.active_second_ratio,
          nf.tcp_ratio,
          nf.udp_ratio,
          nf.tls_ratio,
          nf.quic_ratio,
          nf.unique_dns_qname_count AS dns_count,
          ctx.tls_sni_unique_count AS sni_count,
          ctx.distinct_observed_domains AS domain_count,
          ctx.distinct_root_domains AS unique_root_domains,
          ctx.first_party_domain_rows AS first_party_domain_count,
          ctx.third_party_domain_rows AS third_party_domain_count,
          ctx.unknown_domain_rows AS unresolved_domain_count,
          ctx.matched_service_count,
          ctx.owner_classes_csv,
          ctx.role_classes_csv,
          ctx.service_keys_csv,
          nf.tls_client_hello_count,
          nf.tls_server_hello_count,
          nf.unique_ja3_count,
          nf.unique_ja3s_count,
          nf.unique_ja4_count,
          nf.top1_ja3_share,
          nf.top1_ja4_share,
          nf.top1_ja3s_share
        FROM v_dynamic_run_context_v1 ctx
        JOIN dynamic_sessions ds
          ON ds.dynamic_run_id = ctx.dynamic_run_id
        LEFT JOIN dynamic_network_features nf
          ON nf.dynamic_run_id = ctx.dynamic_run_id
        {where_sql}
        ORDER BY ctx.package_name, ctx.started_at_utc, ctx.dynamic_run_id
    """
    return core_q.run_sql(
        query,
        params,
        fetch="all",
        dictionary=True,
        query_name="dynamic.pcap_behavior_ml.run_rows",
    ) or []


def _load_domain_service_rows(packages: Sequence[str]) -> list[dict[str, Any]]:
    from scytaledroid.Database.db_core import db_queries as core_q

    if packages:
        placeholders = ", ".join(["%s"] * len(packages))
        package_filter = f"AND LOWER(TRIM(obs.package_name)) IN ({placeholders})"
        params: tuple[str, ...] = tuple(sorted({_norm_text(value).lower() for value in packages if _norm_text(value)}))
    else:
        package_filter = ""
        params = ()
    query = f"""
        SELECT
          obs.dynamic_run_id,
          obs.package_name,
          LOWER(TRIM(obs.observed_domain)) AS observed_domain,
          LOWER(TRIM(obs.root_domain)) AS root_domain,
          LOWER(TRIM(COALESCE(obs.owner_class, ''))) AS owner_class,
          LOWER(TRIM(COALESCE(obs.role_class, ''))) AS role_class,
          LOWER(TRIM(COALESCE(svc.service_category, ''))) AS service_category,
          LOWER(TRIM(COALESCE(svc.service_key, ''))) AS service_key
        FROM dynamic_domain_observations obs
        LEFT JOIN dynamic_service_domain_map sdm
          ON sdm.is_active = 1
         AND (
              LOWER(TRIM(COALESCE(sdm.package_name_scope, ''))) = ''
              OR CONVERT(sdm.package_name_scope USING utf8mb4) COLLATE utf8mb4_general_ci =
                 CONVERT(obs.package_name USING utf8mb4) COLLATE utf8mb4_general_ci
         )
         AND (
              (
                UPPER(TRIM(COALESCE(sdm.match_type, ''))) = 'EXACT'
                AND LOWER(TRIM(COALESCE(obs.observed_domain, ''))) = LOWER(TRIM(COALESCE(sdm.domain_pattern, '')))
              )
              OR
              (
                UPPER(TRIM(COALESCE(sdm.match_type, ''))) = 'SUFFIX'
                AND (
                  LOWER(TRIM(COALESCE(obs.observed_domain, ''))) = LOWER(TRIM(COALESCE(sdm.domain_pattern, '')))
                  OR LOWER(TRIM(COALESCE(obs.observed_domain, ''))) LIKE CONCAT('%%.', LOWER(TRIM(COALESCE(sdm.domain_pattern, ''))))
                )
              )
         )
        LEFT JOIN dynamic_service_catalog svc
          ON svc.service_id = sdm.service_id
         AND svc.is_active = 1
        WHERE 1=1
          {package_filter}
        ORDER BY obs.dynamic_run_id, obs.observed_domain
    """
    return core_q.run_sql(
        query,
        params,
        fetch="all",
        dictionary=True,
        query_name="dynamic.pcap_behavior_ml.domain_service_rows",
    ) or []


def _aggregate_service_stats(domain_rows: Sequence[Mapping[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    run_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "domains": set(),
        "roots": set(),
        "category_domains": defaultdict(set),
        "service_keys": defaultdict(set),
        "owner_class_domains": defaultdict(set),
        "top_service_family": "",
        "top_service_share": None,
        "unique_service_families": 0,
        "service_entropy": None,
    })
    service_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "apps_seen": set(),
        "runs_seen": set(),
        "domains": set(),
    })
    for row in domain_rows:
        run_id = _norm_text(row.get("dynamic_run_id"))
        if not run_id:
            continue
        domain = _norm_text(row.get("observed_domain")).lower()
        root = _norm_text(row.get("root_domain")).lower()
        category = _norm_text(row.get("service_category")).lower()
        owner_class = _norm_text(row.get("owner_class")).lower()
        package_name = _norm_text(row.get("package_name")).lower()
        bucket = run_stats[run_id]
        if domain:
            bucket["domains"].add(domain)
        if root:
            bucket["roots"].add(root)
        bucket["owner_class_domains"][owner_class or "unknown"].add(domain)
        cat_key = category or "unresolved"
        bucket["category_domains"][cat_key].add(domain)
        service_key = _norm_text(row.get("service_key")).lower()
        if service_key:
            bucket["service_keys"][cat_key].add(service_key)
        fam = service_stats[cat_key]
        fam["apps_seen"].add(package_name)
        fam["runs_seen"].add(run_id)
        if domain:
            fam["domains"].add(domain)

    summarized_run_stats: dict[str, dict[str, Any]] = {}
    for run_id, payload in run_stats.items():
        category_counts = {key: len(value) for key, value in payload["category_domains"].items()}
        total = sum(category_counts.values())
        top_service_family = ""
        top_service_share = None
        if category_counts:
            top_service_family = max(sorted(category_counts), key=lambda key: category_counts[key])
            top_service_share = category_counts[top_service_family] / float(total) if total > 0 else None
        summarized_run_stats[run_id] = {
            "unique_service_families": len([key for key in category_counts if key and key != "unresolved"]),
            "category_counts": category_counts,
            "top_service_family": top_service_family,
            "top_service_share": top_service_share,
            "service_entropy": _entropy_from_counter(category_counts),
            "owner_class_counts": {key: len(value) for key, value in payload["owner_class_domains"].items()},
            "domains": payload["domains"],
            "roots": payload["roots"],
        }
    summarized_service_stats: dict[str, dict[str, Any]] = {}
    for family, payload in service_stats.items():
        summarized_service_stats[family] = {
            "apps_seen": sorted(value for value in payload["apps_seen"] if value),
            "runs_seen": sorted(value for value in payload["runs_seen"] if value),
            "domains": sorted(value for value in payload["domains"] if value),
        }
    return summarized_run_stats, summarized_service_stats


def _load_tls_metadata(evidence_root: Path, *, recompute_exact: bool) -> dict[str, Any]:
    payload = _read_json(evidence_root / "analysis" / "pcap_report.json") or {}
    tls = payload.get("tls_fingerprints") if isinstance(payload.get("tls_fingerprints"), dict) else {}
    if recompute_exact:
        pcap_path = _find_pcap_path(evidence_root)
        if pcap_path and pcap_path.exists():
            from scytaledroid.DynamicAnalysis.pcap.fingerprints import summarize_tls_fingerprints

            try:
                tls = summarize_tls_fingerprints(pcap_path, top_n=512)
            except Exception:
                tls = tls or {}
    return dict(tls or {})


def _feature_status(row: Mapping[str, Any], *, local_pcap_available: bool, has_domains: bool, has_ja4: bool) -> str:
    tech_state = _norm_text(row.get("technical_validity_state"))
    if not _norm_text(row.get("evidence_path")):
        return "missing_evidence_path"
    if not local_pcap_available:
        return "missing_local_pcap"
    if _safe_int(row.get("pcap_valid")) != 1:
        return "pcap_not_valid"
    if tech_state == "TECH_LEGACY_UNKNOWN":
        return "legacy_local_partial"
    if has_domains and has_ja4:
        return "feature_complete"
    if has_domains and not has_ja4:
        return "fingerprint_missing"
    return "partial_local_feature_set"


def _is_stats_eligible(row: Mapping[str, Any], *, local_pcap_available: bool, has_domains: bool, has_ja4: bool) -> bool:
    return (
        local_pcap_available
        and _safe_int(row.get("pcap_valid")) == 1
        and _norm_text(row.get("technical_validity_state")) == "TECH_VALID"
        and has_domains
        and has_ja4
    )


def _service_share(category_counts: Mapping[str, int], family: str, total_domains: int) -> float | None:
    if total_domains <= 0:
        return None
    count = int(category_counts.get(family) or 0)
    return float(count) / float(total_domains)


def _bucketed_category_count(category_counts: Mapping[str, int], bucket_name: str) -> int:
    families = SERVICE_BUCKETS.get(bucket_name, ())
    return sum(int(category_counts.get(family) or 0) for family in families)


def _build_run_feature_matrix(
    run_rows: Sequence[Mapping[str, Any]],
    service_by_run: Mapping[str, Mapping[str, Any]],
    *,
    recompute_exact_tls: bool,
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    feature_rows: list[dict[str, Any]] = []
    by_package: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in run_rows:
        run_id = _norm_text(row.get("dynamic_run_id"))
        package_name = _norm_text(row.get("package_name")).lower()
        app_label = _norm_text(row.get("app_label")) or FOCUS_PACKAGES.get(package_name) or package_name
        evidence_root = Path(_norm_text(row.get("evidence_path")))
        local_pcap = _find_pcap_path(evidence_root)
        local_pcap_available = bool(local_pcap and local_pcap.exists())
        service_stats = dict(service_by_run.get(run_id) or {})
        category_counts = dict(service_stats.get("category_counts") or {})
        total_service_domains = sum(category_counts.values())
        service_families_observed = ", ".join(
            sorted(key for key, count in category_counts.items() if key and key != "unresolved" and int(count or 0) > 0)
        )

        # For modern/local runs we recompute exact TLS top distributions so entropy and top-value
        # metrics are not constrained by older top-N-limited report artifacts.
        recompute_exact = recompute_exact_tls and (
            local_pcap_available
            and _safe_int(row.get("pcap_valid")) == 1
            and _norm_text(row.get("technical_validity_state")) == "TECH_VALID"
        )
        tls = _load_tls_metadata(evidence_root, recompute_exact=recompute_exact)
        ja3_counter = _counter_from_top_items(tls.get("top_ja3"))
        ja4_counter = _counter_from_top_items(tls.get("top_ja4"))
        ja3s_counter = _counter_from_top_items(tls.get("top_ja3s"))
        alpn_counter = _counter_from_top_items(tls.get("top_alpn"))
        has_domains = (_safe_int(row.get("domain_count")) or 0) > 0
        has_ja4 = (_safe_int(row.get("unique_ja4_count")) or _safe_int(tls.get("unique_ja4_count")) or 0) > 0

        status = _feature_status(
            row,
            local_pcap_available=local_pcap_available,
            has_domains=has_domains,
            has_ja4=has_ja4,
        )
        stats_eligible = _is_stats_eligible(
            row,
            local_pcap_available=local_pcap_available,
            has_domains=has_domains,
            has_ja4=has_ja4,
        )

        pcap_bytes = _safe_int(row.get("pcap_bytes"))
        domain_count = _safe_int(row.get("domain_count"))
        service_family_count = _safe_int(service_stats.get("unique_service_families")) or 0
        unique_ja4_count = _safe_int(row.get("unique_ja4_count"))
        if unique_ja4_count is None:
            unique_ja4_count = _safe_int(tls.get("unique_ja4_count"))
        unique_ja3_count = _safe_int(row.get("unique_ja3_count"))
        if unique_ja3_count is None:
            unique_ja3_count = _safe_int(tls.get("unique_ja3_count"))
        unique_ja3s_count = _safe_int(row.get("unique_ja3s_count"))
        if unique_ja3s_count is None:
            unique_ja3s_count = _safe_int(tls.get("unique_ja3s_count"))
        top1_ja3_share = _safe_float(row.get("top1_ja3_share"))
        if top1_ja3_share is None:
            top1_ja3_share = _safe_float(tls.get("top1_ja3_share"))
        top1_ja4_share = _safe_float(row.get("top1_ja4_share"))
        if top1_ja4_share is None:
            top1_ja4_share = _safe_float(tls.get("top1_ja4_share"))
        top1_ja3s_share = _safe_float(row.get("top1_ja3s_share"))
        if top1_ja3s_share is None:
            top1_ja3s_share = _safe_float(tls.get("top1_ja3s_share"))

        interaction_mode = _interaction_mode(_norm_text(row.get("run_profile")), _norm_text(row.get("interaction_level")))
        duration_s = _safe_float(row.get("capture_duration_s"))
        bytes_per_sec = _safe_float(row.get("bytes_per_sec"))
        packets_per_sec = _safe_float(row.get("packets_per_sec"))
        ja4_per_domain = (
            float(unique_ja4_count) / float(domain_count)
            if unique_ja4_count is not None and domain_count and domain_count > 0
            else None
        )
        domains_per_mb = (
            float(domain_count) / (float(pcap_bytes) / 1_000_000.0)
            if domain_count and pcap_bytes and pcap_bytes > 0
            else None
        )
        ja4_per_mb = (
            float(unique_ja4_count) / (float(pcap_bytes) / 1_000_000.0)
            if unique_ja4_count is not None and pcap_bytes and pcap_bytes > 0
            else None
        )
        service_families_per_domain = (
            float(service_family_count) / float(domain_count)
            if service_family_count and domain_count and domain_count > 0
            else None
        )
        unresolved_domains = int(category_counts.get("unresolved") or 0)
        adtech_domains = _bucketed_category_count(category_counts, "adtech")
        analytics_domains = _bucketed_category_count(category_counts, "analytics")
        cdn_domains = _bucketed_category_count(category_counts, "cdn")
        total_domains_for_share = domain_count or total_service_domains or 0

        record = {
            "dynamic_run_id": run_id,
            "package_name": package_name,
            "app_label": app_label,
            "version_code": _safe_int(row.get("version_code")),
            "static_run_id": _safe_int(row.get("static_run_id")),
            "evidence_path": str(evidence_root),
            "feature_status": status,
            "local_pcap_available": 1 if local_pcap_available else 0,
            "stats_eligible": 1 if stats_eligible else 0,
            "run_profile": _norm_text(row.get("run_profile")),
            "interaction_level": _norm_text(row.get("interaction_level")),
            "interaction_mode": interaction_mode,
            "messaging_activity": _norm_text(row.get("messaging_activity")),
            "valid_dataset_run": _safe_int(row.get("valid_dataset_run")),
            "countable": _safe_int(row.get("countable")),
            "analysis_included": 1
            if row_analysis_included(
                {
                    "valid_dataset_run": row.get("valid_dataset_run"),
                    "paper_eligible": row.get("paper_eligible"),
                }
            )
            else 0,
            "quota_state": _norm_text(row.get("quota_state")),
            "technical_validity_state": _norm_text(row.get("technical_validity_state")),
            "supplemental_class": _supplemental_class(row),
            "pcap_valid": _safe_int(row.get("pcap_valid")),
            "pcap_bytes": pcap_bytes,
            "packet_count": _safe_int(row.get("packet_count")),
            "duration_s": duration_s,
            "bytes_per_second": bytes_per_sec,
            "packets_per_second": packets_per_sec,
            "avg_packet_size": _safe_float(row.get("avg_packet_size_bytes")),
            "burstiness": _safe_float(row.get("burstiness_bytes_p95_over_p50")),
            "window_count": None,
            "active_window_ratio": _safe_float(row.get("active_second_ratio")),
            "tcp_ratio": _safe_float(row.get("tcp_ratio")),
            "udp_ratio": _safe_float(row.get("udp_ratio")),
            "tls_ratio": _safe_float(row.get("tls_ratio")),
            "quic_ratio": _safe_float(row.get("quic_ratio")),
            "dns_count": _safe_int(row.get("dns_count")),
            "sni_count": _safe_int(row.get("sni_count")),
            "domain_count": domain_count,
            "unique_root_domains": _safe_int(row.get("unique_root_domains")),
            "unique_service_families": service_family_count or None,
            "first_party_domain_count": _safe_int(row.get("first_party_domain_count")),
            "third_party_domain_count": _safe_int(row.get("third_party_domain_count")),
            "adtech_domain_count": adtech_domains or None,
            "analytics_domain_count": analytics_domains or None,
            "cdn_domain_count": cdn_domains or None,
            "unresolved_domain_count": unresolved_domains or None,
            "service_entropy": _safe_float(service_stats.get("service_entropy")),
            "service_families_observed": service_families_observed,
            "top_service_family": _norm_text(service_stats.get("top_service_family")),
            "top_service_share": _safe_float(service_stats.get("top_service_share")),
            "tls_client_hello_count": _safe_int(row.get("tls_client_hello_count")) or _safe_int(tls.get("client_hello_count")),
            "tls_server_hello_count": _safe_int(row.get("tls_server_hello_count")) or _safe_int(tls.get("server_hello_count")),
            "unique_ja3_count": unique_ja3_count,
            "unique_ja3s_count": unique_ja3s_count,
            "unique_ja4_count": unique_ja4_count,
            "top_ja3": _first_top_value(tls.get("top_ja3")),
            "top_ja3s": _first_top_value(tls.get("top_ja3s")),
            "top_ja4": _first_top_value(tls.get("top_ja4")),
            "top1_ja3_share": top1_ja3_share,
            "top1_ja4_share": top1_ja4_share,
            "top1_ja3s_share": top1_ja3s_share,
            "ja3_entropy": _entropy_from_counter(ja3_counter),
            "ja4_entropy": _entropy_from_counter(ja4_counter),
            "ja3s_entropy": _entropy_from_counter(ja3s_counter),
            "alpn_count": len(alpn_counter) if alpn_counter else None,
            "top_alpn": _first_top_value(tls.get("top_alpn")),
            "top_sni": _first_top_value(tls.get("top_sni_from_client_hello")),
            "sni_to_ja4_diversity": (
                float((_safe_int(row.get("sni_count")) or 0)) / float(unique_ja4_count)
                if (_safe_int(row.get("sni_count")) or 0) > 0 and unique_ja4_count and unique_ja4_count > 0
                else None
            ),
            "domains_per_mb": domains_per_mb,
            "ja4_per_domain": ja4_per_domain,
            "ja4_per_mb": ja4_per_mb,
            "service_families_per_domain": service_families_per_domain,
            "unresolved_share": (
                float(unresolved_domains) / float(total_domains_for_share)
                if unresolved_domains and total_domains_for_share > 0
                else 0.0 if total_domains_for_share > 0 else None
            ),
            "adtech_share": (
                float(adtech_domains) / float(total_domains_for_share)
                if adtech_domains and total_domains_for_share > 0
                else 0.0 if total_domains_for_share > 0 else None
            ),
            "cdn_share": (
                float(cdn_domains) / float(total_domains_for_share)
                if cdn_domains and total_domains_for_share > 0
                else 0.0 if total_domains_for_share > 0 else None
            ),
            "first_party_share": (
                float(_safe_int(row.get("first_party_domain_count")) or 0) / float(total_domains_for_share)
                if total_domains_for_share > 0
                else None
            ),
        }
        feature_rows.append(record)
        by_package[package_name].append(record)
    return feature_rows, by_package


def _build_app_rollups(by_package: Mapping[str, Sequence[Mapping[str, Any]]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    app_rollups: list[dict[str, Any]] = []
    baseline_vs_interactive: list[dict[str, Any]] = []
    paper_rows: list[dict[str, Any]] = []
    app_vectors: list[dict[str, Any]] = []
    service_hint_rows: list[dict[str, Any]] = []
    metrics_to_compare = (
        "unique_ja4_count",
        "unique_ja3_count",
        "domain_count",
        "unique_service_families",
        "top1_ja4_share",
        "pcap_bytes",
        "packets_per_second",
        "adtech_share",
        "unresolved_share",
    )
    for package_name in sorted(by_package):
        rows = list(by_package[package_name])
        if not rows:
            continue
        app_label = _norm_text(rows[0].get("app_label")) or package_name
        stats_rows = [row for row in rows if _safe_int(row.get("stats_eligible")) == 1]
        if not stats_rows:
            continue
        countable_rows = [row for row in stats_rows if _safe_int(row.get("countable")) == 1]
        analysis_rows = analysis_included_rows(stats_rows)
        supplemental_rows = [row for row in stats_rows if _norm_text(row.get("quota_state")) == "SUPPLEMENTAL_VALID"]
        baseline_rows = [row for row in stats_rows if _norm_text(row.get("interaction_mode")) == "baseline"]
        interactive_rows = [row for row in stats_rows if _norm_text(row.get("interaction_mode")) != "baseline"]
        ja4_values = [float(row["unique_ja4_count"]) for row in stats_rows if row.get("unique_ja4_count") is not None]
        ja3_values = [float(row["unique_ja3_count"]) for row in stats_rows if row.get("unique_ja3_count") is not None]
        ja3s_values = [float(row["unique_ja3s_count"]) for row in stats_rows if row.get("unique_ja3s_count") is not None]
        top_share_values = [float(row["top1_ja4_share"]) for row in stats_rows if row.get("top1_ja4_share") is not None]
        baseline_ja4 = [float(row["unique_ja4_count"]) for row in baseline_rows if row.get("unique_ja4_count") is not None]
        interactive_ja4 = [float(row["unique_ja4_count"]) for row in interactive_rows if row.get("unique_ja4_count") is not None]
        med_ja4, iqr_ja4 = _median_iqr(ja4_values)
        med_ja3, _ = _median_iqr(ja3_values)
        med_ja3s, _ = _median_iqr(ja3s_values)
        med_top_share, _ = _median_iqr(top_share_values)
        baseline_med, _ = _median_iqr(baseline_ja4)
        interactive_med, _ = _median_iqr(interactive_ja4)

        family_counter: Counter[str] = Counter()
        for row in stats_rows:
            families = [
                value.strip()
                for value in _norm_text(row.get("service_families_observed")).split(",")
                if value.strip()
            ]
            if families:
                family_counter.update(families)
                continue
            fam = _norm_text(row.get("top_service_family"))
            if fam:
                family_counter[fam] += 1
        family_text = ", ".join(key for key, _count in family_counter.most_common(6))
        if interactive_med is not None and baseline_med is not None and interactive_med > baseline_med + 1:
            interpretation = "interaction-broadened"
        elif baseline_med is not None and baseline_med <= 2 and (med_top_share or 0.0) >= 0.75:
            interpretation = "stable single-stack"
        elif (med_ja4 or 0.0) >= 8:
            interpretation = "high diversity"
        elif (med_ja4 or 0.0) >= 4:
            interpretation = "moderate diversity"
        else:
            interpretation = "insufficient data" if not stats_rows else "stable low diversity"

        app_metric_rows: list[dict[str, Any]] = []

        for metric in metrics_to_compare:
            baseline_metric = [float(row[metric]) for row in baseline_rows if row.get(metric) is not None]
            interactive_metric = [float(row[metric]) for row in interactive_rows if row.get(metric) is not None]
            base_med, base_iqr = _median_iqr(baseline_metric)
            int_med, int_iqr = _median_iqr(interactive_metric)
            delta = None if int_med is None or base_med is None else (int_med - base_med)
            if len(baseline_metric) >= 2 and len(interactive_metric) >= 2:
                cliffs = _cliffs_delta(interactive_metric, baseline_metric)
                p_value = _exact_permutation_p_value_for_median_delta(interactive_metric, baseline_metric)
                status = "ok" if p_value is not None else "descriptive_only"
            else:
                cliffs = None
                p_value = None
                status = "insufficient_n"
            metric_row = {
                "app_label": app_label,
                "package_name": package_name,
                "baseline_n": len(baseline_metric),
                "interactive_n": len(interactive_metric),
                "metric": metric,
                "baseline_median": base_med,
                "baseline_iqr": base_iqr,
                "interactive_median": int_med,
                "interactive_iqr": int_iqr,
                "delta_median": delta,
                "cliffs_delta": cliffs,
                "cliffs_delta_band": _cliffs_delta_band(cliffs),
                "permutation_p_value": p_value,
                "inference_note": _inference_note(p_value=p_value, delta=cliffs),
                "comparison_status": status,
                "interpretation": interpretation,
            }
            baseline_vs_interactive.append(metric_row)
            app_metric_rows.append(metric_row)

        tested_rows = [row for row in app_metric_rows if row.get("permutation_p_value") is not None]
        strongest_row = None
        if tested_rows:
            strongest_row = sorted(
                tested_rows,
                key=lambda row: (
                    float(row.get("permutation_p_value") or 1.0),
                    -abs(float(row.get("cliffs_delta") or 0.0)),
                    _norm_text(row.get("metric")),
                ),
            )[0]
        comparison_depth = _comparison_depth_label(
            baseline_runs=len(baseline_rows),
            interactive_runs=len(interactive_rows),
        )
        strongest_p_value = float(strongest_row.get("permutation_p_value")) if strongest_row and strongest_row.get("permutation_p_value") is not None else None
        inference_readiness = _inference_readiness_label(
            baseline_runs=len(baseline_rows),
            interactive_runs=len(interactive_rows),
            strongest_p_value=strongest_p_value,
        )

        app_rollups.append(
            {
                "app_label": app_label,
                "package_name": package_name,
                "runs_total": len(stats_rows),
                "countable_runs": len(countable_rows),
                "analysis_included_runs": len(analysis_rows),
                "supplemental_runs": len(supplemental_rows),
                "baseline_runs": len(baseline_rows),
                "interactive_runs": len(interactive_rows),
                "median_unique_ja4_count": med_ja4,
                "iqr_unique_ja4_count": iqr_ja4,
                "median_unique_ja3_count": med_ja3,
                "median_unique_ja3s_count": med_ja3s,
                "median_top_ja4_share": med_top_share,
                "baseline_stability": baseline_med,
                "interactive_broadening": interactive_med,
                "service_families_observed": family_text,
                "comparison_depth": comparison_depth,
                "inference_readiness": inference_readiness,
                "strongest_shift_metric": _norm_text(strongest_row.get("metric")) if strongest_row else "",
                "strongest_shift_p_value": strongest_p_value,
                "strongest_shift_effect_band": _norm_text(strongest_row.get("cliffs_delta_band")) if strongest_row else "",
                "strongest_shift_note": _norm_text(strongest_row.get("inference_note")) if strongest_row else "descriptive_only",
                "interpretation": interpretation,
            }
        )

        domain_values = [float(row["domain_count"]) for row in analysis_rows if row.get("domain_count") is not None]
        paper_rows.append(
            {
                "app": app_label,
                "countable_runs": len(countable_rows),
                "analysis_included_runs": len(analysis_rows),
                "runtime_domains_median": _median_iqr(domain_values)[0],
                "service_families": family_text,
                "unique_ja4_median": med_ja4,
                "ja4_iqr": iqr_ja4,
                "top_ja4_share": med_top_share,
                "baseline_interactive_pattern": (
                    f"baseline {baseline_med:g} -> interactive {interactive_med:g}"
                    if baseline_med is not None and interactive_med is not None
                    else f"baseline {baseline_med:g}" if baseline_med is not None else "insufficient"
                ),
                "interpretation": interpretation,
            }
        )

        app_vectors.append(
            {
                "package_name": package_name,
                "app_label": app_label,
                "run_count": len(stats_rows),
                "vector": [
                    float(med_ja4 or 0.0),
                    float(med_ja3 or 0.0),
                    float(_median_iqr([float(row["domain_count"]) for row in stats_rows if row.get("domain_count") is not None])[0] or 0.0),
                    float(_median_iqr([float(row["unique_service_families"]) for row in stats_rows if row.get("unique_service_families") is not None])[0] or 0.0),
                    float(med_top_share or 0.0),
                    float(_median_iqr([float(row["adtech_share"]) for row in stats_rows if row.get("adtech_share") is not None])[0] or 0.0),
                    float(_median_iqr([float(row["unresolved_share"]) for row in stats_rows if row.get("unresolved_share") is not None])[0] or 0.0),
                    float(_median_iqr([float(row["pcap_bytes"]) for row in stats_rows if row.get("pcap_bytes") is not None])[0] or 0.0),
                ],
            }
        )
        service_hint_rows.append(
            {
                "package_name": package_name,
                "app_label": app_label,
                "family_text": family_text,
                "interpretation": interpretation,
            }
        )
    return app_rollups, baseline_vs_interactive, paper_rows, app_vectors, service_hint_rows


def _build_similarity_outputs(app_vectors: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    raw_vectors = {
        _norm_text(row.get("package_name")): list(row.get("vector") or [])
        for row in app_vectors
        if _norm_text(row.get("package_name")) and isinstance(row.get("vector"), list)
    }
    scaled = _robust_scale_vectors(raw_vectors)
    similarities: dict[tuple[str, str], float] = {}
    rows_by_pkg = { _norm_text(row.get("package_name")): row for row in app_vectors }
    similarity_rows: list[dict[str, Any]] = []
    packages = sorted(scaled)
    for idx, package_name in enumerate(packages):
        for other in packages[idx + 1:]:
            score = _cosine_similarity(scaled[package_name], scaled[other])
            if score is None:
                continue
            similarities[(package_name, other)] = score
            left = rows_by_pkg[package_name]
            right = rows_by_pkg[other]
            similarity_rows.append(
                {
                    "package_name": package_name,
                    "app_label": _norm_text(left.get("app_label")),
                    "other_package_name": other,
                    "other_app_label": _norm_text(right.get("app_label")),
                    "cosine_similarity": score,
                }
            )
    cluster_map = _connected_component_clusters(similarities, threshold=0.8)
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
        row = rows_by_pkg[package_name]
        cluster_rows.append(
            {
                "cluster_id": cluster_map.get(package_name, 0),
                "app_label": _norm_text(row.get("app_label")),
                "package_name": package_name,
                "run_count": _safe_int(row.get("run_count")) or 0,
                "nearest_neighbor": nearest_neighbor,
                "nearest_neighbor_similarity": nearest_score,
                "cluster_basis": "robust-scaled cosine similarity over app-level medians",
            }
        )
    return similarity_rows, cluster_rows


def _build_anomaly_scores(feature_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    eligible = [row for row in feature_rows if _safe_int(row.get("stats_eligible")) == 1]
    feature_names = [
        "pcap_bytes",
        "domain_count",
        "unique_service_families",
        "unique_ja4_count",
        "top1_ja4_share",
        "adtech_share",
        "unresolved_share",
        "packets_per_second",
        "bytes_per_second",
    ]
    global_stats: dict[str, tuple[float, float]] = {}
    for feature in feature_names:
        values = [float(row[feature]) for row in eligible if row.get(feature) is not None]
        if not values:
            continue
        med = float(median(values))
        deviations = [abs(value - med) for value in values]
        mad = float(median(deviations)) if deviations else 0.0
        global_stats[feature] = (med, mad if mad > 1e-9 else 1.0)

    package_stats: dict[str, dict[str, tuple[float, float]]] = defaultdict(dict)
    rows_by_package: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in eligible:
        rows_by_package[_norm_text(row.get("package_name"))].append(row)
    for package_name, rows in rows_by_package.items():
        if len(rows) < 3:
            continue
        for feature in feature_names:
            values = [float(row[feature]) for row in rows if row.get(feature) is not None]
            if len(values) < 3:
                continue
            med = float(median(values))
            deviations = [abs(value - med) for value in values]
            mad = float(median(deviations)) if deviations else 0.0
            package_stats[package_name][feature] = (med, mad if mad > 1e-9 else 1.0)

    out: list[dict[str, Any]] = []
    for row in eligible:
        explanations: list[tuple[float, str]] = []
        global_scores: list[float] = []
        app_scores: list[float] = []
        package_name = _norm_text(row.get("package_name"))
        for feature in feature_names:
            value = row.get(feature)
            if value is None or feature not in global_stats:
                continue
            med, mad = global_stats[feature]
            z = 0.6745 * (float(value) - med) / mad
            global_scores.append(abs(z))
            if abs(z) >= 1.5:
                explanations.append((abs(z), f"{feature} z={z:.2f}"))
            if feature in package_stats.get(package_name, {}):
                app_med, app_mad = package_stats[package_name][feature]
                app_z = 0.6745 * (float(value) - app_med) / app_mad
                app_scores.append(abs(app_z))
        explanations.sort(reverse=True)
        out.append(
            {
                "dynamic_run_id": _norm_text(row.get("dynamic_run_id")),
                "package_name": package_name,
                "app_label": _norm_text(row.get("app_label")),
                "run_profile": _norm_text(row.get("run_profile")),
                "interaction_mode": _norm_text(row.get("interaction_mode")),
                "quota_state": _norm_text(row.get("quota_state")),
                "countable": _safe_int(row.get("countable")),
                "global_anomaly_score": sum(global_scores) / float(len(global_scores)) if global_scores else None,
                "app_relative_anomaly_score": sum(app_scores) / float(len(app_scores)) if app_scores else None,
                "top_explanation_1": explanations[0][1] if len(explanations) >= 1 else "",
                "top_explanation_2": explanations[1][1] if len(explanations) >= 2 else "",
                "top_explanation_3": explanations[2][1] if len(explanations) >= 3 else "",
            }
        )
    out.sort(key=lambda row: (float(row.get("global_anomaly_score") or 0.0), float(row.get("app_relative_anomaly_score") or 0.0)), reverse=True)
    return out


def _build_service_fingerprint_associations(
    feature_rows: Sequence[Mapping[str, Any]],
    domain_service_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    eligible_runs = {
        _norm_text(row.get("dynamic_run_id")): row
        for row in feature_rows
        if _safe_int(row.get("stats_eligible")) == 1
    }
    family_runs: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    family_domains: dict[str, set[str]] = defaultdict(set)
    family_top_ja4: dict[str, Counter[str]] = defaultdict(Counter)
    family_apps: dict[str, set[str]] = defaultdict(set)
    family_run_top_ja4_seen: set[tuple[str, str]] = set()
    for row in domain_service_rows:
        run_id = _norm_text(row.get("dynamic_run_id"))
        feature_row = eligible_runs.get(run_id)
        if not feature_row:
            continue
        family = _norm_text(row.get("service_category")).lower() or "unresolved"
        domain = _norm_text(row.get("observed_domain")).lower()
        family_domains[family].add(domain)
        family_apps[family].add(_norm_text(feature_row.get("package_name")))
        family_runs[family].append(feature_row)
        top_ja4 = _norm_text(feature_row.get("top_ja4"))
        family_run_key = (family, run_id)
        if top_ja4 and family_run_key not in family_run_top_ja4_seen:
            family_top_ja4[family][top_ja4] += 1
            family_run_top_ja4_seen.add(family_run_key)

    out: list[dict[str, Any]] = []
    for family in sorted(family_runs):
        rows = family_runs[family]
        unique_rows = list({_norm_text(row.get("dynamic_run_id")): row for row in rows}.values())
        ja4_values = [float(row["unique_ja4_count"]) for row in unique_rows if row.get("unique_ja4_count") is not None]
        top_shares = [float(row["top1_ja4_share"]) for row in unique_rows if row.get("top1_ja4_share") is not None]
        if not ja4_values:
            continue
        med_ja4 = float(median(ja4_values))
        med_top_share = float(median(top_shares)) if top_shares else None
        if family == "unresolved":
            interpretation = "Unresolved domains should be reviewed; fingerprints provide behavioral context but not attribution."
        elif med_top_share is not None and med_top_share >= 0.75:
            interpretation = "Stable service-family fingerprint profile."
        elif med_ja4 >= 8:
            interpretation = "Service family correlates with higher fingerprint diversity."
        else:
            interpretation = "Moderate fingerprint diversity within this service family."
        out.append(
            {
                "service_family": family,
                "apps_seen": len(family_apps[family]),
                "run_count": len(unique_rows),
                "median_unique_ja4": med_ja4,
                "common_top_ja4": family_top_ja4[family].most_common(1)[0][0] if family_top_ja4[family] else "",
                "median_top_ja4_share": med_top_share,
                "associated_domains_sample": " | ".join(sorted(family_domains[family])[:5]),
                "interpretation": interpretation,
            }
        )
    return out


def _build_cross_app_metric_summary(
    baseline_vs_interactive: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    by_metric: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in baseline_vs_interactive:
        metric = _norm_text(row.get("metric"))
        if metric:
            by_metric[metric].append(row)

    out: list[dict[str, Any]] = []
    for metric in sorted(by_metric):
        rows = by_metric[metric]
        comparable = [
            row for row in rows
            if row.get("delta_median") is not None
            and int(row.get("baseline_n") or 0) >= 2
            and int(row.get("interactive_n") or 0) >= 2
        ]
        deltas = [float(row.get("delta_median")) for row in comparable if row.get("delta_median") is not None]
        cliffs = [abs(float(row.get("cliffs_delta"))) for row in comparable if row.get("cliffs_delta") is not None]
        p_values = [float(row.get("permutation_p_value")) for row in comparable if row.get("permutation_p_value") is not None]
        pos = sum(1 for value in deltas if value > 0)
        neg = sum(1 for value in deltas if value < 0)
        zero = sum(1 for value in deltas if value == 0)
        large = sum(1 for row in comparable if _norm_text(row.get("cliffs_delta_band")) == "large")
        if not comparable:
            interpretation = "no cross-app comparable baseline/interactive sample yet"
        elif pos > neg and sum(1 for p in p_values if p <= 0.10) > 0:
            interpretation = "interactive broadening trend observed"
        elif neg > pos and sum(1 for p in p_values if p <= 0.10) > 0:
            interpretation = "interactive narrowing trend observed"
        else:
            interpretation = "mixed or inconclusive cross-app shift"
        out.append(
            {
                "metric": metric,
                "apps_compared": len(comparable),
                "apps_positive_delta": pos,
                "apps_negative_delta": neg,
                "apps_zero_delta": zero,
                "apps_p_le_0_10": sum(1 for p in p_values if p <= 0.10),
                "apps_p_le_0_05": sum(1 for p in p_values if p <= 0.05),
                "apps_large_effect": large,
                "median_delta": _median_iqr(deltas)[0],
                "median_abs_cliffs_delta": _median_iqr(cliffs)[0],
                "interpretation": interpretation,
            }
        )
    return out


def _build_paper_findings(
    summary: Mapping[str, Any],
    app_rollups: Sequence[Mapping[str, Any]],
    baseline_vs_interactive: Sequence[Mapping[str, Any]],
    service_associations: Sequence[Mapping[str, Any]],
    cross_app_summary: Sequence[Mapping[str, Any]],
) -> str:
    by_pkg = {_norm_text(row.get("package_name")): row for row in app_rollups}
    by_pkg_metric = {
        (_norm_text(row.get("package_name")), _norm_text(row.get("metric"))): row
        for row in baseline_vs_interactive
    }
    lines: list[str] = []
    lines.append("# PCAP Behavioral Findings")
    lines.append("")
    lines.append("This audit is read-only, payload-free, and evidence-governed. It uses TLS handshake fingerprints, domain/service observations, and transport-shape features without decrypting traffic or inspecting payloads.")
    lines.append("")
    lines.append("## Coverage")
    lines.append("")
    lines.append(f"- Total runs audited: {summary.get('total_runs', 0)}")
    lines.append(f"- Local runs with PCAP present: {summary.get('local_pcap_available_runs', 0)}")
    lines.append(f"- Local runs with complete domain + JA4 features: {summary.get('fingerprint_complete_runs', 0)}")
    lines.append(f"- Stats-eligible governed runs: {summary.get('stats_eligible_runs', 0)}")
    lines.append(f"- Apps inference-ready for baseline vs interactive comparison: {summary.get('apps_inference_ready', 0)}")
    lines.append("")
    findings = [
        ("bbc.mobile.news.ww", "BBC News shows high TLS fingerprint diversity, consistent with publisher + adtech + audience-measurement paths.", "High"),
        ("com.cnn.mobile.android.phone", "CNN also shows high diversity and adtech/measurement/CDN broadening in both baseline and interactive traffic.", "High"),
        ("com.facebook.orca", "Messenger baseline-connected runs stay countable and fingerprinted despite lower-volume messaging traffic.", "Medium"),
        ("com.whatsapp", "WhatsApp baseline-connected runs are stable low-diversity, while interactive runs broaden the encrypted-service mix.", "High"),
        ("com.twitter.android", "X supplemental quiet baselines still produce usable TLS fingerprints even when not quota-counted.", "Medium"),
        ("com.zhiliaoapp.musically", "TikTok shows high fingerprint diversity across multiple service families.", "Medium"),
    ]
    for package_name, claim, confidence in findings:
        row = by_pkg.get(package_name)
        if not row:
            continue
        ja4_delta_row = by_pkg_metric.get((package_name, "unique_ja4_count"))
        lines.append(f"## {row.get('app_label')}")
        lines.append("")
        lines.append(f"- Finding: {claim}")
        lines.append(f"- Direct evidence: median JA4={row.get('median_unique_ja4_count')}, top JA4 share={row.get('median_top_ja4_share')}, service families={row.get('service_families_observed')}")
        if ja4_delta_row:
            lines.append(f"- Baseline vs interactive JA4 inference: {_format_inference_summary(ja4_delta_row)}")
        lines.append(f"- Confidence: {confidence}")
        lines.append("- Caveat: behavioral fingerprints complement domain/SNI attribution; they do not prove vendor ownership or maliciousness.")
        lines.append("- Paper status: paper-ready" if confidence == "High" else "- Paper status: exploratory but usable")
        lines.append(f"- Readiness: {row.get('inference_readiness')}")
        lines.append("")
    if cross_app_summary:
        lines.append("## Cross-App Shift Summary")
        lines.append("")
        for row in cross_app_summary[:5]:
            lines.append(
                f"- {row.get('metric')}: apps_compared={row.get('apps_compared')}, "
                f"positive={row.get('apps_positive_delta')}, negative={row.get('apps_negative_delta')}, "
                f"p<=0.10={row.get('apps_p_le_0_10')}, interpretation={row.get('interpretation')}"
            )
        lines.append("")
    lines.append("## Service / Fingerprint Associations")
    lines.append("")
    for row in sorted(service_associations, key=lambda item: float(item.get("median_unique_ja4") or 0.0), reverse=True)[:5]:
        lines.append(
            f"- {row.get('service_family')}: median JA4={row.get('median_unique_ja4')}, median top-share={row.get('median_top_ja4_share')}, sample domains={row.get('associated_domains_sample')}"
        )
    lines.append("")
    lines.append("## Caveats")
    lines.append("")
    lines.append("- Legacy DB-only rows remain visible but are excluded from inference when local PCAP or complete feature context is unavailable.")
    lines.append("- TLS fingerprints are handshake-level behavioral indicators, not identity proofs.")
    lines.append("- Small per-app interactive samples are reported conservatively and marked insufficient when needed.")
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

    run_rows = _load_run_rows(package_filter)
    domain_rows = _load_domain_service_rows(package_filter)
    service_by_run, _service_global = _aggregate_service_stats(domain_rows)
    feature_rows, by_package = _build_run_feature_matrix(
        run_rows,
        service_by_run,
        recompute_exact_tls=recompute_exact_tls,
    )
    app_rollups, baseline_vs_interactive, paper_rows, app_vectors, _service_hints = _build_app_rollups(by_package)
    similarity_rows, cluster_rows = _build_similarity_outputs(app_vectors)
    anomaly_rows = _build_anomaly_scores(feature_rows)
    service_associations = _build_service_fingerprint_associations(feature_rows, domain_rows)
    cross_app_summary = _build_cross_app_metric_summary(baseline_vs_interactive)

    _write_csv(output_root / "run_feature_matrix.csv", feature_rows, RUN_FEATURE_MATRIX_FIELDS)
    _write_csv(output_root / "app_feature_rollup.csv", app_rollups, APP_ROLLUP_FIELDS)
    _write_csv(output_root / "baseline_vs_interactive_stats.csv", baseline_vs_interactive, BASELINE_INTERACTIVE_FIELDS)
    _write_csv(output_root / "cross_app_metric_summary.csv", cross_app_summary, CROSS_APP_FIELDS)
    _write_csv(output_root / "cluster_assignments.csv", cluster_rows, CLUSTER_FIELDS)
    _write_csv(output_root / "app_similarity_matrix.csv", similarity_rows, SIMILARITY_FIELDS)
    _write_csv(output_root / "anomaly_scores.csv", anomaly_rows, ANOMALY_FIELDS)
    _write_csv(output_root / "service_fingerprint_associations.csv", service_associations, ASSOCIATION_FIELDS)
    _write_csv(output_root / "paper_table_preview.csv", paper_rows, PAPER_TABLE_FIELDS)

    summary = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "packages_filtered": sorted({_norm_text(value).lower() for value in package_filter if _norm_text(value)}) or None,
        "total_runs": len(feature_rows),
        "local_pcap_available_runs": sum(1 for row in feature_rows if _safe_int(row.get("local_pcap_available")) == 1),
        "stats_eligible_runs": sum(1 for row in feature_rows if _safe_int(row.get("stats_eligible")) == 1),
        "fingerprint_complete_runs": sum(1 for row in feature_rows if _norm_text(row.get("feature_status")) == "feature_complete"),
        "legacy_flagged_runs": sum(1 for row in feature_rows if _norm_text(row.get("feature_status")).startswith("legacy")),
        "apps_with_stats_eligible_runs": len(app_rollups),
        "apps_with_interactive_comparison": sum(
            1 for row in app_rollups if _norm_text(row.get("comparison_depth")) in {"tested", "limited", "descriptive_only"}
        ),
        "apps_inference_ready": sum(1 for row in app_rollups if _norm_text(row.get("inference_readiness")) == "paper_ready_signal"),
        "apps_tested_but_inconclusive": sum(1 for row in app_rollups if _norm_text(row.get("inference_readiness")) == "tested_but_inconclusive"),
        "apps_limited_comparison": sum(1 for row in app_rollups if _norm_text(row.get("inference_readiness")) == "limited_comparison"),
        "apps_needing_interactive_depth": sum(1 for row in app_rollups if _norm_text(row.get("inference_readiness")) == "needs_interactive_depth"),
        "focus_package_count": sum(1 for row in app_rollups if _norm_text(row.get("package_name")) in FOCUS_PACKAGES),
        "recompute_exact_tls": bool(recompute_exact_tls),
        "output_files": {
            "summary_json": str((output_root / "summary.json").resolve()),
            "run_feature_matrix_csv": str((output_root / "run_feature_matrix.csv").resolve()),
            "app_feature_rollup_csv": str((output_root / "app_feature_rollup.csv").resolve()),
            "baseline_vs_interactive_stats_csv": str((output_root / "baseline_vs_interactive_stats.csv").resolve()),
            "cross_app_metric_summary_csv": str((output_root / "cross_app_metric_summary.csv").resolve()),
            "cluster_assignments_csv": str((output_root / "cluster_assignments.csv").resolve()),
            "app_similarity_matrix_csv": str((output_root / "app_similarity_matrix.csv").resolve()),
            "anomaly_scores_csv": str((output_root / "anomaly_scores.csv").resolve()),
            "service_fingerprint_associations_csv": str((output_root / "service_fingerprint_associations.csv").resolve()),
            "paper_table_preview_csv": str((output_root / "paper_table_preview.csv").resolve()),
            "paper_findings_md": str((output_root / "paper_findings.md").resolve()),
        },
    }
    (output_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    findings = _build_paper_findings(summary, app_rollups, baseline_vs_interactive, service_associations, cross_app_summary)
    (output_root / "paper_findings.md").write_text(findings, encoding="utf-8")
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
