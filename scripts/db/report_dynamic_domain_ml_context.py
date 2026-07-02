#!/usr/bin/env python3
"""Read-only ML/context export for dynamic runtime domains and destinations.

The export stays payload-free. It uses DNS/SNI/domain observations, service
catalog mappings, and service-signal taxonomy to explain where traffic appears
to go and how each destination can be represented for analysis.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

DOMAIN_CONTEXT_FIELDS: tuple[str, ...] = (
    "package_name",
    "app_label",
    "observed_domain",
    "root_domain",
    "observation_rows",
    "observed_run_count",
    "total_indicator_hits",
    "indicator_types",
    "indicator_sources",
    "profiles_seen",
    "valid_dataset_run_count",
    "countable_run_count",
    "owner_class",
    "role_class",
    "confidence",
    "classification_basis",
    "package_name_scope",
    "match_type",
    "is_first_party",
    "service_key",
    "service_display_name",
    "service_owner_name",
    "service_owner_class",
    "service_category",
    "service_primary_use_case",
    "service_role_class",
    "service_confidence",
    "signal_keys",
    "signal_families",
    "focus_areas",
    "severity_hints",
    "destination_class",
    "data_activity_class",
    "privacy_relevance",
    "ml_feature_family",
    "where_data_is_going",
    "direction_context_scope",
    "avg_outbound_byte_ratio_for_runs",
    "avg_inbound_byte_ratio_for_runs",
    "avg_direction_confident_packet_ratio_for_runs",
    "source_urls",
    "analyst_note",
)

PACKAGE_SUMMARY_FIELDS: tuple[str, ...] = (
    "package_name",
    "app_label",
    "domain_rows",
    "distinct_root_domains",
    "observed_runs",
    "first_party_domains",
    "third_party_domains",
    "high_privacy_relevance_domains",
    "medium_privacy_relevance_domains",
    "adtech_domains",
    "analytics_domains",
    "identity_domains",
    "subscription_paywall_domains",
    "security_or_bot_domains",
    "content_delivery_domains",
    "top_destination_classes",
    "top_service_categories",
    "top_signal_families",
    "ml_readiness",
    "ml_caveat",
)

ROOT_SUMMARY_FIELDS: tuple[str, ...] = (
    "root_domain",
    "domain_rows",
    "packages_seen",
    "observed_runs",
    "owner_classes",
    "service_keys",
    "service_categories",
    "signal_families",
    "privacy_relevance_max",
    "example_domains",
)

TABLE_DICTIONARY_FIELDS: tuple[str, ...] = (
    "table_name",
    "grain",
    "purpose",
    "joins",
    "ml_use",
    "important_columns",
    "caveats",
)

TABLE_DICTIONARY_ROWS: tuple[dict[str, str], ...] = (
    {
        "table_name": "dynamic_sessions",
        "grain": "one dynamic run",
        "purpose": "Run header, APK identity, device/capture metadata, dataset validity, and PCAP lineage.",
        "joins": "dynamic_run_id -> dynamic_network_features, dynamic_network_indicators, dynamic_domain_observations",
        "ml_use": "Run labels, profile/baseline-vs-interaction strata, validity filters, app/version grouping.",
        "important_columns": "dynamic_run_id, package_name, operator_run_profile, countable, valid_dataset_run, pcap_valid, pcap_bytes, evidence_path",
        "caveats": "Historical DB-only rows may lack modern feature/domain observations; use coverage reports before modeling.",
    },
    {
        "table_name": "dynamic_network_features",
        "grain": "one dynamic run feature vector",
        "purpose": "Payload-free traffic volume, timing, protocol, TLS, flow, and direction aggregate features.",
        "joins": "dynamic_run_id -> dynamic_sessions; dynamic_run_id -> domain observations for contextual labels",
        "ml_use": "Numeric features for clustering, anomaly detection, baseline ranges, and interaction deltas.",
        "important_columns": "packet_count, data_size_bytes, bytes_per_sec, tls_ratio, quic_ratio, unique_dst_ip_count, direction_* ratios, JA3/JA4 counts",
        "caveats": "Direction metrics are run-level, not per-domain; do not assign bytes to a specific domain without flow-level linkage.",
    },
    {
        "table_name": "dynamic_network_indicators",
        "grain": "one run + indicator value",
        "purpose": "Persisted top DNS/SNI/TLS/domain indicators extracted from dynamic traffic summaries.",
        "joins": "dynamic_run_id -> dynamic_sessions; DNS/SNI values can be classified into dynamic_domain_observations",
        "ml_use": "Sparse categorical features and recovery source when PCAP evidence packs are missing.",
        "important_columns": "indicator_type, indicator_value, indicator_count, indicator_source, meta_json",
        "caveats": "Indicator counts are top-N evidence, not full packet counts.",
    },
    {
        "table_name": "dynamic_domain_observations",
        "grain": "one run + observed DNS/SNI domain",
        "purpose": "Canonical classified runtime domain observations: owner, role, confidence, match basis, and first-party flag.",
        "joins": "dynamic_run_id -> dynamic_sessions; observed_domain/root_domain -> service resolver/catalog maps",
        "ml_use": "Domain destination labels, owner class features, role features, first/third-party ratios, service/signal enrichment.",
        "important_columns": "observed_domain, root_domain, owner_class, role_class, confidence, classification_basis, indicator_count",
        "caveats": "DNS/SNI visibility only; payload contents and exact personal data categories are not observed.",
    },
    {
        "table_name": "dynamic_domain_reference",
        "grain": "one curated domain classification rule",
        "purpose": "Repo-owned taxonomy rules used to classify observed domains into owner/role/confidence.",
        "joins": "domain_pattern + match_type + package_name_scope feed dynamic_domain_observations classification",
        "ml_use": "Explainability/provenance table for label source and confidence.",
        "important_columns": "package_name_scope, domain_pattern, match_type, owner_class, role_class, source_url, notes",
        "caveats": "Global rules can be lower-confidence than package-scoped rules; prefer package-scoped exact/suffix matches.",
    },
    {
        "table_name": "dynamic_service_catalog",
        "grain": "one provider/service",
        "purpose": "Provider catalog: owner name/class, service category, use case, documentation and privacy-policy links.",
        "joins": "service_id -> dynamic_service_domain_map; service_key -> service signal mapping",
        "ml_use": "Destination owner/service categorical features and higher-level service-family grouping.",
        "important_columns": "service_key, owner_name, owner_class, service_category, primary_use_case, confidence",
        "caveats": "Service categories are analytical buckets, not legal determinations.",
    },
    {
        "table_name": "dynamic_service_domain_map",
        "grain": "one service + domain pattern",
        "purpose": "Maps domains to service providers and more specific service roles.",
        "joins": "service_id -> dynamic_service_catalog; pattern matching over observed domains",
        "ml_use": "Turns raw domains into provider/service labels for categorical ML features.",
        "important_columns": "service_id, package_name_scope, domain_pattern, match_type, role_class, confidence",
        "caveats": "A domain may be generic; package scope and match specificity determine the best service match.",
    },
    {
        "table_name": "dynamic_signal_catalog",
        "grain": "one privacy/security/context signal",
        "purpose": "Semantic signal taxonomy layered above services.",
        "joins": "signal_id -> dynamic_service_signal_map",
        "ml_use": "Signal-family features such as advertising, attribution, analytics, bot defense, privacy gateway, first-party context.",
        "important_columns": "signal_key, signal_family, focus_area, severity_hint, analyst_guidance",
        "caveats": "Signals guide review; they are not standalone findings without app/run context.",
    },
    {
        "table_name": "dynamic_service_signal_map",
        "grain": "one service + signal relationship",
        "purpose": "Maps each service provider to one or more privacy/security/context signals.",
        "joins": "service_id -> dynamic_service_catalog; signal_id -> dynamic_signal_catalog",
        "ml_use": "Multi-hot service signal features for models and paper tables.",
        "important_columns": "service_id, signal_id, signal_strength, confidence, rationale",
        "caveats": "One service can emit multiple signals; do not force a single-label interpretation.",
    },
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", action="append", default=[], help="Restrict to one or more package names.")
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    parser.add_argument("--stdout-json", action="store_true", help="Print summary JSON to stdout.")
    return parser


def _write_csv(path: Path, rows: list[Mapping[str, Any]], fields: tuple[str, ...] | None = None) -> None:
    fieldnames = list(fields or ())
    if not fieldnames:
        for row in rows:
            for key in row.keys():
                if key not in fieldnames:
                    fieldnames.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def _join_values(values: set[str] | list[str] | tuple[str, ...], *, sep: str = " | ") -> str:
    return sep.join(sorted({str(value).strip() for value in values if str(value or "").strip()}))


def _highest_relevance(values: set[str]) -> str:
    order = {"high": 3, "medium": 2, "low": 1, "": 0}
    return max((value for value in values if value), key=lambda value: order.get(value, 0), default="")


def destination_class(owner_class: str, service_category: str, focus_areas: set[str]) -> str:
    owner = str(owner_class or "").strip().lower()
    category = str(service_category or "").strip().lower()
    if owner == "first_party":
        if category in {"social_platform"}:
            return "first_party_social_or_messaging_platform"
        if category in {"publisher", "content_delivery"}:
            return "first_party_publisher_or_content"
        return "first_party_operated_destination"
    if category in {"adtech", "ad_verification", "ad_measurement", "attribution", "identity_and_adtech"}:
        return "third_party_ad_or_measurement_destination"
    if category in {"subscription_paywall"}:
        return "third_party_subscription_or_paywall_destination"
    if category in {"analytics", "audience_personalization", "identity_and_tag_management"}:
        return "third_party_analytics_or_identity_destination"
    if category in {"security_or_bot_defense"}:
        return "third_party_security_or_bot_defense"
    if category in {"consent_and_privacy"} or "privacy" in focus_areas:
        return "third_party_consent_or_privacy_infrastructure"
    if category in {"platform_infrastructure", "content_delivery"}:
        return "third_party_infrastructure_or_delivery"
    return "unmapped_or_general_destination" if not category else f"{owner or 'unknown'}_{category}"


def data_activity_class(role_class: str, service_category: str, signal_families: set[str]) -> str:
    role = str(role_class or "").strip().lower()
    category = str(service_category or "").strip().lower()
    families = {str(value or "").strip().lower() for value in signal_families}
    if "attribution" in families or "attribution" in role:
        return "attribution_or_campaign_measurement"
    if "advertising" in families or "ad" in role or category == "adtech":
        return "advertising_or_ad_measurement"
    if "publisher_monetization" in families or "paywall" in role or category == "subscription_paywall":
        return "subscription_paywall_or_customer_journey"
    if "analytics" in families or "analytics" in role or "collection" in role:
        return "analytics_or_audience_collection"
    if "identity" in families or "identity" in role:
        return "identity_or_tag_management"
    if "bot" in role or "security" in category:
        return "security_or_abuse_prevention"
    if "consent" in role or category == "consent_and_privacy":
        return "consent_or_privacy_preferences"
    if "content_delivery" in role or "cdn" in role or category == "content_delivery":
        return "content_or_media_delivery"
    if "realtime" in role or "messaging" in role:
        return "realtime_or_messaging_transport"
    if "api" in role or "platform" in role:
        return "platform_api"
    return "general_infrastructure_or_unknown"


def privacy_relevance(focus_areas: set[str], signal_families: set[str], service_category: str) -> str:
    focus = {str(value or "").strip().lower() for value in focus_areas}
    families = {str(value or "").strip().lower() for value in signal_families}
    category = str(service_category or "").strip().lower()
    if "privacy" in focus or category in {
        "adtech",
        "attribution",
        "identity_and_adtech",
        "identity_and_tag_management",
        "subscription_paywall",
    }:
        return "high"
    if "mixed" in focus or category in {"analytics", "audience_personalization", "security_or_bot_defense", "consent_and_privacy"}:
        return "medium"
    if families & {"advertising", "attribution", "profiling", "identity_management", "analytics"}:
        return "high"
    return "low"


def _ml_readiness(domain_rows: list[Mapping[str, Any]]) -> tuple[str, str]:
    if not domain_rows:
        return "not_ready", "No domain rows."
    unresolved = sum(1 for row in domain_rows if not row.get("service_key"))
    low_conf = sum(1 for row in domain_rows if str(row.get("confidence") or "").lower() == "low")
    if unresolved:
        return "review", f"{unresolved} domain rows lack service mapping."
    if low_conf:
        return "usable_with_review", f"{low_conf} domain rows are low-confidence."
    return "ready", "All exported domain rows have service context and no low-confidence domain labels."


def _load_seed_aware_catalogs(core_q: Any) -> tuple[
    tuple[dict[str, Any], ...],
    tuple[dict[str, Any], ...],
    dict[str, dict[str, Any]],
    dict[str, list[dict[str, Any]]],
]:
    from scytaledroid.DynamicAnalysis.service_context import (
        default_service_catalog_seed_rows,
        default_service_domain_map_seed_rows,
    )
    from scytaledroid.DynamicAnalysis.service_signals import (
        default_service_signal_map_seed_rows,
        default_signal_catalog_seed_rows,
    )
    from scripts.db._dynamic_service_seed_overlay import (
        merge_missing_seed_service_maps,
        merge_missing_seed_services,
    )
    from scripts.db.report_dynamic_service_signals import (
        _merge_missing_seed_service_signal_maps,
        _merge_missing_seed_signals,
    )

    service_rows = core_q.run_sql(
        """
        SELECT service_key, display_name, owner_name, owner_class, service_category,
               primary_use_case, documentation_url, privacy_policy_url, source_url, confidence
        FROM dynamic_service_catalog
        WHERE is_active = 1
        ORDER BY service_key
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic.domain_ml_context.services",
    ) or []
    service_map_rows = core_q.run_sql(
        """
        SELECT dsc.service_key, dsdm.package_name_scope, dsdm.domain_pattern,
               dsdm.match_type, dsdm.role_class, dsdm.source_url, dsdm.confidence
        FROM dynamic_service_domain_map dsdm
        JOIN dynamic_service_catalog dsc
          ON dsc.service_id = dsdm.service_id
        WHERE dsdm.is_active = 1
          AND dsc.is_active = 1
        ORDER BY dsc.service_key, dsdm.package_name_scope, dsdm.match_type, dsdm.domain_pattern
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic.domain_ml_context.service_maps",
    ) or []
    signal_rows = core_q.run_sql(
        """
        SELECT signal_key, display_name, signal_family, focus_area, severity_hint,
               description, analyst_guidance, source_url
        FROM dynamic_signal_catalog
        WHERE is_active = 1
        ORDER BY signal_key
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic.domain_ml_context.signals",
    ) or []
    service_signal_rows = core_q.run_sql(
        """
        SELECT dsc.service_key, dsg.signal_key, dssm.signal_strength,
               dssm.confidence, dssm.rationale
        FROM dynamic_service_signal_map dssm
        JOIN dynamic_service_catalog dsc
          ON dsc.service_id = dssm.service_id
        JOIN dynamic_signal_catalog dsg
          ON dsg.signal_id = dssm.signal_id
        WHERE dssm.is_active = 1
          AND dsc.is_active = 1
          AND dsg.is_active = 1
        ORDER BY dsc.service_key, dsg.signal_key
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic.domain_ml_context.service_signal_maps",
    ) or []

    service_rows = merge_missing_seed_services(
        [dict(row) for row in service_rows if isinstance(row, Mapping)],
        default_service_catalog_seed_rows(),
    )
    service_map_rows = merge_missing_seed_service_maps(
        [dict(row) for row in service_map_rows if isinstance(row, Mapping)],
        default_service_domain_map_seed_rows(),
    )
    signal_rows = _merge_missing_seed_signals(
        [dict(row) for row in signal_rows if isinstance(row, Mapping)],
        default_signal_catalog_seed_rows(),
    )
    service_signal_rows = _merge_missing_seed_service_signal_maps(
        [dict(row) for row in service_signal_rows if isinstance(row, Mapping)],
        default_service_signal_map_seed_rows(),
    )
    signals_by_key = {str(row.get("signal_key") or ""): dict(row) for row in signal_rows}
    signals_by_service: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in service_signal_rows:
        service_key = str(row.get("service_key") or "")
        signal_key = str(row.get("signal_key") or "")
        signal = signals_by_key.get(signal_key, {})
        signals_by_service[service_key].append({**dict(row), **{f"signal_{k}": v for k, v in signal.items()}})
    return tuple(service_rows), tuple(service_map_rows), signals_by_key, dict(signals_by_service)


def _load_domain_rows(core_q: Any, packages: list[str]) -> list[dict[str, Any]]:
    package_filters = [str(value or "").strip().lower() for value in packages if str(value or "").strip()]
    where_sql = ""
    params: tuple[object, ...] = ()
    if package_filters:
        placeholders = ", ".join(["%s"] * len(package_filters))
        where_sql = f"WHERE ddo.package_name IN ({placeholders})"
        params = tuple(package_filters)
    return [
        dict(row)
        for row in (
            core_q.run_sql(
                f"""
                SELECT
                  ddo.package_name,
                  COALESCE(a.display_name, ddo.package_name) AS app_label,
                  ddo.observed_domain,
                  ddo.root_domain,
                  COUNT(*) AS observation_rows,
                  COUNT(DISTINCT ddo.dynamic_run_id) AS observed_run_count,
                  SUM(COALESCE(ddo.indicator_count, 0)) AS total_indicator_hits,
                  GROUP_CONCAT(DISTINCT ddo.indicator_type ORDER BY ddo.indicator_type SEPARATOR '|') AS indicator_types,
                  GROUP_CONCAT(DISTINCT COALESCE(ddo.indicator_source, '') ORDER BY COALESCE(ddo.indicator_source, '') SEPARATOR '|') AS indicator_sources,
                  GROUP_CONCAT(DISTINCT COALESCE(ds.operator_run_profile, nf.run_profile, '') ORDER BY COALESCE(ds.operator_run_profile, nf.run_profile, '') SEPARATOR '|') AS profiles_seen,
                  SUM(CASE WHEN COALESCE(ds.valid_dataset_run, nf.valid_dataset_run, 0) = 1 THEN 1 ELSE 0 END) AS valid_dataset_run_count,
                  SUM(CASE WHEN COALESCE(ds.countable, nf.countable, 0) = 1 THEN 1 ELSE 0 END) AS countable_run_count,
                  ddo.owner_class,
                  ddo.role_class,
                  ddo.confidence,
                  ddo.classification_basis,
                  ddo.package_name_scope,
                  ddo.match_type,
                  MAX(ddo.is_first_party) AS is_first_party,
                  AVG(nf.outbound_byte_ratio) AS avg_outbound_byte_ratio_for_runs,
                  AVG(nf.inbound_byte_ratio) AS avg_inbound_byte_ratio_for_runs,
                  AVG(nf.direction_confident_packet_ratio) AS avg_direction_confident_packet_ratio_for_runs
                FROM dynamic_domain_observations ddo
                LEFT JOIN dynamic_sessions ds
                  ON ds.dynamic_run_id = ddo.dynamic_run_id
                LEFT JOIN dynamic_network_features nf
                  ON nf.dynamic_run_id = ddo.dynamic_run_id
                LEFT JOIN apps a
                  ON a.package_name = ddo.package_name
                {where_sql}
                GROUP BY
                  ddo.package_name,
                  COALESCE(a.display_name, ddo.package_name),
                  ddo.observed_domain,
                  ddo.root_domain,
                  ddo.owner_class,
                  ddo.role_class,
                  ddo.confidence,
                  ddo.classification_basis,
                  ddo.package_name_scope,
                  ddo.match_type
                ORDER BY ddo.package_name, total_indicator_hits DESC, ddo.observed_domain
                """,
                params,
                fetch="all",
                dictionary=True,
                query_name="dynamic.domain_ml_context.domain_rows",
            )
            or []
        )
        if isinstance(row, Mapping)
    ]


def _table_schema_rows(core_q: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for table in [row["table_name"] for row in TABLE_DICTIONARY_ROWS]:
        cols = core_q.run_sql(
            """
            SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = %s
            ORDER BY ORDINAL_POSITION
            """,
            (table,),
            fetch="all",
            dictionary=True,
            query_name="dynamic.domain_ml_context.table_schema",
        ) or []
        for col in cols:
            if not isinstance(col, Mapping):
                continue
            rows.append(
                {
                    "table_name": table,
                    "column_name": col.get("COLUMN_NAME"),
                    "column_type": col.get("COLUMN_TYPE"),
                    "nullable": col.get("IS_NULLABLE"),
                    "key": col.get("COLUMN_KEY"),
                }
            )
    return rows


def _build_domain_context_rows(
    domain_rows: list[dict[str, Any]],
    service_rows: tuple[dict[str, Any], ...],
    service_map_rows: tuple[dict[str, Any], ...],
    signals_by_service: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    from scytaledroid.DynamicAnalysis.service_context import resolve_service_for_domain

    out: list[dict[str, Any]] = []
    for row in domain_rows:
        package_name = str(row.get("package_name") or "").strip().lower()
        domain = str(row.get("observed_domain") or "").strip().lower()
        resolved = resolve_service_for_domain(
            domain,
            package_name=package_name,
            service_rows=service_rows,
            map_rows=service_map_rows,
        )
        service_key = str(resolved.get("service_key") or "")
        signal_maps = signals_by_service.get(service_key, [])
        signal_keys = {str(signal.get("signal_key") or "") for signal in signal_maps}
        signal_families = {str(signal.get("signal_signal_family") or "") for signal in signal_maps}
        focus_areas = {str(signal.get("signal_focus_area") or "") for signal in signal_maps}
        severity_hints = {str(signal.get("signal_severity_hint") or "") for signal in signal_maps}
        source_urls = {
            str(row.get("source_url") or ""),
            str(resolved.get("source_url") or ""),
            str(resolved.get("documentation_url") or ""),
        }
        source_urls.update(str(signal.get("signal_source_url") or "") for signal in signal_maps)
        service_category = str(resolved.get("service_category") or "")
        role_class = str(resolved.get("role_class") or row.get("role_class") or "")
        relevance = privacy_relevance(focus_areas, signal_families, service_category)
        destination = destination_class(str(row.get("owner_class") or ""), service_category, focus_areas)
        activity = data_activity_class(role_class, service_category, signal_families)
        owner_name = str(resolved.get("owner_name") or row.get("owner_class") or "unknown")
        service_display = str(resolved.get("service_display_name") or resolved.get("display_name") or service_key or "unmapped")
        out.append(
            {
                **row,
                "is_first_party": int(row.get("is_first_party") or 0),
                "service_key": service_key,
                "service_display_name": service_display,
                "service_owner_name": owner_name,
                "service_owner_class": resolved.get("owner_class") or "",
                "service_category": service_category,
                "service_primary_use_case": resolved.get("primary_use_case") or "",
                "service_role_class": role_class,
                "service_confidence": resolved.get("confidence") or "",
                "signal_keys": _join_values(signal_keys),
                "signal_families": _join_values(signal_families),
                "focus_areas": _join_values(focus_areas),
                "severity_hints": _join_values(severity_hints),
                "destination_class": destination,
                "data_activity_class": activity,
                "privacy_relevance": relevance,
                "ml_feature_family": "|".join(
                    value
                    for value in [
                        str(row.get("owner_class") or ""),
                        service_category,
                        activity,
                        _join_values(signal_families, sep="+"),
                    ]
                    if value
                ),
                "where_data_is_going": f"{owner_name} / {service_display} / {service_category or 'unknown_category'}",
                "direction_context_scope": "run_level_direction_ratios_only_not_domain_bytes",
                "source_urls": _join_values(source_urls),
                "analyst_note": (
                    "DNS/SNI destination context only; payload-free. Use run-level direction ratios as behavior context, "
                    "not as domain-attributed byte counts."
                ),
            }
        )
    return out


def _build_package_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("package_name") or "")].append(row)
    summaries: list[dict[str, Any]] = []
    for package_name, items in sorted(grouped.items()):
        readiness, caveat = _ml_readiness(items)
        service_categories = Counter(str(row.get("service_category") or "") for row in items if row.get("service_category"))
        destination_classes = Counter(str(row.get("destination_class") or "") for row in items if row.get("destination_class"))
        signal_families = Counter()
        for row in items:
            for family in str(row.get("signal_families") or "").split("|"):
                family = family.strip()
                if family:
                    signal_families[family] += 1
        summaries.append(
            {
                "package_name": package_name,
                "app_label": items[0].get("app_label", ""),
                "domain_rows": len(items),
                "distinct_root_domains": len({row.get("root_domain") for row in items if row.get("root_domain")}),
                "observed_runs": sum(int(row.get("observed_run_count") or 0) for row in items),
                "first_party_domains": sum(1 for row in items if str(row.get("owner_class") or "") == "first_party"),
                "third_party_domains": sum(1 for row in items if str(row.get("owner_class") or "") == "third_party"),
                "high_privacy_relevance_domains": sum(1 for row in items if row.get("privacy_relevance") == "high"),
                "medium_privacy_relevance_domains": sum(1 for row in items if row.get("privacy_relevance") == "medium"),
                "adtech_domains": sum(1 for row in items if "ad" in str(row.get("data_activity_class") or "")),
                "analytics_domains": sum(1 for row in items if "analytics" in str(row.get("data_activity_class") or "")),
                "identity_domains": sum(1 for row in items if "identity" in str(row.get("data_activity_class") or "")),
                "subscription_paywall_domains": sum(
                    1
                    for row in items
                    if "subscription" in str(row.get("data_activity_class") or "")
                    or "paywall" in str(row.get("data_activity_class") or "")
                ),
                "security_or_bot_domains": sum(1 for row in items if "security" in str(row.get("data_activity_class") or "")),
                "content_delivery_domains": sum(1 for row in items if "content" in str(row.get("data_activity_class") or "")),
                "top_destination_classes": " | ".join(f"{k}:{v}" for k, v in destination_classes.most_common(5)),
                "top_service_categories": " | ".join(f"{k}:{v}" for k, v in service_categories.most_common(5)),
                "top_signal_families": " | ".join(f"{k}:{v}" for k, v in signal_families.most_common(5)),
                "ml_readiness": readiness,
                "ml_caveat": caveat,
            }
        )
    return summaries


def _build_root_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("root_domain") or "")].append(row)
    out: list[dict[str, Any]] = []
    for root, items in sorted(grouped.items()):
        if not root:
            continue
        out.append(
            {
                "root_domain": root,
                "domain_rows": len(items),
                "packages_seen": _join_values({str(row.get("package_name") or "") for row in items}),
                "observed_runs": sum(int(row.get("observed_run_count") or 0) for row in items),
                "owner_classes": _join_values({str(row.get("owner_class") or "") for row in items}),
                "service_keys": _join_values({str(row.get("service_key") or "") for row in items}),
                "service_categories": _join_values({str(row.get("service_category") or "") for row in items}),
                "signal_families": _join_values(
                    {
                        family.strip()
                        for row in items
                        for family in str(row.get("signal_families") or "").split("|")
                        if family.strip()
                    }
                ),
                "privacy_relevance_max": _highest_relevance(
                    {str(row.get("privacy_relevance") or "") for row in items}
                ),
                "example_domains": _join_values(
                    [str(row.get("observed_domain") or "") for row in sorted(items, key=lambda r: int(r.get("total_indicator_hits") or 0), reverse=True)[:8]]
                ),
            }
        )
    return out


def _write_markdown_guide(path: Path, summary: Mapping[str, Any]) -> None:
    lines = [
        "# Dynamic Domain ML Context Guide",
        "",
        "This bundle explains runtime domain destinations using payload-free DNS/SNI observations, domain classifications, service-provider mappings, and service-signal taxonomy.",
        "",
        "## Files",
        "",
        "- `domain_ml_context.csv`: one package/domain row enriched with owner class, service provider, signal families, destination class, activity class, and run-level direction context.",
        "- `package_destination_summary.csv`: one package rollup for destination mix and ML readiness.",
        "- `root_domain_summary.csv`: one root-domain rollup across packages.",
        "- `table_dictionary.csv`: table-level explanation for the DB surfaces used by this export.",
        "- `table_schema_columns.csv`: live DB column inventory for the same tables.",
        "",
        "## Modeling Notes",
        "",
        "- Treat `owner_class`, `service_category`, `signal_families`, `destination_class`, and `data_activity_class` as categorical or multi-hot features.",
        "- Use `total_indicator_hits`, `observed_run_count`, and package rollup counts as magnitude/context features, not as byte counts.",
        "- Domain rows are based on DNS/SNI visibility. The system does not inspect payloads and cannot prove the content of data transferred.",
        "- Direction ratios come from `dynamic_network_features` at run grain. They are useful for run behavior, but they are not per-domain byte attribution.",
        "",
        "## Summary",
        "",
        f"- Domain rows: {summary.get('domain_rows')}",
        f"- Packages: {summary.get('packages')}",
        f"- Root domains: {summary.get('root_domains')}",
        f"- Unmapped domain rows: {summary.get('unmapped_domain_rows')}",
        f"- Low-confidence domain rows: {summary.get('low_confidence_domain_rows')}",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate_report(*, packages: list[str] | None = None, output_dir: Path | None = None) -> dict[str, Any]:
    from scytaledroid.Database.db_core import db_queries as core_q

    output_root = output_dir or (
        _REPO_ROOT / "output" / "audit" / "dynamic_domain_ml_context" / datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
    )
    output_root.mkdir(parents=True, exist_ok=True)

    service_rows, service_map_rows, _signals_by_key, signals_by_service = _load_seed_aware_catalogs(core_q)
    raw_domain_rows = _load_domain_rows(core_q, packages or [])
    domain_rows = _build_domain_context_rows(raw_domain_rows, service_rows, service_map_rows, signals_by_service)
    package_rows = _build_package_summary(domain_rows)
    root_rows = _build_root_summary(domain_rows)
    schema_rows = _table_schema_rows(core_q)

    _write_csv(output_root / "domain_ml_context.csv", domain_rows, DOMAIN_CONTEXT_FIELDS)
    _write_csv(output_root / "package_destination_summary.csv", package_rows, PACKAGE_SUMMARY_FIELDS)
    _write_csv(output_root / "root_domain_summary.csv", root_rows, ROOT_SUMMARY_FIELDS)
    _write_csv(output_root / "table_dictionary.csv", list(TABLE_DICTIONARY_ROWS), TABLE_DICTIONARY_FIELDS)
    _write_csv(output_root / "table_schema_columns.csv", schema_rows)

    summary = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "repo_root": str(_REPO_ROOT),
        "packages": len({row.get("package_name") for row in domain_rows}),
        "domain_rows": len(domain_rows),
        "root_domains": len(root_rows),
        "service_catalog_count": len(service_rows),
        "service_domain_map_count": len(service_map_rows),
        "unmapped_domain_rows": sum(1 for row in domain_rows if not row.get("service_key")),
        "low_confidence_domain_rows": sum(1 for row in domain_rows if str(row.get("confidence") or "").lower() == "low"),
        "output_files": {
            "domain_ml_context_csv": str((output_root / "domain_ml_context.csv").resolve()),
            "package_destination_summary_csv": str((output_root / "package_destination_summary.csv").resolve()),
            "root_domain_summary_csv": str((output_root / "root_domain_summary.csv").resolve()),
            "table_dictionary_csv": str((output_root / "table_dictionary.csv").resolve()),
            "table_schema_columns_csv": str((output_root / "table_schema_columns.csv").resolve()),
            "guide_md": str((output_root / "README.md").resolve()),
            "summary_json": str((output_root / "summary.json").resolve()),
        },
        "no_db_writes": True,
        "experimental_audit": True,
    }
    _write_markdown_guide(output_root / "README.md", summary)
    (output_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    summary = generate_report(
        packages=args.package or None,
        output_dir=Path(args.output_dir).expanduser().resolve() if args.output_dir else None,
    )
    if args.stdout_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print("# dynamic domain ML context")
        print(f"domain_rows: {summary['domain_rows']}")
        print(f"packages: {summary['packages']}")
        print(f"root_domains: {summary['root_domains']}")
        print(f"unmapped_domain_rows: {summary['unmapped_domain_rows']}")
        print(f"low_confidence_domain_rows: {summary['low_confidence_domain_rows']}")
        print(f"summary_json: {summary['output_files']['summary_json']}")
        print(f"guide_md: {summary['output_files']['guide_md']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
