"""Read-only service/provider/signal summaries derived from PCAP top DNS/SNI indicators."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
from typing import Any

from scytaledroid.DynamicAnalysis.domain_context import normalize_domain
from scytaledroid.DynamicAnalysis.service_context import (
    default_service_catalog_seed_rows,
    default_service_domain_map_seed_rows,
    resolve_service_for_domain,
)
from scytaledroid.DynamicAnalysis.service_signals import (
    default_service_signal_map_seed_rows,
    default_signal_catalog_seed_rows,
)


def summarize_pcap_service_context(
    report: Mapping[str, Any],
    *,
    package_name: str,
) -> dict[str, dict[str, Any]]:
    observed_domains = _aggregate_domain_observations(report)
    package_key = str(package_name or "").strip().lower()
    if not observed_domains:
        return {
            "service_context": {
                "status": "no_observations",
                "package_name": package_key or None,
                "observed_domain_count": 0,
                "resolved_domain_count": 0,
                "unresolved_domain_count": 0,
                "service_count": 0,
                "owner_class_hit_counts": {},
                "service_category_hit_counts": {},
                "role_class_hit_counts": {},
                "services": [],
                "unresolved_domains": [],
            },
            "service_signals": {
                "status": "no_observations",
                "package_name": package_key or None,
                "signal_count": 0,
                "signal_observation_count": 0,
                "focus_area_hit_counts": {},
                "severity_hit_counts": {},
                "signal_family_hit_counts": {},
                "signals": [],
                "services_without_signal_mappings": [],
            },
        }

    service_rows = tuple(default_service_catalog_seed_rows())
    service_map_rows = tuple(default_service_domain_map_seed_rows())
    signal_rows = tuple(default_signal_catalog_seed_rows())
    service_signal_rows = tuple(default_service_signal_map_seed_rows())

    signals_by_key = {str(row.get("signal_key") or ""): dict(row) for row in signal_rows}
    signal_maps_by_service: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in service_signal_rows:
        signal_maps_by_service[str(row.get("service_key") or "")].append(dict(row))

    owner_class_hits: Counter[str] = Counter()
    service_category_hits: Counter[str] = Counter()
    role_class_hits: Counter[str] = Counter()
    service_rollups: dict[str, dict[str, Any]] = {}
    unresolved_domains: list[dict[str, Any]] = []
    signal_rollups: dict[str, dict[str, Any]] = {}
    services_without_signal_mappings: set[str] = set()

    for observed in observed_domains:
        resolved = resolve_service_for_domain(
            observed["domain"],
            package_name=package_key,
            service_rows=service_rows,
            map_rows=service_map_rows,
        )
        total_hits = int(observed.get("total_hits") or 0)
        sources = list(observed.get("indicator_sources") or [])
        service_key = str(resolved.get("service_key") or "")
        if not service_key:
            unresolved_domains.append(
                {
                    "domain": observed["domain"],
                    "root_domain": observed["root_domain"],
                    "total_hits": total_hits,
                    "indicator_sources": sources,
                }
            )
            continue

        owner_class = str(resolved.get("owner_class") or "")
        service_category = str(resolved.get("service_category") or "")
        role_class = str(resolved.get("role_class") or "")
        if owner_class:
            owner_class_hits[owner_class] += total_hits
        if service_category:
            service_category_hits[service_category] += total_hits
        if role_class:
            role_class_hits[role_class] += total_hits

        service_row = service_rollups.setdefault(
            service_key,
            {
                "service_key": service_key,
                "service_display_name": resolved.get("service_display_name"),
                "owner_name": resolved.get("owner_name"),
                "owner_class": resolved.get("owner_class"),
                "service_category": resolved.get("service_category"),
                "primary_use_case": resolved.get("primary_use_case"),
                "confidence": resolved.get("confidence"),
                "source_url": resolved.get("source_url"),
                "total_hits": 0,
                "domain_count": 0,
                "indicator_sources": set(),
                "domains": [],
            },
        )
        service_row["total_hits"] = int(service_row.get("total_hits") or 0) + total_hits
        service_row["domain_count"] = int(service_row.get("domain_count") or 0) + 1
        service_row["indicator_sources"].update(sources)
        service_row["domains"].append(
            {
                "domain": observed["domain"],
                "root_domain": observed["root_domain"],
                "total_hits": total_hits,
                "role_class": resolved.get("role_class"),
                "indicator_sources": sources,
                "match_type": resolved.get("match_type"),
                "package_name_scope": resolved.get("package_name_scope"),
            }
        )

        signal_maps = signal_maps_by_service.get(service_key) or []
        if not signal_maps:
            services_without_signal_mappings.add(service_key)
            continue
        for signal_map in signal_maps:
            signal_key = str(signal_map.get("signal_key") or "")
            signal = signals_by_key.get(signal_key)
            if not signal:
                continue
            signal_row = signal_rollups.setdefault(
                signal_key,
                {
                    "signal_key": signal_key,
                    "signal_display_name": signal.get("display_name"),
                    "signal_family": signal.get("signal_family"),
                    "focus_area": signal.get("focus_area"),
                    "severity_hint": signal.get("severity_hint"),
                    "description": signal.get("description"),
                    "analyst_guidance": signal.get("analyst_guidance"),
                    "total_hits": 0,
                    "observed_domain_count": 0,
                    "service_keys": set(),
                    "services": [],
                },
            )
            signal_row["total_hits"] = int(signal_row.get("total_hits") or 0) + total_hits
            signal_row["observed_domain_count"] = int(signal_row.get("observed_domain_count") or 0) + 1
            signal_row["service_keys"].add(service_key)
            signal_row["services"].append(
                {
                    "service_key": service_key,
                    "service_display_name": resolved.get("service_display_name"),
                    "domain": observed["domain"],
                    "total_hits": total_hits,
                    "signal_strength": signal_map.get("signal_strength"),
                    "signal_confidence": signal_map.get("confidence"),
                }
            )

    service_rows_out = sorted(
        (_finalize_service_row(row) for row in service_rollups.values()),
        key=lambda row: (-int(row.get("total_hits") or 0), str(row.get("service_key") or "")),
    )
    unresolved_rows_out = sorted(
        unresolved_domains,
        key=lambda row: (-int(row.get("total_hits") or 0), str(row.get("domain") or "")),
    )
    signal_rows_out = sorted(
        (_finalize_signal_row(row) for row in signal_rollups.values()),
        key=lambda row: (-int(row.get("total_hits") or 0), str(row.get("signal_key") or "")),
    )

    focus_area_hits = Counter()
    severity_hits = Counter()
    signal_family_hits = Counter()
    for row in signal_rows_out:
        total_hits = int(row.get("total_hits") or 0)
        focus_area = str(row.get("focus_area") or "")
        severity_hint = str(row.get("severity_hint") or "")
        signal_family = str(row.get("signal_family") or "")
        if focus_area:
            focus_area_hits[focus_area] += total_hits
        if severity_hint:
            severity_hits[severity_hint] += total_hits
        if signal_family:
            signal_family_hits[signal_family] += total_hits

    return {
        "service_context": {
            "status": "ok",
            "package_name": package_key or None,
            "observed_domain_count": len(observed_domains),
            "resolved_domain_count": sum(1 for row in observed_domains if row["domain"] not in {item["domain"] for item in unresolved_rows_out}),
            "unresolved_domain_count": len(unresolved_rows_out),
            "service_count": len(service_rows_out),
            "owner_class_hit_counts": dict(sorted(owner_class_hits.items())),
            "service_category_hit_counts": dict(sorted(service_category_hits.items())),
            "role_class_hit_counts": dict(sorted(role_class_hits.items())),
            "services": service_rows_out,
            "unresolved_domains": unresolved_rows_out,
        },
        "service_signals": {
            "status": "ok" if signal_rows_out else "no_signal_hits",
            "package_name": package_key or None,
            "signal_count": len(signal_rows_out),
            "signal_observation_count": sum(int(row.get("observed_domain_count") or 0) for row in signal_rows_out),
            "focus_area_hit_counts": dict(sorted(focus_area_hits.items())),
            "severity_hit_counts": dict(sorted(severity_hits.items())),
            "signal_family_hit_counts": dict(sorted(signal_family_hits.items())),
            "signals": signal_rows_out,
            "services_without_signal_mappings": sorted(services_without_signal_mappings),
        },
    }


def _aggregate_domain_observations(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    domains: dict[str, dict[str, Any]] = {}
    for indicator_key, items in (("top_dns", report.get("top_dns")), ("top_sni", report.get("top_sni"))):
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, Mapping):
                continue
            domain = normalize_domain(item.get("value"))
            if not domain:
                continue
            try:
                count = int(item.get("count") or 0)
            except (TypeError, ValueError):
                count = 0
            row = domains.setdefault(
                domain,
                {
                    "domain": domain,
                    "root_domain": _root_domain_fallback(domain),
                    "total_hits": 0,
                    "indicator_sources": set(),
                },
            )
            row["total_hits"] = int(row.get("total_hits") or 0) + max(count, 0)
            row["indicator_sources"].add(indicator_key)
    rows = []
    for row in domains.values():
        rows.append(
            {
                "domain": row["domain"],
                "root_domain": row["root_domain"],
                "total_hits": int(row.get("total_hits") or 0),
                "indicator_sources": sorted(row.get("indicator_sources") or []),
            }
        )
    rows.sort(key=lambda row: (-int(row.get("total_hits") or 0), str(row.get("domain") or "")))
    return rows


def _finalize_service_row(row: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(row)
    out["indicator_sources"] = sorted(out.get("indicator_sources") or [])
    domains = list(out.get("domains") or [])
    domains.sort(key=lambda item: (-int(item.get("total_hits") or 0), str(item.get("domain") or "")))
    out["domains"] = domains
    return out


def _finalize_signal_row(row: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(row)
    service_keys = sorted(out.get("service_keys") or [])
    out["service_keys"] = service_keys
    out["service_count"] = len(service_keys)
    services = list(out.get("services") or [])
    services.sort(
        key=lambda item: (
            -int(item.get("total_hits") or 0),
            str(item.get("service_key") or ""),
            str(item.get("domain") or ""),
        )
    )
    out["services"] = services
    return out


def _root_domain_fallback(domain: str) -> str:
    parts = str(domain or "").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return str(domain or "")


__all__ = ["summarize_pcap_service_context"]
