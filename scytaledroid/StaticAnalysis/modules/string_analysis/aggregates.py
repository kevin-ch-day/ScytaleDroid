"""Helpers to build derived aggregates for string-analysis results."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, MutableMapping, Sequence

from .hit_record import StringHit


def _masked_value(hit: StringHit) -> str:
    value = hit.masked or hit.value
    if value == hit.value and len(value) > 8:
        return f"{value[:4]}…{value[-4:]}"
    return value


def summarise_endpoint_roots(
    endpoint_by_root: Mapping[str, Counter[str]],
    domain_sources: Mapping[str, set[str]] | None = None,
) -> list[dict[str, object]]:
    payload: list[dict[str, object]] = []
    for root, scheme_counts in endpoint_by_root.items():
        total = sum(scheme_counts.values())
        payload.append(
            {
                "root_domain": root,
                "total": total,
                "schemes": dict(sorted(scheme_counts.items())),
                "source_types": sorted(domain_sources.get(root, set())) if domain_sources else [],
            }
        )
    payload.sort(key=lambda item: item["total"], reverse=True)
    return payload


def summarise_cleartext_hits(
    endpoint_cleartext: Sequence[StringHit],
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    seen: set[tuple[str, str | None]] = set()
    for hit in endpoint_cleartext:
        key = (hit.value, hit.src)
        if key in seen:
            continue
        seen.add(key)
        results.append(
            {
                "value": hit.value,
                "src": hit.src,
                "root_domain": hit.root_domain,
                "scheme": hit.scheme,
                "risk_tag": hit.risk_tag,
                "confidence": hit.confidence,
            }
        )
    return results


def summarise_api_keys(
    api_key_hits: Sequence[StringHit],
) -> list[dict[str, object]]:
    return [
        {
            "provider": hit.provider,
            "masked": _masked_value(hit),
            "src": hit.src,
            "confidence": hit.confidence,
            "finding_type": hit.finding_type,
            "token_type": hit.tag,
        }
        for hit in api_key_hits
        if hit.confidence != "low"
    ]


def summarise_cloud_refs(
    cloud_hits: Sequence[tuple[StringHit, str | None]],
) -> list[dict[str, object]]:
    return [
        {
            "provider": hit.provider,
            "service": hit.tag,
            "resource": hit.resource_name,
            "region": region,
            "src": hit.src,
        }
        for hit, region in cloud_hits
    ]


def summarise_analytics(
    analytics_vendor_ids: Mapping[str, MutableMapping[str, set[str]]]
) -> dict[str, list[dict[str, object]]]:
    payload: dict[str, list[dict[str, object]]] = {}
    for vendor, src_map in analytics_vendor_ids.items():
        vendor_entries: list[dict[str, object]] = []
        for src_label, identifiers in src_map.items():
            vendor_entries.append(
                {
                    "src": src_label,
                    "ids": sorted(identifiers),
                    "count": len(identifiers),
                }
            )
        vendor_entries.sort(
            key=lambda item: (
                -int(item.get("count", 0) or 0),
                str(item.get("src") or ""),
            )
        )
        payload[vendor] = vendor_entries
    return payload


def summarise_entropy(
    entropy_high_samples: Sequence[StringHit],
    *,
    limit: int = 10,
) -> list[dict[str, object]]:
    return [
        {
            "masked": _masked_value(hit),
            "src": hit.src,
        }
        for hit in entropy_high_samples[:limit]
    ]


def build_aggregates(
    *,
    endpoint_totals: Counter[str],
    endpoint_by_root: Mapping[str, Counter[str]],
    domain_sources: Mapping[str, set[str]],
    endpoint_cleartext: Sequence[StringHit],
    api_key_hits: Sequence[StringHit],
    cloud_hits: Sequence[tuple[StringHit, str | None]],
    analytics_vendor_ids: Mapping[str, MutableMapping[str, set[str]]],
    entropy_high_samples: Sequence[StringHit],
) -> Mapping[str, object]:
    return {
        "endpoint_totals": dict(endpoint_totals),
        "endpoint_roots": summarise_endpoint_roots(endpoint_by_root, domain_sources),
        "endpoint_cleartext": summarise_cleartext_hits(endpoint_cleartext),
        "api_keys_high": summarise_api_keys(api_key_hits),
        "cloud_refs": summarise_cloud_refs(cloud_hits),
        "analytics_ids": summarise_analytics(analytics_vendor_ids),
        "entropy_high_samples": summarise_entropy(entropy_high_samples),
    }


__all__ = [
    "build_aggregates",
    "summarise_analytics",
    "summarise_api_keys",
    "summarise_cleartext_hits",
    "summarise_cloud_refs",
    "summarise_endpoint_roots",
    "summarise_entropy",
]