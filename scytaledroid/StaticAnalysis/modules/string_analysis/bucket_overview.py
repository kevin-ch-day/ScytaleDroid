"""File: scytaledroid/StaticAnalysis/modules/string_analysis/bucket_overview.py

Helpers for building structured bucket summaries for reporting."""

from __future__ import annotations

from collections import Counter
from typing import Mapping, Sequence

from .hit_record import StringHit


def _top_value_payload(hits: Sequence[StringHit]) -> list[dict[str, object]]:
    counter = Counter(hit.value for hit in hits)
    top_entries: list[dict[str, object]] = []
    for value, count in counter.most_common(5):
        value_hits = [hit for hit in hits if hit.value == value]
        sources = sorted({hit.src for hit in value_hits if hit.src})
        tags = sorted({hit.tag for hit in value_hits if hit.tag})
        providers = sorted({hit.provider for hit in value_hits if hit.provider})
        risks = sorted({hit.risk_tag for hit in value_hits if hit.risk_tag})
        example = next(
            (
                hit
                for hit in value_hits
                if hit.masked or hit.tag or hit.provider or hit.risk_tag
            ),
            None,
        )
        top_entries.append(
            {
                "value": value,
                "count": count,
                "sources": sources[:5],
                "source_total": len(sources),
                "tags": tags[:5],
                "providers": providers[:5],
                "risk_tags": risks[:5],
                "example": {
                    key: getattr(example, key)
                    for key in (
                        "src",
                        "masked",
                        "tag",
                        "provider",
                        "risk_tag",
                        "confidence",
                    )
                    if example and getattr(example, key)
                }
                if example
                else None,
            }
        )
    return top_entries


def build_bucket_overview(
    samples: Mapping[str, Sequence[StringHit]],
    counts: Mapping[str, int],
) -> Mapping[str, object]:
    """Summarise collected hits for presentation and storage."""

    bucket_summaries: dict[str, Mapping[str, object]] = {}
    bucket_order: list[str] = []
    overall_sources: Counter[str] = Counter()

    for bucket, hits in samples.items():
        if not hits:
            continue

        bucket_order.append(bucket)
        unique_values = len({hit.value for hit in hits})
        source_types: Counter[str] = Counter(hit.source_type for hit in hits if hit.source_type)
        top_sources = Counter(hit.src for hit in hits if hit.src).most_common(5)
        tags = sorted({hit.tag for hit in hits if hit.tag})
        risks = sorted({hit.risk_tag for hit in hits if hit.risk_tag})

        bucket_summaries[bucket] = {
            "bucket": bucket,
            "total": counts.get(bucket, len(hits)),
            "unique_values": unique_values,
            "top_values": _top_value_payload(hits),
            "source_types": dict(source_types),
            "top_sources": [list(row) for row in top_sources],
            "tags": tags,
            "risk_tags": risks,
        }

        for source_type, value in source_types.items():
            overall_sources[source_type] += value

    return {
        "buckets": bucket_summaries,
        "order": bucket_order,
        "source_totals": dict(overall_sources),
    }


__all__ = ["build_bucket_overview"]
