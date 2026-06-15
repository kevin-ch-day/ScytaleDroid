"""Read-only helpers for correlating static string indicators with dynamic evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence


def correlate_static_roots_with_dynamic_indicators(
    *,
    static_roots: Sequence[str],
    dynamic_indicators: Sequence[str],
) -> dict[str, object]:
    static_set = {str(item or "").strip().lower() for item in static_roots if str(item or "").strip()}
    dynamic_set = {str(item or "").strip().lower() for item in dynamic_indicators if str(item or "").strip()}
    matched = sorted(static_set & dynamic_set)
    unmatched_static = sorted(static_set - dynamic_set)
    unmatched_dynamic = sorted(dynamic_set - static_set)
    status = "matched" if matched else "unavailable"
    return {
        "status": status,
        "matched_roots": matched,
        "matched_count": len(matched),
        "static_root_count": len(static_set),
        "dynamic_indicator_count": len(dynamic_set),
        "unmatched_static_roots": unmatched_static,
        "unmatched_dynamic_indicators": unmatched_dynamic,
    }


def dynamic_indicators_from_report(report: Mapping[str, object] | None) -> list[str]:
    if not isinstance(report, Mapping):
        return []
    indicators: list[str] = []
    for key in ("top_dns", "top_sni"):
        rows = report.get(key)
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
            continue
        for row in rows:
            if isinstance(row, Mapping):
                value = str(row.get("value") or "").strip().lower()
                if value:
                    indicators.append(value)
    return indicators


__all__ = [
    "correlate_static_roots_with_dynamic_indicators",
    "dynamic_indicators_from_report",
]
