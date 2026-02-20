"""Formatting helpers for static analysis output."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

from scytaledroid.Utils.DisplayUtils import colors


def _hash_prefix(value: str | None, *, prefix: int = 4, suffix: int = 4) -> str | None:
    if not value or not isinstance(value, str):
        return None
    if len(value) <= (prefix + suffix + 2):
        return value
    return f"{value[:prefix]}…{value[-suffix:]}"


def _percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    k = (len(ordered) - 1) * pct
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(ordered[int(k)])
    d0 = ordered[f] * (c - k)
    d1 = ordered[c] * (k - f)
    return float(d0 + d1)


def _format_highlight_tokens(
    stats: Mapping[str, int],
    totals: Mapping[str, int],
    app_count: int,
) -> list[str]:
    tokens: list[str] = []
    providers = stats.get("providers", 0)
    if providers:
        tokens.append(
            f"{providers} exported provider{'s' if providers != 1 else ''} lacking strong guards"
        )
    guard = stats.get("nsc_guard", 0)
    if guard:
        tokens.append(
            f"NSC blocks cleartext in {guard}/{app_count} app{'s' if guard != 1 else ''}"
        )
    suppressed = stats.get("secrets_suppressed", 0)
    if suppressed:
        tokens.append(
            f"{suppressed} secret hit{'s' if suppressed != 1 else ''} auto-suppressed"
        )
    if not tokens:
        high = totals.get("high", 0) + totals.get("critical", 0)
        if high:
            tokens.append(
                f"{high} high-severity finding{'s' if high != 1 else ''} require review"
            )
        else:
            tokens.append("No high-severity findings detected")
    return tokens


def _format_masvs_cell(area_counts: Mapping[str, int] | None) -> str:
    if not isinstance(area_counts, Mapping):
        summary = "N/A"
        if colors.colors_enabled():
            return colors.apply(summary, colors.style("muted"), bold=True)
        return summary
    high = int(area_counts.get("High", 0))
    medium = int(area_counts.get("Medium", 0))
    if high > 0:
        status = "FAIL"
        palette = colors.style("error")
    elif medium > 0:
        status = "WARN"
        palette = colors.style("warning")
    else:
        status = "PASS"
        palette = colors.style("success")
    summary = f"{status} H{high}/M{medium}"
    if colors.colors_enabled():
        return colors.apply(summary, palette, bold=True)
    return summary


def _normalize_target_sdk(value: object) -> str:
    if value in (None, ""):
        return "—"
    try:
        return str(int(value))
    except Exception:
        return str(value)


__all__ = [
    "_format_highlight_tokens",
    "_format_masvs_cell",
    "_hash_prefix",
    "_normalize_target_sdk",
    "_percentile",
]
