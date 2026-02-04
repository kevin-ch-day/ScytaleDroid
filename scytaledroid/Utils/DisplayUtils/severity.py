"""Colour-aware helpers for rendering severity distributions."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping

from . import colors
from .summary_cards import SummaryCardItem, summary_item

_SEVERITY_ORDER: tuple[tuple[str, str, str], ...] = (
    ("critical", "Critical", "severity_critical"),
    ("high", "High", "severity_high"),
    ("medium", "Medium", "severity_medium"),
    ("low", "Low", "severity_low"),
    ("info", "Info", "severity_info"),
)

_ALIAS_MAP: dict[str, str] = {
    "c": "critical",
    "crit": "critical",
    "criticality": "critical",
    "p0": "critical",
    "sev0": "critical",
    "urgent": "critical",
    "blocker": "critical",
    "h": "high",
    "p1": "high",
    "sev1": "high",
    "sevh": "high",
    "high": "high",
    "m": "medium",
    "p2": "medium",
    "sev2": "medium",
    "medium": "medium",
    "med": "medium",
    "l": "low",
    "p3": "low",
    "sev3": "low",
    "low": "low",
    "minor": "low",
    "i": "info",
    "info": "info",
    "information": "info",
    "note": "info",
    "notes": "info",
    "p4": "info",
    "sev4": "info",
    "informational": "info",
}


def _canonical_key(value: object) -> str | None:
    text = str(value).strip().lower()
    if not text:
        return None
    text = text.replace("-", "").replace("_", "")
    if text in _ALIAS_MAP:
        return _ALIAS_MAP[text]
    if text and text[0] in _ALIAS_MAP:
        # allow single-letter tokens like "H" or "M"
        candidate = _ALIAS_MAP.get(text[0])
        if candidate:
            return candidate
    return None


def _coerce_int(value: object) -> int:
    if isinstance(value, bool):  # bool is int subclass
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if not text:
        return 0
    try:
        numeric = float(text)
    except ValueError:
        return 0
    return int(numeric)


def normalise_counts(counts: Mapping[str, object] | Iterable[tuple[str, object]]) -> dict[str, int]:
    """Normalise severity counts to canonical keys.

    ``counts`` may be a mapping or an iterable of ``(key, value)`` tuples. Keys such as
    ``"H"``, ``"p0"``, ``"high"``, or ``"info"`` are all folded into the canonical
    buckets ``critical``, ``high``, ``medium``, ``low``, ``info``.
    """

    if isinstance(counts, Mapping):
        source_iter = counts.items()
    else:
        source_iter = counts

    totals: Counter[str] = Counter()
    for key, raw_value in source_iter:
        canonical = _canonical_key(key)
        if canonical is None:
            continue
        value = max(0, _coerce_int(raw_value))
        if value:
            totals[canonical] += value
    for canonical, _label, _style in _SEVERITY_ORDER:
        totals.setdefault(canonical, 0)
    return dict(totals)


def severity_summary_items(
    counts: Mapping[str, object] | Iterable[tuple[str, object]],
    *,
    include_zero: bool = True,
) -> list[SummaryCardItem]:
    """Return summary-card entries for the supplied severity ``counts``."""

    totals = normalise_counts(counts)
    items: list[SummaryCardItem] = []
    for key, label, style_name in _SEVERITY_ORDER:
        value = totals.get(key, 0)
        if value or include_zero:
            items.append(summary_item(label, value, value_style=style_name))
    return items


def format_severity_strip(
    counts: Mapping[str, object] | Iterable[tuple[str, object]],
    *,
    include_zero: bool = False,
    short: bool = True,
) -> str:
    """Return a colourised inline summary of severity ``counts``."""

    totals = normalise_counts(counts)
    tokens: list[str] = []
    for key, label, style_name in _SEVERITY_ORDER:
        value = totals.get(key, 0)
        if not value and not include_zero:
            continue
        display_label = label[0] if short else label
        style = colors.style(style_name)
        token = colors.apply(f"{display_label}:{value}", style, bold=value > 0)
        tokens.append(token)
    if not tokens:
        return colors.apply("No findings", colors.style("muted"))
    return " ".join(tokens)


# Delta-specific helpers (new/removed/updated) for reuse across dashboards
DELTA_STYLES = {
    "new": "severity_success",
    "added": "severity_success",
    "removed": "severity_error",
    "deleted": "severity_error",
    "updated": "severity_warning",
    "changed": "severity_warning",
}


def format_delta_token(kind: str, value: object) -> str:
    """Return a colourised inline token for change deltas."""

    canonical = kind.lower().strip()
    style_name = DELTA_STYLES.get(canonical, "muted")
    numeric = str(value).strip()
    palette_style = colors.style(style_name)
    label = canonical.upper()
    return colors.apply(f"{label}:{numeric}", palette_style, bold=True)



__all__ = ["format_severity_strip", "normalise_counts", "severity_summary_items"]
