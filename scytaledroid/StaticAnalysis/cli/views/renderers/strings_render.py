"""String analysis rendering helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from textwrap import fill

from scytaledroid.StaticAnalysis.modules.string_analysis import (
    BUCKET_LABELS,
    BUCKET_METADATA,
    BUCKET_ORDER,
)
from scytaledroid.Utils.System import output_prefs

_WIDTH = 78


def _wrap_lines(text: str, *, indent: int = 2, subsequent_indent: int | None = None) -> list[str]:
    if not text:
        return []
    subsequent = subsequent_indent if subsequent_indent is not None else indent
    return fill(
        text,
        width=_WIDTH,
        initial_indent=" " * indent,
        subsequent_indent=" " * subsequent,
        break_long_words=False,
        break_on_hyphens=False,
    ).splitlines()


def _count_value(key: str, *, source: Mapping[str, object] | None = None) -> int:
    if not source:
        return 0
    try:
        return int(source.get(key) or 0)
    except Exception:
        return 0


def string_lines(string_payload: Mapping[str, object]) -> list[str]:
    lines: list[str] = ["String Analysis"]
    options = string_payload.get("options") if isinstance(string_payload, Mapping) else {}
    aggregates = string_payload.get("aggregates") if isinstance(string_payload, Mapping) else {}
    extra = string_payload.get("extra") if isinstance(string_payload, Mapping) else {}

    if output_prefs.is_compact_mode():
        lines.append("  (compact output)")
        return lines

    counts = string_payload.get("counts") if isinstance(string_payload, Mapping) else None
    if isinstance(counts, Mapping):
        lines.append("  Totals (by bucket)")
        for key in BUCKET_ORDER:
            if key not in counts:
                continue
            label = BUCKET_LABELS.get(key, key)
            lines.append(f"    {label:<24} {counts.get(key)}")

    if isinstance(extra, Mapping):
        extra_counts = extra.get("counts")
        if isinstance(extra_counts, Mapping) and extra_counts:
            lines.append("")
            lines.append("  Extra counters")
            for key, value in extra_counts.items():
                lines.append(f"    {key}={value}")

    if isinstance(extra, Mapping):
        skipped = extra.get("regex_skipped")
        noise_config = extra.get("noise_config")
        if skipped or noise_config:
            lines.append("")
            lines.append("  Noise gate")
            skipped_value = f"{skipped}" if skipped is not None else "—"
            noise_value = f"{noise_config}" if noise_config is not None else "—"
            lines.append(f"    regex_skipped={skipped_value}  noise_config={noise_value}")

    if isinstance(aggregates, Mapping):
        buckets = aggregates.get("buckets")
        if isinstance(buckets, Mapping) and buckets:
            lines.append("")
            lines.append("  Additional buckets")
            for key, data in buckets.items():
                if not isinstance(data, Mapping):
                    continue
                label = BUCKET_METADATA.get(key, None)
                label_name = label.label if label else key
                lines.append(
                    f"    {label_name}: total={data.get('total', 0)}, unique={data.get('unique', 0)}"
                )

    entropy_samples = []
    if isinstance(aggregates, Mapping):
        entropy_entries = aggregates.get("entropy_high_samples")
        if isinstance(entropy_entries, Sequence):
            entropy_samples = [entry for entry in entropy_entries if isinstance(entry, Mapping)]

    if entropy_samples:
        total_entropy = _count_value("entropy_high", source=extra) or len(entropy_samples)
        lines.append("")
        lines.append("  High-Entropy Strings")
        sample_limit = output_prefs.get_string_sample_limit()
        shown = min(len(entropy_samples), max(2, sample_limit))
        try:
            min_entropy = float(options.get("min_entropy", 5.5))
        except Exception:
            min_entropy = 5.5
        lines.append(
            f"    {shown} samples shown (entropy ≥{min_entropy:.2f}); +{max(total_entropy - shown, 0)} more total"
        )
        for entry in entropy_samples[:shown]:
            masked = str(entry.get("masked") or "(hidden)")
            src = str(entry.get("src") or "string")
            detail = f"      {masked}                         Src: {src}"
            lines.extend(_wrap_lines(detail, indent=6, subsequent_indent=8))

    return lines


__all__ = ["string_lines"]
