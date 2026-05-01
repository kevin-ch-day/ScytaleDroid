"""Small pure helpers for deduplicating profile rows in run result rendering."""

from __future__ import annotations

from collections.abc import Mapping, Sequence


def dedupe_profile_entries(entries: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    """Keep first row per package / label / package_name key; preserve anonymous rows."""
    seen: set[str] = set()
    deduped: list[dict[str, object]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            deduped.append(entry)
            continue
        key_token = entry.get("package") or entry.get("label") or entry.get("package_name")
        label = str(key_token or "").strip()
        if not label:
            deduped.append(entry)
            continue
        if label in seen:
            continue
        seen.add(label)
        deduped.append(entry)
    return deduped


__all__ = ["dedupe_profile_entries"]
