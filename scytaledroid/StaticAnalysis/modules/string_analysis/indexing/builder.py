"""High level orchestration for building string indexes."""

from __future__ import annotations

from scytaledroid.StaticAnalysis._androguard import APK

from .models import IndexedString, StringIndex
from .sources import collect_file_strings


def build_string_index(apk: APK, *, include_resources: bool = True) -> StringIndex:
    """Extract strings from *apk* and return a searchable index."""

    collected: tuple[IndexedString, ...] = collect_file_strings(apk)

    if not include_resources:
        filtered = tuple(entry for entry in collected if entry.origin_type not in {"res"})
    else:
        filtered = collected

    return StringIndex(strings=filtered)


__all__ = ["build_string_index"]
