"""High level orchestration for building string indexes."""

from __future__ import annotations

from scytaledroid.StaticAnalysis._androguard import APK

from .models import IndexedString, StringIndex
from .sources import collect_file_strings, iterate_resource_strings


def build_string_index(apk: APK, *, include_resources: bool = True) -> StringIndex:
    """Extract strings from *apk* and return a searchable index."""

    collected: list[IndexedString] = []

    try:
        for raw in apk.get_strings() or []:
            if not raw:
                continue
            value = str(raw)
            if not value.strip():
                continue
            collected.append(IndexedString(value=value, origin="classes.dex", origin_type="code"))
    except Exception:  # pragma: no cover - defensive against androguard quirks
        pass

    if include_resources:
        try:
            resources = apk.get_android_resources()
        except Exception:
            resources = None
        if resources is not None:
            try:
                for value in iterate_resource_strings(resources):
                    collected.append(
                        IndexedString(
                            value=value,
                            origin="resources.arsc",
                            origin_type="resource",
                        )
                    )
            except Exception:  # pragma: no cover - resource parsing varies per APK
                pass

    collected.extend(collect_file_strings(apk))

    deduped: dict[tuple[str, str, str], IndexedString] = {}
    for entry in collected:
        key = (entry.value, entry.origin, entry.origin_type)
        deduped.setdefault(key, entry)

    return StringIndex(strings=tuple(deduped.values()))


__all__ = ["build_string_index"]
