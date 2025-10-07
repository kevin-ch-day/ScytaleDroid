"""String extraction helpers for static analysis detectors."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable, Mapping, MutableMapping, Optional, Sequence

from androguard.core.apk import APK


@dataclass(frozen=True)
class IndexedString:
    """Represents a string literal discovered in an APK."""

    value: str
    origin: str = "unknown"
    origin_type: str = "unknown"
    sha256: str = field(init=False)

    def __post_init__(self) -> None:  # pragma: no cover - simple hashing
        object.__setattr__(self, "sha256", hashlib.sha256(self.value.encode("utf-8")).hexdigest())


@dataclass(frozen=True)
class StringIndex:
    """Container with helper lookups for extracted strings."""

    strings: tuple[IndexedString, ...] = ()
    _hash_lookup: Mapping[str, IndexedString] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self._hash_lookup:
            return
        lookup: MutableMapping[str, IndexedString] = {}
        for entry in self.strings:
            lookup.setdefault(entry.sha256, entry)
        object.__setattr__(self, "_hash_lookup", dict(lookup))

    def __len__(self) -> int:
        return len(self.strings)

    def is_empty(self) -> bool:
        return not self.strings

    def get_by_hash(self, sha256: str) -> Optional[IndexedString]:
        return self._hash_lookup.get(sha256)

    def values(self) -> Sequence[str]:
        return tuple(entry.value for entry in self.strings)

    @classmethod
    def empty(cls) -> "StringIndex":
        return cls(strings=tuple())


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
            collected.append(IndexedString(value=value, origin="dex", origin_type="code"))
    except Exception:  # pragma: no cover - defensive against androguard quirks
        pass

    if include_resources:
        try:
            resources = apk.get_android_resources()
        except Exception:
            resources = None
        if resources is not None:
            try:
                for value in _iterate_resource_strings(resources):
                    collected.append(
                        IndexedString(value=value, origin="resources", origin_type="resource")
                    )
            except Exception:  # pragma: no cover - resource parsing varies per APK
                pass

    deduped: dict[str, IndexedString] = {}
    for entry in collected:
        deduped.setdefault(entry.value, entry)

    return StringIndex(strings=tuple(deduped.values()))


def _iterate_resource_strings(resources: object) -> Iterable[str]:
    """Best-effort generator for resource string values."""

    try:
        public = resources.get_resolved_strings()
    except Exception:
        public = None

    if isinstance(public, Mapping):
        for value in public.values():
            if not value:
                continue
            string_value = str(value)
            if string_value.strip():
                yield string_value

    if hasattr(resources, "get_string_resources"):  # pragma: no cover - optional API
        try:
            entries = resources.get_string_resources()
        except Exception:
            entries = None
        if isinstance(entries, Mapping):
            for value in entries.values():
                if not value:
                    continue
                string_value = str(value)
                if string_value.strip():
                    yield string_value


__all__ = ["IndexedString", "StringIndex", "build_string_index"]
