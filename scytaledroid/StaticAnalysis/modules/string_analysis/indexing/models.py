"""Data models for indexed strings."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable, Collection, Mapping, MutableMapping, Optional, Pattern, Sequence

from .utils import ensure_pattern


@dataclass(frozen=True)
class IndexedString:
    """Represents a string literal discovered in an APK."""

    value: str
    origin: str = "unknown"
    origin_type: str = "unknown"
    confidence: str = "normal"
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

    def filter(self, predicate: Callable[[IndexedString], bool]) -> tuple[IndexedString, ...]:
        """Return entries matching *predicate*."""

        return tuple(entry for entry in self.strings if predicate(entry))

    def search(
        self,
        pattern: Pattern[str] | str,
        *,
        origin_types: Collection[str] | None = None,
        min_length: int = 0,
        limit: int | None = None,
    ) -> tuple[IndexedString, ...]:
        """Return strings matching *pattern* with optional filters."""

        compiled = ensure_pattern(pattern)
        matches: list[IndexedString] = []
        for entry in self.strings:
            if origin_types and entry.origin_type not in origin_types:
                continue
            if min_length and len(entry.value) < min_length:
                continue
            if not compiled.search(entry.value):
                continue
            matches.append(entry)
            if limit is not None and len(matches) >= limit:
                break
        return tuple(matches)

    def counts_by_origin_type(self) -> Mapping[str, int]:
        """Return a frequency table for recorded origin types."""

        counts: MutableMapping[str, int] = {}
        for entry in self.strings:
            counts[entry.origin_type] = counts.get(entry.origin_type, 0) + 1
        return dict(counts)

    @classmethod
    def empty(cls) -> "StringIndex":
        return cls(strings=tuple())


__all__ = ["IndexedString", "StringIndex"]
