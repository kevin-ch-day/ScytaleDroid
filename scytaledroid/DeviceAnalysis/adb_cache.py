"""Cache utilities for adb package metadata."""

from __future__ import annotations

import time
from typing import Dict, Generic, Optional, Tuple, TypeVar


T = TypeVar("T")
CacheKey = Tuple[str, str]

DEFAULT_TTL_SECONDS = 300.0


class TTLCache(Generic[T]):
    """Simple TTL cache keyed by (serial, package)."""

    def __init__(self, ttl_seconds: float = DEFAULT_TTL_SECONDS) -> None:
        self._ttl_seconds = ttl_seconds
        self._entries: Dict[CacheKey, Tuple[float, T]] = {}

    def get(self, key: CacheKey) -> Optional[T]:
        entry = self._entries.get(key)
        if entry is None:
            return None
        stored_at, value = entry
        if time.monotonic() - stored_at > self._ttl_seconds:
            self._entries.pop(key, None)
            return None
        return value

    def set(self, key: CacheKey, value: T) -> None:
        self._entries[key] = (time.monotonic(), value)

    def clear(self, serial: Optional[str] = None) -> None:
        if serial is None:
            self._entries.clear()
            return
        keys = [key for key in self._entries if key[0] == serial]
        for key in keys:
            self._entries.pop(key, None)


PACKAGE_PATH_CACHE: TTLCache[list[str]] = TTLCache()
PACKAGE_META_CACHE: TTLCache[dict[str, Optional[str]]] = TTLCache()
