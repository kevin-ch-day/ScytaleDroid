"""Small helpers for correlation detector runtime-state caches and counters."""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import TypeVar

T = TypeVar("T")

_STATS_KEY = "correlation_runtime_stats"


def runtime_cache(
    runtime_state: MutableMapping[str, object] | None,
    cache_name: str,
) -> MutableMapping[object, object] | None:
    if not isinstance(runtime_state, MutableMapping):
        return None
    cache = runtime_state.get(cache_name)
    if isinstance(cache, MutableMapping):
        return cache
    cache = {}
    runtime_state[cache_name] = cache
    return cache


def record_counter(
    runtime_state: MutableMapping[str, object] | None,
    counter_name: str,
    amount: int = 1,
) -> None:
    if not isinstance(runtime_state, MutableMapping):
        return
    stats = runtime_state.get(_STATS_KEY)
    if not isinstance(stats, MutableMapping):
        stats = {}
        runtime_state[_STATS_KEY] = stats
    current = stats.get(counter_name, 0)
    try:
        current_int = int(current)
    except (TypeError, ValueError):
        current_int = 0
    stats[counter_name] = current_int + int(amount)


def cache_lookup(
    runtime_state: MutableMapping[str, object] | None,
    cache_name: str,
    cache_key: object,
    *,
    hit_counter: str,
    miss_counter: str,
) -> tuple[bool, T | None]:
    cache = runtime_cache(runtime_state, cache_name)
    if cache is None or cache_key not in cache:
        record_counter(runtime_state, miss_counter)
        return False, None
    record_counter(runtime_state, hit_counter)
    return True, cache.get(cache_key)  # type: ignore[return-value]


def cache_store(
    runtime_state: MutableMapping[str, object] | None,
    cache_name: str,
    cache_key: object,
    value: object,
) -> None:
    cache = runtime_cache(runtime_state, cache_name)
    if cache is None:
        return
    cache[cache_key] = value


def snapshot_runtime_stats(
    runtime_state: MutableMapping[str, object] | None,
) -> dict[str, int]:
    if not isinstance(runtime_state, MutableMapping):
        return {}
    stats = runtime_state.get(_STATS_KEY)
    if not isinstance(stats, MutableMapping):
        return {}
    out: dict[str, int] = {}
    for key, value in stats.items():
        try:
            out[str(key)] = int(value)
        except (TypeError, ValueError):
            continue
    return out


__all__ = [
    "cache_lookup",
    "cache_store",
    "record_counter",
    "runtime_cache",
    "snapshot_runtime_stats",
]
