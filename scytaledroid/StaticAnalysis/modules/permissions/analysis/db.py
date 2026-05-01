"""DB helpers for permission analysis."""

from __future__ import annotations

from collections.abc import Iterable, Mapping


def fetch_framework_protections(short_names: Iterable[str]) -> Mapping[str, str | None]:
    """Return mapping of permission SHORT name -> protection from DB, if available.

    Falls back to an empty mapping when DB is not configured or query fails.
    """

    names = [n for n in set(short_names) if isinstance(n, str) and n]
    if not names:
        return {}
    try:
        from scytaledroid.Database.db_func.permissions.permission_dicts import (
            fetch_aosp_protection_map,
        )

        return fetch_aosp_protection_map(names)
    except Exception:
        return {}


__all__ = ["fetch_framework_protections"]