# File: permission_protection_lookup.py
"""Framework permission protection-level lookups."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import yaml

_FALLBACK_PROTECTION_CACHE: dict[str, dict[str, object]] | None = None


def _load_fallback_protections() -> dict[str, dict[str, object]]:
    global _FALLBACK_PROTECTION_CACHE
    if _FALLBACK_PROTECTION_CACHE is not None:
        return _FALLBACK_PROTECTION_CACHE

    mapping: dict[str, dict[str, object]] = {}
    path = Path("config/framework_permissions.yaml")
    if path.exists():
        try:
            with path.open("r", encoding="utf-8") as handle:
                payload = yaml.safe_load(handle) or []
            if isinstance(payload, list):
                for item in payload:
                    if not isinstance(item, dict):
                        continue
                    short = str(item.get("short") or item.get("perm_name") or "").upper()
                    if not short:
                        continue
                    mapping[short] = item
        except Exception:
            mapping = {}
    _FALLBACK_PROTECTION_CACHE = mapping
    return _FALLBACK_PROTECTION_CACHE


def _fetch_protections(
    names: list[str],
    target_sdk: int | None = None,
) -> Mapping[str, str | None]:
    """Best-effort DB lookup of framework protection levels for given names.

    Returns a mapping of perm_name -> protection or None. On any error, returns
    an empty mapping.
    """
    try:  # optional DB dependency
        from scytaledroid.Database.db_func.permissions.permission_dicts import (
            fetch_aosp_protection_map,
        )

        db_map = fetch_aosp_protection_map(names, target_sdk=target_sdk)
    except Exception:
        db_map = {}

    names_upper = {str(name).upper() for name in names}
    results: dict[str, str | None] = {
        key.upper(): value for key, value in (db_map or {}).items()
    }

    missing = [name for name in names_upper if name not in results]
    if missing:
        fallback = _load_fallback_protections()
        for name in missing:
            entry = fallback.get(name)
            if not entry:
                continue
            added = entry.get("added_api")
            deprecated = entry.get("deprecated_api")
            if target_sdk is not None:
                try:
                    added_int = int(added) if added is not None else None
                except (TypeError, ValueError):
                    added_int = None
                try:
                    deprecated_int = int(deprecated) if deprecated is not None else None
                except (TypeError, ValueError):
                    deprecated_int = None
                if added_int is not None and target_sdk < added_int:
                    continue
                if deprecated_int is not None and target_sdk >= deprecated_int:
                    pass
            protection = entry.get("protection")
            results[name] = str(protection) if protection not in (None, "") else None

    return results


__all__ = ["_fetch_protections"]