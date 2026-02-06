"""Shared DB-backed helpers for run reporting."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence

from scytaledroid.Database.db_core import db_queries as core_q


def _apply_display_names(entries: Sequence[dict[str, object]]) -> None:
    packages: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        package = str(entry.get("package") or entry.get("package_name") or "").strip()
        if not package:
            continue
        lowered = package.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        packages.append(lowered)

    if not packages:
        return

    placeholders = ", ".join(["%s"] * len(packages))
    try:
        rows = core_q.run_sql(
            f"SELECT package_name, display_name FROM apps WHERE package_name IN ({placeholders})",
            tuple(packages),
            fetch="all",
            dictionary=True,
        )
    except Exception:
        return

    display_map: dict[str, str] = {}
    for row in rows or []:
        pkg = str(row.get("package_name") or "").strip().lower()
        label = str(row.get("display_name") or "").strip()
        if pkg and label:
            display_map[pkg] = label

    if not display_map:
        return

    for entry in entries:
        if not isinstance(entry, MutableMapping):
            continue
        package = str(entry.get("package") or entry.get("package_name") or "").strip()
        if not package:
            continue
        label = display_map.get(package.lower())
        if not label:
            continue
        entry["display_name"] = label
        entry["label"] = label


__all__ = ["_apply_display_names"]
