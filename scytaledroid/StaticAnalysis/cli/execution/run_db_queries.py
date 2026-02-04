"""Shared DB-backed helpers for run reporting."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Utils.DisplayUtils import status_messages


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


def _warn_legacy_running_rows() -> None:
    try:
        row = core_q.run_sql(
            """
            SELECT COUNT(*)
            FROM static_analysis_runs
            WHERE status='RUNNING'
              AND ended_at_utc IS NULL
              AND TIMESTAMPDIFF(HOUR, created_at, UTC_TIMESTAMP()) > 24
            """,
            fetch="one",
        )
    except Exception:
        return
    if not row:
        return
    value = row[0] if not isinstance(row, dict) else next(iter(row.values()), 0)
    try:
        count = int(value or 0)
    except (TypeError, ValueError):
        return
    if count <= 0:
        return
    print(
        status_messages.status(
            f"Detected {count} legacy RUNNING rows older than 24h (pre-finalization). No action required.",
            level="warn",
        )
    )


__all__ = ["_apply_display_names", "_warn_legacy_running_rows"]