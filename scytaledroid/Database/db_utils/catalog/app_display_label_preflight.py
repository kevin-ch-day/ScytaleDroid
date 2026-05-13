"""Read-only `apps.display_name` coverage for static selection groups (preflight / menus)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any


def _selection_display_label_progress(groups: Sequence[Any]) -> tuple[int, int, tuple[str, ...]] | None:
    """Return ``(labeled, total, missing_keys_lower)`` or ``None`` when unavailable."""

    if not groups:
        return None
    try:
        from scytaledroid.Database.db_core import db_config
    except Exception:
        return None
    if not db_config.db_enabled():
        return None
    try:
        from scytaledroid.StaticAnalysis.core.repository import load_display_name_map
    except Exception:
        return None

    keys = sorted(
        {
            str(getattr(g, "package_name", "") or "").strip().lower()
            for g in groups
            if str(getattr(g, "package_name", "") or "").strip()
        }
    )
    total = len(keys)
    if total == 0:
        return None
    try:
        dmap = load_display_name_map(groups)
    except Exception:
        return None
    labeled = sum(1 for k in keys if (dmap.get(k) or "").strip())
    miss = tuple(k for k in keys if not (dmap.get(k) or "").strip())
    return labeled, total, miss


def _resolve_latest_inventory_snapshot_id() -> int | None:
    try:
        from scytaledroid.Database.db_core.db_queries import run_sql
    except Exception:
        return None
    try:
        row = run_sql(
            "SELECT MAX(snapshot_id) FROM device_inventory_snapshots",
            fetch="one",
            query_name="preflight.latest_inventory_snapshot",
        )
    except Exception:
        return None
    if not row or row[0] is None:
        return None
    try:
        return int(row[0])
    except (TypeError, ValueError):
        return None


def _count_play_store_focus_bucket_hits(
    snapshot_id: int,
    package_lowers: tuple[str, ...],
) -> int | None:
    """How many *distinct* packages from *package_lowers* appear in the hygiene focus bucket.

    Mirrors ``scripts/db/report_app_label_hygiene.py`` Play/Unclassified focus filters
    (empty ``apps.display_name``, ``app_label`` equals package, vending installer, etc.).
    """

    if not package_lowers:
        return 0
    try:
        from scytaledroid.Database.db_core.db_queries import run_sql
    except Exception:
        return None
    placeholders = ",".join(["%s"] * len(package_lowers))
    params: tuple[Any, ...] = (snapshot_id, *package_lowers)
    sql = f"""
        SELECT COUNT(DISTINCT LOWER(di.package_name))
        FROM device_inventory di
        LEFT JOIN apps a ON LOWER(di.package_name) = LOWER(a.package_name)
        WHERE di.snapshot_id = %s
          AND LOWER(di.package_name) IN ({placeholders})
          AND di.source_label = 'Play Store'
          AND di.profile_name = 'Unclassified'
          AND di.partition_label = 'Data (/data)'
          AND di.installer = 'com.android.vending'
          AND di.review_needed = 1
          AND (a.display_name IS NULL OR TRIM(IFNULL(a.display_name, '')) = '')
          AND LOWER(TRIM(IFNULL(di.app_label, ''))) = LOWER(TRIM(di.package_name))
    """
    try:
        row = run_sql(
            sql,
            params,
            fetch="one",
            query_name="preflight.play_store_focus_bucket_hits",
        )
    except Exception:
        return None
    if not row or row[0] is None:
        return None
    try:
        return int(row[0])
    except (TypeError, ValueError):
        return None


def summarize_apps_display_labels_for_groups(groups: Sequence[Any]) -> tuple[int, int] | None:
    """Return ``(labeled_count, total_packages)`` for the selection, or ``None`` if unavailable.

    A package counts as *labeled* when ``apps.display_name`` is non-empty for that
    ``package_name`` (case-insensitive lookup). Does **not** read ``device_inventory`` and
    does **not** apply CSV overrides.
    """

    prog = _selection_display_label_progress(groups)
    if prog is None:
        return None
    labeled, total, _miss = prog
    return labeled, total


def format_apps_display_name_hygiene_line(groups: Sequence[Any]) -> str | None:
    """One-line operator summary, or ``None`` when skipped."""

    try:
        from scytaledroid.Database.db_core import db_config
    except Exception:
        return None
    if not db_config.db_enabled():
        return "Display labels: skipped (primary DB not configured)"

    prog = _selection_display_label_progress(groups)
    if prog is None:
        return None
    labeled, total, miss_keys = prog
    need = max(0, total - labeled)
    base = (
        f"Display labels: {labeled}/{total} labeled · {need} need review — "
        "review: Database Tools → option 8 (Catalog hygiene), or "
        "`PYTHONPATH=. python scripts/db/report_app_label_hygiene.py`"
    )
    if need <= 0 or not miss_keys:
        return base
    snap_id = _resolve_latest_inventory_snapshot_id()
    if snap_id is None:
        return base
    in_focus = _count_play_store_focus_bucket_hits(snap_id, miss_keys)
    if in_focus is None:
        return base
    outside = need - in_focus
    if outside <= 0:
        return base
    return (
        f"{base} · Play/Unclassified hygiene focus matches {in_focus}/{need} empty "
        f"display_name packages ({outside} outside that bucket: non-vending, different "
        "source/profile/partition, review_needed≠1, inventory app_label≠package, or not "
        f"in latest inventory snapshot {snap_id})"
    )


__all__ = [
    "format_apps_display_name_hygiene_line",
    "summarize_apps_display_labels_for_groups",
]
