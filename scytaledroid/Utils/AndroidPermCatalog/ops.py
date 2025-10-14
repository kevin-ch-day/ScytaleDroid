from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from . import api
from .group_map import attach_groups as _attach_groups


@dataclass(frozen=True)
class Catalog:
    path: Optional[Path]
    items: list


def load_cached_or_refresh(cache_path: Path, *, source: str = "auto") -> Catalog:
    """Load catalog from cache if present, otherwise refresh and persist."""
    if cache_path.exists():
        try:
            items = api.load_catalog_json(cache_path)
            return Catalog(path=cache_path, items=items)
        except Exception as exc:
            log.warning(f"Failed to load cached permission catalog: {exc}", category="application")

    try:
        items = api.load_catalog(source)  # type: ignore[arg-type]
    except Exception as exc:
        print(status_messages.status(f"Unable to refresh catalog: {exc}", level="error"))
        return Catalog(path=None, items=[])

    try:
        api.save_catalog_json(cache_path, items, source=source)
    except Exception as exc:
        log.warning(f"Unable to write catalog cache: {exc}", category="application")
    return Catalog(path=cache_path, items=items)


def list_snapshot_files(cache_path: Path) -> list[Path]:
    base = cache_path.parent
    stem, suffix = cache_path.stem, cache_path.suffix
    return sorted([p for p in base.glob(f"{stem}.*{suffix}") if p.is_file()])


def export_csv(cache_path: Path, items) -> Optional[Path]:
    import csv
    out_path = cache_path.with_suffix(".csv")
    try:
        with out_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["short", "constant", "protection", "tokens", "added_api", "added_version", "group"]) 
            for p in items:
                writer.writerow([
                    p.short,
                    p.name,
                    p.protection or "-",
                    "|".join(p.protection_tokens or ()),
                    p.added_api if p.added_api is not None else "-",
                    p.added_version or "-",
                    p.group or "-",
                ])
        return out_path
    except Exception as exc:
        print(status_messages.status(f"Failed to write CSV: {exc}", level="error"))
        return None


def purge_old_snapshots(cache_path: Path) -> int:
    removed = 0
    for path in list_snapshot_files(cache_path):
        try:
            path.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def counts_by_protection(items) -> list[list[str]]:
    from collections import Counter

    c = Counter((entry.protection or "-") for entry in items)
    rows: list[list[str]] = []
    for key, value in sorted(c.items(), key=lambda kv: (kv[0] != "-", kv[0])):
        rows.append([key, str(value)])
    return rows


def find_entry(items, query: str):
    q = query.strip()
    by_const = api.index_by_constant(items)
    if q in by_const:
        return by_const[q]
    by_short = api.index_by_short(items)
    return by_short.get(q) or by_short.get(q.upper())


def attach_groups(items) -> int:
    """Attach permission groups from SDK where possible; returns update count."""
    return _attach_groups(items)


__all__ = [
    "Catalog",
    "load_cached_or_refresh",
    "list_snapshot_files",
    "export_csv",
    "purge_old_snapshots",
    "counts_by_protection",
    "find_entry",
    "attach_groups",
]

