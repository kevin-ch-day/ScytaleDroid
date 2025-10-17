from __future__ import annotations

import argparse

from .constants import DEFAULT_CACHE
from .ops import counts_by_protection, find_entry, load_cached_or_refresh


def main() -> None:
    parser = argparse.ArgumentParser(description="Android permissions catalog utility")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("refresh", help="Refresh catalog (SDK/online) and write JSON cache")
    sub.add_parser("counts", help="Show counts by protection level (uses cache or refresh)")
    find_p = sub.add_parser("find", help="Lookup a permission by short name or constant")
    find_p.add_argument("query", help="e.g. CAMERA or android.permission.CAMERA")
    sub.add_parser("write-db", help="Write the framework catalog to the database")

    args = parser.parse_args()

    if not args.cmd:
        _ = load_cached_or_refresh(DEFAULT_CACHE)
        print(f"Catalog ready at {DEFAULT_CACHE}")
        return

    if args.cmd == "refresh":
        cat = load_cached_or_refresh(DEFAULT_CACHE)
        if cat.items:
            print(f"Refreshed {len(cat.items)} entries → {DEFAULT_CACHE}")
        return

    if args.cmd == "counts":
        cat = load_cached_or_refresh(DEFAULT_CACHE)
        if cat.items:
            rows = counts_by_protection(cat.items)
            print("Protection,Count")
            for k, v in rows:
                print(f"{k},{v}")
        return

    if args.cmd == "write-db":
        from scytaledroid.Database.db_func.permissions import framework_permissions as fp
        if not fp.table_exists() and not fp.ensure_table():
            raise SystemExit("Unable to prepare android_framework_permissions table.")
        cat = load_cached_or_refresh(DEFAULT_CACHE)
        if not cat.items:
            raise SystemExit("No catalog items loaded.")
        processed = fp.upsert_permissions(cat.items, source="cli")
        print(f"Upserts: {processed} / Items: {len(cat.items)}")
        return

    if args.cmd == "find":
        from scytaledroid.Utils.AndroidPermCatalog import api as _api
        cat = load_cached_or_refresh(DEFAULT_CACHE)
        if not cat.items:
            raise SystemExit(1)
        entry = find_entry(cat.items, args.query)
        if not entry:
            print("No match found")
            raise SystemExit(2)
        print(f"{entry.short}")
        print(f"  Constant: {entry.name}")
        print(f"  Protection: {entry.protection or '-'}  (raw: {entry.protection_raw or '-'})")
        print(f"  Added in API: {entry.added_api or '-'}")
        flags = []
        if entry.hard_restricted:
            flags.append("hard_restricted")
        if entry.soft_restricted:
            flags.append("soft_restricted")
        if entry.system_only:
            flags.append("system_only")
        if flags:
            print(f"  Flags: {', '.join(flags)}")
        if entry.summary:
            print(f"  Summary: {entry.summary}")
        print(f"  Doc: {entry.doc_url}")


__all__ = ["main"]

