from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from . import api


DEFAULT_CACHE = Path(__file__).resolve().parent / "cache" / "framework_permissions.json"


@dataclass(frozen=True)
class _Catalog:
    path: Optional[Path]
    items: list


def _load_from_cache_or_refresh(cache_path: Path, *, source: str = "auto") -> _Catalog:
    if cache_path.exists():
        try:
            items = api.load_catalog_json(cache_path)
            return _Catalog(path=cache_path, items=items)
        except Exception as exc:
            log.warning(f"Failed to load cached permission catalog: {exc}", category="application")

    try:
        items = api.load_catalog(source)  # type: ignore[arg-type]
    except Exception as exc:
        print(status_messages.status(f"Unable to refresh catalog: {exc}", level="error"))
        return _Catalog(path=None, items=[])

    try:
        api.save_catalog_json(cache_path, items, source=source)
    except Exception as exc:
        log.warning(f"Unable to write catalog cache: {exc}", category="application")
    return _Catalog(path=cache_path, items=items)


def _list_snapshot_files(cache_path: Path) -> list[Path]:
    base = cache_path.parent
    stem, suffix = cache_path.stem, cache_path.suffix
    return sorted([p for p in base.glob(f"{stem}.*{suffix}") if p.is_file()])


def _export_csv(cache_path: Path, items) -> Optional[Path]:
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


def _counts_by_protection(items) -> list[list[str]]:
    from collections import Counter

    c = Counter((entry.protection or "-") for entry in items)
    rows: list[list[str]] = []
    for key, value in sorted(c.items(), key=lambda kv: (kv[0] != "-", kv[0])):
        rows.append([key, str(value)])
    return rows


def _find_entry(items, query: str):
    q = query.strip()
    by_const = api.index_by_constant(items)
    if q in by_const:
        return by_const[q]
    by_short = api.index_by_short(items)
    return by_short.get(q) or by_short.get(q.upper())


def perm_catalog_menu() -> None:
    """Harvest Android permissions from developer.android.com and manage JSON cache."""

    cache_path = DEFAULT_CACHE

    source = "auto"

    while True:
        print()
        menu_utils.print_header("Harvest Android Permissions", f"Source: {source} — developer.android.com/reference/android/Manifest.permission")
        options = [
            menu_utils.MenuOption("1", "Harvest now (refresh cache)", "Pull + save JSON; keep timestamped snapshots"),
            menu_utils.MenuOption("2", "Show counts by protection level"),
            menu_utils.MenuOption("3", "Search by name or constant", "e.g., CAMERA or android.permission.CAMERA"),
            menu_utils.MenuOption("4", "Dump JSON snapshot", f"Write to {cache_path}"),
            menu_utils.MenuOption("5", "Test run (preview 20)", "Show a small dataset of 20 items"),
            menu_utils.MenuOption("6", "Dangerous only preview"),
            menu_utils.MenuOption("7", "Export CSV"),
            menu_utils.MenuOption("8", "Diff vs last snapshot"),
            menu_utils.MenuOption("9", "Select source (auto/sdk/online)"),
        ]
        menu_utils.print_menu(options, is_main=False)
        choice = prompt_utils.get_choice([opt.key for opt in options] + ["0"], default="0")

        if choice == "0":
            break

        # Harvest (refresh cache)
        if choice == "1":
            catalog = _load_from_cache_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            print(status_messages.status(
                f"Harvest complete: {len(catalog.items)} permissions" + (f" (cached at {cache_path})" if catalog.path else ""),
                level="success",
            ))
            continue

        # Counts by protection
        if choice == "2":
            catalog = _load_from_cache_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            print()
            table_utils.render_table(["Protection", "Count"], _counts_by_protection(catalog.items))
            continue

        # Search one
        if choice == "3":
            catalog = _load_from_cache_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            query = prompt_utils.prompt_text("Permission (short or constant)", default="CAMERA", required=True)
            entry = _find_entry(catalog.items, query)
            if not entry:
                # fuzzy suggestions
                q = query.strip().upper()
                candidates = [p for p in catalog.items if q in p.short.upper() or q in p.name.upper()]
                suggestions = ", ".join(p.short for p in candidates[:5])
                if suggestions:
                    print(status_messages.status(f"No exact match. Suggestions: {suggestions}", level="warn"))
                else:
                    print(status_messages.status("No match found.", level="warn"))
                continue
            print()
            print(f"{entry.short}")
            print(f"  Constant: {entry.name}")
            print(f"  Protection: {entry.protection or '-'}  (raw: {entry.protection_raw or '-'})")
            added = (
                f"API {entry.added_api}" if entry.added_api is not None else (f"version {entry.added_version}" if entry.added_version else "-")
            )
            print(f"  Added: {added}")
            if entry.deprecated_api is not None:
                print(f"  Deprecated in API: {entry.deprecated_api}")
                if entry.deprecated_note:
                    print(f"    Note: {entry.deprecated_note}")
            flags = []
            if entry.hard_restricted:
                flags.append("hard_restricted")
            if entry.soft_restricted:
                flags.append("soft_restricted")
            if entry.system_only:
                flags.append("system_only")
            if flags:
                print(f"  Flags: {', '.join(flags)}")
            if entry.restricted_note:
                print(f"  Restricted note: {entry.restricted_note}")
            if entry.system_only_note:
                print(f"  System-only note: {entry.system_only_note}")
            if entry.protection_tokens:
                print(f"  Tokens: {', '.join(entry.protection_tokens)}")
            if entry.api_references:
                print(f"  API refs: {', '.join(entry.api_references[:4])}{' …' if len(entry.api_references) > 4 else ''}")
            if entry.summary:
                print(f"  Summary: {entry.summary}")
            print(f"  Doc: {entry.doc_url}")
            continue

        # Dump JSON snapshot
        if choice == "4":
            catalog = _load_from_cache_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            try:
                api.save_catalog_json(cache_path, catalog.items, source=source)
                print(status_messages.status(f"Wrote {cache_path}", level="success"))
            except Exception as exc:
                print(status_messages.status(f"Failed to write JSON: {exc}", level="error"))
            continue

        # Test run (20 items preview)
        if choice == "5":
            catalog = _load_from_cache_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            sample = catalog.items[:20]
            rows = [[p.short, p.protection or "-", str(p.added_api or "-"), p.name] for p in sample]
            print()
            table_utils.render_table(["Short", "Protection", "Added API", "Constant"], rows)
            continue

        if choice == "6":
            catalog = _load_from_cache_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            filtered = [p for p in catalog.items if (p.protection == "dangerous" or (p.protection_tokens and "dangerous" in p.protection_tokens))]
            rows = [[p.short, p.name, p.added_api or p.added_version or "-"] for p in filtered[:40]]
            print()
            table_utils.render_table(["Short", "Constant", "Added"], rows)
            print(status_messages.status(f"Showing {min(40, len(filtered))} of {len(filtered)} dangerous permissions", level="info"))
            continue

        if choice == "7":
            catalog = _load_from_cache_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            out = _export_csv(cache_path, catalog.items)
            if out:
                print(status_messages.status(f"CSV exported to {out}", level="success"))
            continue

        if choice == "8":
            snaps = _list_snapshot_files(cache_path)
            if len(snaps) < 1:
                print(status_messages.status("No prior snapshots found.", level="warn"))
                continue
            latest = snaps[-1]
            try:
                prev_items = api.load_catalog_json(latest)
                current_items = api.load_catalog_json(cache_path) if cache_path.exists() else []
            except Exception as exc:
                print(status_messages.status(f"Failed to load snapshots: {exc}", level="error"))
                continue
            prev_set = {p.name for p in prev_items}
            cur_set = {p.name for p in current_items}
            added = sorted(cur_set - prev_set)
            removed = sorted(prev_set - cur_set)
            print(status_messages.status(f"Diff vs {latest.name}: +{len(added)} / -{len(removed)}", level="info"))
            for name in added[:20]:
                print(f"  + {name}")
            for name in removed[:20]:
                print(f"  - {name}")
            continue

        if choice == "9":
            mapping = {"1": "auto", "2": "sdk", "3": "online"}
            print("  1) auto  2) sdk  3) online")
            sel = prompt_utils.get_choice(["1", "2", "3"], default="1")
            source = mapping[sel]
            print(status_messages.status(f"Source set to: {source}", level="success"))
            continue


if __name__ == "__main__":  # pragma: no cover - manual invocation
    import argparse

    parser = argparse.ArgumentParser(description="Android permissions catalog utility")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("refresh", help="Refresh catalog (SDK/online) and write JSON cache")
    sub.add_parser("counts", help="Show counts by protection level (uses cache or refresh)")
    find_p = sub.add_parser("find", help="Lookup a permission by short name or constant")
    find_p.add_argument("query", help="e.g. CAMERA or android.permission.CAMERA")

    args = parser.parse_args()

    if not args.cmd:
        # Default to quick refresh to help ad-hoc runs
        _ = _load_from_cache_or_refresh(DEFAULT_CACHE)
        print(f"Catalog ready at {DEFAULT_CACHE}")
    elif args.cmd == "refresh":
        cat = _load_from_cache_or_refresh(DEFAULT_CACHE)
        if cat.items:
            print(f"Refreshed {len(cat.items)} entries → {DEFAULT_CACHE}")
    elif args.cmd == "counts":
        cat = _load_from_cache_or_refresh(DEFAULT_CACHE)
        if cat.items:
            rows = _counts_by_protection(cat.items)
            print("Protection,Count")
            for k, v in rows:
                print(f"{k},{v}")
    elif args.cmd == "find":
        cat = _load_from_cache_or_refresh(DEFAULT_CACHE)
        if not cat.items:
            raise SystemExit(1)
        entry = _find_entry(cat.items, args.query)
        if not entry:
            print("No match found")
            raise SystemExit(2)
        print(f"{entry.short}")
        print(f"  Constant: {entry.name}")
        print(f"  Protection: {entry.protection or '-'}  (raw: {entry.protection_raw or '-'})")
        print(f"  Added in API: {entry.added_api or '-'}")
        if entry.deprecated_api is not None:
            print(f"  Deprecated in API: {entry.deprecated_api}")
            if entry.deprecated_note:
                print(f"    Note: {entry.deprecated_note}")
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
