from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from . import api
from .group_map import attach_groups
from dataclasses import asdict as _asdict
import json


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


def _purge_old_snapshots(cache_path: Path) -> int:
    """Delete timestamped snapshot JSONs, keep only the primary file.

    Returns number of files removed.
    """
    removed = 0
    for path in _list_snapshot_files(cache_path):
        try:
            path.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def _validate_and_report(items) -> None:
    import re as _re
    bad_tokens: list[str] = []
    summary_markers: list[str] = []
    missing_notes: list[str] = []

    allowed = {
        "dangerous",
        "normal",
        "signature",
        "signatureorsystem",
        "privileged",
        "development",
        "installer",
        "instant",
        "appop",
        "system",
        "internal",
        "oem",
        "preinstalled",
        "role",
    }

    for p in items:
        # Check tokens only include allowed set
        if getattr(p, "protection_tokens", None):
            extra = [t for t in p.protection_tokens if t not in allowed]
            if extra:
                bad_tokens.append(f"{p.short}: {','.join(extra)}")
        # Check summaries for residual markers
        if getattr(p, "summary", "") and _re.search(r"\b(Protection level:|Constant\s+Value:)\b", p.summary, _re.I):
            summary_markers.append(p.short)
        # Notes present when flags are true
        if p.system_only and not p.system_only_note:
            missing_notes.append(f"{p.short}: system_only without note")
        if p.hard_restricted and not p.restricted_note:
            missing_notes.append(f"{p.short}: hard_restricted without note")

    print(status_messages.status(f"Validation: {len(bad_tokens)} token issues; {len(summary_markers)} summaries with markers; {len(missing_notes)} missing notes", level="info"))
    if bad_tokens:
        print("Token issues (top 10):")
        for row in bad_tokens[:10]:
            print(f"  - {row}")
    if summary_markers:
        print("Summaries with residual markers (top 10):")
        for name in summary_markers[:10]:
            print(f"  - {name}")
    if missing_notes:
        print("Missing notes for flags (top 10):")
        for row in missing_notes[:10]:
            print(f"  - {row}")


def _db_prep_menu(items) -> None:
    from scytaledroid.Database.db_core import db_config
    from scytaledroid.Database.db_utils import db_utils as _dbu
    try:
        from scytaledroid.Database.db_queries import framework_permissions as _q
        ddl = getattr(_q, "CREATE_TABLE", "<DDL not available>")
    except Exception:
        ddl = "<DDL not available>"

    while True:
        print()
        menu_utils.print_header("Database prep (preview)", "No writes — plan and verify")
        options = [
            menu_utils.MenuOption("1", "Show DB config", f"host={db_config.DB_CONFIG.get('host')} db={db_config.DB_CONFIG.get('database')} user={db_config.DB_CONFIG.get('user')}") ,
            menu_utils.MenuOption("2", "Check DB connection", "Non-intrusive ping using current config"),
            menu_utils.MenuOption("3", "Show proposed DDL", "android_framework_permissions schema (create if missing later)"),
            menu_utils.MenuOption("4", "Sample upsert payloads (5)", "First 5 mapped rows as dict"),
            menu_utils.MenuOption("5", "Estimate write plan", "Rows total and suggested batch sizes"),
            menu_utils.MenuOption("6", "Persist to DB (test mode)", "Upsert first N rows (requires table exists)"),
        ]
        menu_utils.print_menu(options, is_main=False)
        choice = prompt_utils.get_choice([opt.key for opt in options] + ["0"], default="0")

        if choice == "0":
            break

        if choice == "1":
            cfg = db_config.DB_CONFIG
            print(status_messages.status(f"host={cfg.get('host')} port={cfg.get('port')} db={cfg.get('database')} user={cfg.get('user')}", level="info"))
            continue

        if choice == "2":
            ok = _dbu.check_connection()
            level = "success" if ok else "error"
            print(status_messages.status(f"Connection {'OK' if ok else 'FAILED'}", level=level))
            continue

        if choice == "3":
            print()
            print("-- Proposed DDL --")
            print(ddl.strip())
            continue

        if choice == "4":
            print()
            print("-- Sample payloads --")
            for idx, p in enumerate(items[:5], start=1):
                payload = _asdict(p)
                # flatten: protection_tokens/api_references to pipe strings for readability
                payload["protection_tokens"] = "|".join(p.protection_tokens or ())
                payload["api_references"] = ",".join(p.api_references or ())
                print(f"[{idx}] {payload['short']}")
                print(json.dumps(payload, indent=2, sort_keys=True))
            continue

        if choice == "5":
            total = len(items)
            batch = 500
            batches = (total + batch - 1) // batch
            print(status_messages.status(f"Total rows: {total}; Suggested batch size: {batch}; Batches: {batches}", level="info"))
            continue

        if choice == "6":
            from scytaledroid.Database.db_func import framework_permissions as fp
            # Table exists check (no DDL here)
            if not fp.table_exists():
                print(status_messages.status("Table 'android_framework_permissions' not found. Create it before persisting.", level="error"))
                continue
            # Prompt for N rows
            default_n = "20"
            raw_n = prompt_utils.prompt_text("Rows to persist (test mode)", default=default_n)
            try:
                n = max(1, int(raw_n))
            except ValueError:
                n = 20
            # Dry-run preview
            print(status_messages.status(f"Ready to upsert first {n} row(s).", level="info"))
            if not prompt_utils.prompt_yes_no("Proceed with DB upsert?", default=False):
                continue
            # Build payloads and upsert
            payloads = []
            for p in items[:n]:
                d = _asdict(p)
                # flatten sequences for DB adapter
                d["protection_tokens"] = "|".join(p.protection_tokens or ())
                d["api_references"] = ",".join(p.api_references or ())
                payloads.append(d)
            try:
                processed = fp.upsert_permissions(payloads, source="cli-test", limit=n)
                print(status_messages.status(f"Inserted/updated {processed} row(s) into android_framework_permissions", level="success"))
            except Exception as exc:
                print(status_messages.status(f"Persist failed: {exc}", level="error"))
            continue


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
    keep_snapshots = False

    while True:
        print()
        # Header with current source
        menu_utils.print_header(
            "Harvest Android Permissions",
            f"Source: {source} — developer.android.com/reference/android/Manifest.permission",
        )

        # Grouped sections for better scanability
        menu_utils.print_section("Harvest")
        print("  1) Harvest now (refresh cache)")
        print("  9) Select source (auto/sdk/online)")

        menu_utils.print_section("Analyze")
        print("  2) Show counts by protection level")
        print("  6) Dangerous only preview")
        print(" 11) Validate catalog")
        print(" 14) Counts by group")

        menu_utils.print_section("Export")
        try:
            rel = cache_path.relative_to(Path.cwd())
            display_path = f"{Path.cwd().name}/{rel.as_posix()}"
        except Exception:
            display_path = str(cache_path)
        print(f"  4) Dump JSON snapshot → {display_path}")
        print("  7) Export CSV")
        print("  8) Diff vs last snapshot")
        print(f"  13) Snapshots: {'ON' if keep_snapshots else 'OFF'} (toggle)")

        menu_utils.print_section("Enrich")
        print(" 10) Attach groups from AOSP/SDK (experimental)")

        menu_utils.print_section("Database")
        print(" 12) Database prep (preview)")

        choice = prompt_utils.get_choice(
            ["1","2","4","6","7","8","9","10","11","12","14","5","13","0"],
            default="0",
        )

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
            if not keep_snapshots:
                _purge_old_snapshots(cache_path)
            continue

        # Counts by protection
        if choice == "2":
            catalog = _load_from_cache_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            print()
            table_utils.render_table(["Protection", "Count"], _counts_by_protection(catalog.items))
            continue

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
                api.save_catalog_json(cache_path, catalog.items, source=source, write_timestamped=keep_snapshots)
                print(status_messages.status(f"Wrote {cache_path}", level="success"))
            except Exception as exc:
                print(status_messages.status(f"Failed to write JSON: {exc}", level="error"))
            else:
                if not keep_snapshots:
                    _purge_old_snapshots(cache_path)
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

        if choice == "10":
            catalog = _load_from_cache_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            updated = attach_groups(catalog.items)
            if updated:
                try:
                    api.save_catalog_json(cache_path, catalog.items, source=source)
                except Exception:
                    pass
                print(status_messages.status(f"Attached groups for {updated} permissions", level="success"))
            else:
                print(status_messages.status("No groups attached. Set ANDROID_SDK_ROOT or retry online.", level="warn"))
            continue

        if choice == "11":
            catalog = _load_from_cache_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            _validate_and_report(catalog.items)
            continue

        if choice == "12":
            catalog = _load_from_cache_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            _db_prep_menu(catalog.items)
            continue

        if choice == "13":
            keep_snapshots = not keep_snapshots
            print(status_messages.status(f"Timestamped snapshots {'enabled' if keep_snapshots else 'disabled'}", level="info"))
            if not keep_snapshots:
                _purge_old_snapshots(cache_path)
            continue

        if choice == "14":
            catalog = _load_from_cache_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            from collections import Counter
            c = Counter((getattr(p, "group", None) or "—") for p in catalog.items)
            rows = [[grp, str(cnt)] for grp, cnt in sorted(c.items(), key=lambda kv: (kv[0] == "—", kv[0]))]
            print()
            menu_utils.print_section("Counts by group")
            table_utils.render_table(["Group", "Count"], rows)
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
