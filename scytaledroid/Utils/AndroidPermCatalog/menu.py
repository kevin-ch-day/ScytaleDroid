from __future__ import annotations

from pathlib import Path

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils

from . import api
from .constants import DEFAULT_CACHE
from .ops import (
    attach_groups,
    counts_by_protection,
    export_csv,
    load_cached_or_refresh,
    purge_old_snapshots,
)


def perm_catalog_menu() -> None:
    """Render the Harvest Android Permissions menu and dispatch actions."""

    cache_path = DEFAULT_CACHE
    source = "auto"

    while True:
        # Clear screen before drawing a new menu screen (optional)
        try:
            from scytaledroid.Utils.DisplayUtils import ui_prefs as _ui
            if _ui.should_clear():
                from scytaledroid.Utils.System.util_actions import clear_screen as _clear
                _clear()
            else:
                print()
        except Exception:
            print()
        menu_utils.print_header("Harvest Android Permissions")

        # DB status hint (concise)
        try:
            from scytaledroid.Database.db_core import db_config as _dbc
            from scytaledroid.Database.db_func.permissions import framework_permissions as _fp
            row_count = _fp.count_rows()
            cfg = _dbc.DB_CONFIG
            db_name = cfg.get('database')
            if row_count is None:
                menu_utils.print_hint(f"DB: {db_name} — unable to query android_framework_permissions")
            else:
                menu_utils.print_hint(f"DB: {db_name} — {row_count} row(s)")
        except Exception:
            menu_utils.print_hint("DB: not configured or unreachable")

        # Streamlined sections and options
        menu_utils.print_section("Pipeline")
        print("  1) Full run: harvest → validate → write → verify")

        menu_utils.print_section("Harvest")
        print("  2) Harvest (online) and save JSON")

        menu_utils.print_section("Validate")
        print("  3) Validate catalog")

        # No separate Database section heading — keep menu compact
        print("  4) Write framework catalog to DB")
        print("  5) Verify DB load (counts by protection)")
        print("  6) Ensure permission tables (FW/Vendor/Unknown)")

        choice = prompt_utils.get_choice(["1","2","3","4","5","6","0"], default="0")

        if choice == "0":
            break

        # Full pipeline: Harvest (online) → validate → write → verify
        if choice == "1":
            catalog = load_cached_or_refresh(cache_path, source="online")
            if not catalog.items:
                continue
            print(status_messages.status(
                f"Harvest complete: {len(catalog.items)} permissions" + (f" (cached at {cache_path})" if catalog.path else ""),
                level="success",
            ))
            _validate_and_report(catalog.items)
            from scytaledroid.Database.db_func.permissions import framework_permissions as fp
            if not fp.table_exists() and not fp.ensure_table():
                print(status_messages.status("Unable to prepare android_framework_permissions table.", level="error"))
                continue
            try:
                processed = fp.upsert_permissions(catalog.items, source="online")
                print(status_messages.status(f"Upserts: {processed} / Items: {len(catalog.items)}", level="success"))
            except Exception as exc:
                print(status_messages.status(f"DB write failed: {exc}", level="error"))
                continue
            # Verify DB counts
            try:
                from scytaledroid.Database.db_core import db_queries as _core_q
                from scytaledroid.Database.db_queries.permissions import framework_permissions as _fpq
                rows = _core_q.run_sql(_fpq.PROTECTION_COUNTS, fetch="all")
                print()
                menu_utils.print_section("DB: Counts by protection")
                table_utils.render_table(["Protection", "Count"], rows or [])
            except Exception as exc:
                print(status_messages.status(f"DB verify failed: {exc}", level="error"))
            continue

        # Validate only
        if choice == "3":
            catalog = load_cached_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            _validate_and_report(catalog.items)
            continue

        # Counts by group
        if choice == "6":
            catalog = load_cached_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            from collections import Counter
            c = Counter((getattr(p, "group", None) or "—") for p in catalog.items)
            rows = [[grp, str(cnt)] for grp, cnt in sorted(c.items(), key=lambda kv: (kv[0] == "—", kv[0]))]
            print()
            menu_utils.print_section("Counts by group")
            table_utils.render_table(["Group", "Count"], rows)
            continue

        # Harvest (online) and save JSON only
        if choice == "2":
            catalog = load_cached_or_refresh(cache_path, source="online")
            if not catalog.items:
                continue
            print(status_messages.status(
                f"Harvest complete: {len(catalog.items)} permissions" + (f" (cached at {cache_path})" if catalog.path else ""),
                level="success",
            ))
            continue

        # Write to DB
        if choice == "4":
            from scytaledroid.Database.db_func.permissions import framework_permissions as fp
            if not fp.table_exists() and not fp.ensure_table():
                print(status_messages.status("Unable to prepare android_framework_permissions table.", level="error"))
                continue
            catalog = load_cached_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            try:
                processed = fp.upsert_permissions(catalog.items, source=source)
                print(status_messages.status(f"Upserts: {processed} / Items: {len(catalog.items)}", level="success"))
            except Exception as exc:
                print(status_messages.status(f"DB write failed: {exc}", level="error"))
                continue
            # DB counts summary
            try:
                from scytaledroid.Database.db_core import db_queries as _core_q
                from scytaledroid.Database.db_queries.permissions import framework_permissions as _fpq
                rows = _core_q.run_sql(_fpq.PROTECTION_COUNTS, fetch="all")
                print()
                menu_utils.print_section("DB: Counts by protection")
                table_utils.render_table(["Protection", "Count"], rows or [])
            except Exception:
                pass
            continue

        # Verify DB load (counts by protection)
        if choice == "5":
            try:
                from scytaledroid.Database.db_core import db_queries as _core_q
                from scytaledroid.Database.db_queries.permissions import framework_permissions as _fpq
                rows = _core_q.run_sql(_fpq.PROTECTION_COUNTS, fetch="all")
                print()
                menu_utils.print_section("DB: Counts by protection")
                table_utils.render_table(["Protection", "Count"], rows or [])
            except Exception as exc:
                print(status_messages.status(f"DB verify failed: {exc}", level="error"))
            continue

        # Ensure tables
        if choice == "6":
            # Quick connection check first for clearer feedback
            try:
                from scytaledroid.Database.db_utils import diagnostics as _dbu
                if not _dbu.check_connection():
                    print(status_messages.status("Database connection failed. Use Database Utilities → Check connection to troubleshoot.", level="error"))
                    continue
            except Exception:
                pass
            ok_fw = ok_v = ok_u = ok_d = False
            try:
                from scytaledroid.Database.db_func.permissions import framework_permissions as _fw
                from scytaledroid.Database.db_func.permissions import vendor_permissions as _vp
                from scytaledroid.Database.db_func.permissions import unknown_permissions as _up
                from scytaledroid.Database.db_func.permissions import detected_permissions as _dp
                ok_fw = _fw.ensure_table()
                ok_v = _vp.ensure_table()
                ok_u = _up.ensure_table()
                ok_d = _dp.ensure_table()
            except Exception:
                pass
            level = "success" if (ok_fw and ok_v and ok_u and ok_d) else ("warn" if (ok_fw or ok_v or ok_u or ok_d) else "error")
            print(status_messages.status(
                f"Tables ensured → framework={'OK' if ok_fw else 'FAIL'}, vendor={'OK' if ok_v else 'FAIL'}, unknown={'OK' if ok_u else 'FAIL'}, detected={'OK' if ok_d else 'FAIL'}",
                level=level,
            ))
            continue


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
        if getattr(p, "protection_tokens", None):
            extra = [t for t in p.protection_tokens if t not in allowed]
            if extra:
                bad_tokens.append(f"{p.short}: {','.join(extra)}")
        if getattr(p, "summary", "") and _re.search(r"\b(Protection level:|Constant\s+Value:)\b", p.summary, _re.I):
            summary_markers.append(p.short)
        if p.system_only and not p.system_only_note:
            missing_notes.append(f"{p.short}: system_only without note")
        if p.hard_restricted and not p.restricted_note:
            missing_notes.append(f"{p.short}: hard_restricted without note")

    from scytaledroid.Utils.DisplayUtils import status_messages as _sm
    print(_sm.status(f"Validation: {len(bad_tokens)} token issues; {len(summary_markers)} summaries with markers; {len(missing_notes)} missing notes", level="info"))
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


__all__ = ["perm_catalog_menu"]
