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
            from scytaledroid.Database.db_core import db_queries as _core_q
            cfg = _dbc.DB_CONFIG
            db_name = cfg.get("database")
            row = _core_q.run_sql(
                "SELECT COUNT(*) FROM android_permission_dict_aosp",
                fetch="one",
            )
            row_count = int(row[0]) if row and row[0] is not None else None
            if row_count is None:
                menu_utils.print_hint(f"DB: {db_name} — unable to query android_permission_dict_aosp")
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
        print("  4) Write framework catalog to DB (deprecated)")
        print("  5) Verify DB load (counts by protection)")
        print("  6) Ensure permission tables (dict/meta)")

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
            print(status_messages.status(
                "DB writes are handled by governance imports for android_permission_dict_aosp.",
                level="info",
            ))
            continue

        # Validate only
        if choice == "3":
            catalog = load_cached_or_refresh(cache_path, source=source)
            if not catalog.items:
                continue
            _validate_and_report(catalog.items)
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
            print(status_messages.status(
                "Framework catalog writes are deprecated. Use governance import for dict tables.",
                level="warn",
            ))
            continue

        # Verify DB load (counts by protection)
        if choice == "5":
            try:
                from scytaledroid.Database.db_core import db_queries as _core_q
                rows = _core_q.run_sql(
                    """
                    SELECT COALESCE(protection_level, '(null)') AS protection, COUNT(*) AS total
                    FROM android_permission_dict_aosp
                    GROUP BY COALESCE(protection_level, '(null)')
                    ORDER BY total DESC
                    """,
                    fetch="all",
                )
                print()
                menu_utils.print_section("DB: Counts by protection (dict)")
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
            ok_aosp = ok_oem = ok_unknown = ok_queue = ok_meta = False
            try:
                from scytaledroid.Database.db_core import db_queries as _core_q

                def _table_ok(name: str) -> bool:
                    row = _core_q.run_sql(
                        (
                            "SELECT COUNT(*) FROM information_schema.tables "
                            "WHERE table_schema = DATABASE() AND table_name = %s"
                        ),
                        (name,),
                        fetch="one",
                    )
                    return bool(row and int(row[0]) > 0)

                ok_aosp = _table_ok("android_permission_dict_aosp")
                ok_oem = _table_ok("android_permission_dict_oem")
                ok_unknown = _table_ok("android_permission_dict_unknown")
                ok_queue = _table_ok("android_permission_dict_queue")
                ok_meta = _table_ok("android_permission_meta_oem_vendor")
            except Exception:
                pass
            level = "success" if (ok_aosp and ok_oem and ok_unknown and ok_queue and ok_meta) else ("warn" if (ok_aosp or ok_oem or ok_unknown or ok_queue or ok_meta) else "error")
            print(status_messages.status(
                "Tables ensured → "
                f"aosp={'OK' if ok_aosp else 'FAIL'}, "
                f"oem={'OK' if ok_oem else 'FAIL'}, "
                f"unknown={'OK' if ok_unknown else 'FAIL'}, "
                f"queue={'OK' if ok_queue else 'FAIL'}, "
                f"meta={'OK' if ok_meta else 'FAIL'}",
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
