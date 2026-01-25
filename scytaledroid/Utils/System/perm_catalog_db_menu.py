"""Utilities menu for harvesting Android permissions to the database."""

from __future__ import annotations

from typing import List

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuSpec, MenuOption

from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.db_utils import diagnostics

from scytaledroid.Utils.AndroidPermCatalog.loader import load_permission_doc, ONLINE_URL
from scytaledroid.Utils.AndroidPermCatalog.parser import parse_manifest_permissions


def _ensure_table() -> bool:
    return True


def _harvest_and_write(*, limit: int | None) -> None:
    html, source_label = load_permission_doc("auto")
    if not html:
        print(status_messages.status("Unable to load permission documentation (SDK/online).", level="error"))
        return
    try:
        items = parse_manifest_permissions(html, base_url=ONLINE_URL)
    except Exception as exc:  # pragma: no cover - dependency/runtime errors
        print(status_messages.status(f"Parse failed: {exc}", level="error"))
        return

    if not diagnostics.check_connection():
        print(status_messages.status("Database connection failed.", level="error"))
        return

    payloads: List[dict] = []
    for entry in items:
        payloads.append(
            {
                "name": entry.name,
                "short": entry.short,
                "protection": entry.protection,
                "protection_raw": entry.protection_raw,
                "added_api": entry.added_api,
                "deprecated_api": entry.deprecated_api,
                "deprecated_note": entry.deprecated_note,
                "hard_restricted": entry.hard_restricted,
                "soft_restricted": entry.soft_restricted,
                "system_only": entry.system_only,
                "constant_value": entry.constant_value,
                "summary": entry.summary,
                "doc_url": entry.doc_url,
            }
        )

    print(status_messages.status(
        "Framework permission DB writes are deprecated. "
        "Use governance imports for android_permission_dict_aosp.",
        level="warn",
    ))


def perm_catalog_db_menu() -> None:
    while True:
        print()
        menu_utils.print_header("Android permissions catalog (DB)", "Harvest and persist")
        options = [
            MenuOption("1", "Check database", "Connection + table presence"),
            MenuOption("2", "Harvest permissions (full)", "Parse docs and write to DB"),
            MenuOption("3", "Test run (20 permissions)", "Write a small sample to DB"),
        ]
        spec = MenuSpec(items=options, default="1", show_exit=True)
        menu_utils.render_menu(spec)
        choice = prompt_utils.get_choice([opt.key for opt in options] + ["0"], default="0")

        if choice == "0":
            break

        if choice == "1":
            ok = diagnostics.check_connection()
            if ok:
                print(status_messages.status("Database OK; use governance import for dict tables.", level="success"))
            else:
                print(status_messages.status("Database connection failed.", level="error"))
            continue

        if choice == "2":
            _harvest_and_write(limit=None)
            continue

        if choice == "3":
            _harvest_and_write(limit=20)
            continue
