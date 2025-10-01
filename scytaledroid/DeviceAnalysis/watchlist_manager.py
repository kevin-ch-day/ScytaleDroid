"""Interactive management of harvest watchlists."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List, Optional

from scytaledroid.Database.db_core import db_queries
from scytaledroid.DeviceAnalysis import harvest
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, text_blocks


def manage_watchlists(serial: Optional[str] = None) -> None:
    """Entry point for the watchlist management console."""

    while True:
        watchlists = harvest.load_watchlists()
        print()
        menu_utils.print_header("Harvest Watchlists")
        if not watchlists:
            print(status_messages.status("No watchlists found in data/watchlists/", level="warn"))
        else:
            _render_watchlist_table(watchlists)

        options = {
            "1": "View watchlist contents",
            "2": "Delete a watchlist",
            "3": "Reload watchlists",
            "0": "Back",
        }
        choice = prompt_utils.get_choice(options.keys(), default="0")
        if choice == "0":
            break
        if choice == "1":
            _view_watchlist(watchlists)
        elif choice == "2":
            _delete_watchlist(watchlists)
        elif choice == "3":
            harvest.reset_watchlist_cache()
        else:
            print(status_messages.status("Selection not available.", level="warn"))


def _render_watchlist_table(watchlists: Iterable[harvest.Watchlist]) -> None:
    headers = ("Slug", "Name", "Packages", "Location")
    rows: List[List[str]] = []
    for watchlist in watchlists:
        rows.append(
            [
                watchlist.slug,
                watchlist.name,
                str(len(watchlist.packages)),
                str(Path(watchlist.path).relative_to(Path.cwd())),
            ]
        )
    if rows:
        menu_utils.print_table(headers, rows)


def _view_watchlist(watchlists: Iterable[harvest.Watchlist]) -> None:
    watchlist = _prompt_watchlist_choice(watchlists)
    if not watchlist:
        return

    package_info = _resolve_app_names(watchlist.packages)
    rows: List[List[str]] = []
    for package in watchlist.packages:
        app_name = package_info.get(package, "<unknown>")
        rows.append([app_name, package])

    print()
    print(text_blocks.headline(f"Watchlist: {watchlist.name}", width=70))
    if rows:
        menu_utils.print_table(("App", "Package"), rows)
    else:
        print(status_messages.status("Watchlist contains no packages.", level="warn"))
    prompt_utils.press_enter_to_continue()


def _delete_watchlist(watchlists: Iterable[harvest.Watchlist]) -> None:
    watchlist = _prompt_watchlist_choice(watchlists)
    if not watchlist:
        return
    confirm = prompt_utils.prompt_yes_no(
        f"Delete watchlist '{watchlist.name}'?", default=False
    )
    if not confirm:
        return
    try:
        Path(watchlist.path).unlink()
        harvest.reset_watchlist_cache()
        print(status_messages.status("Watchlist deleted.", level="success"))
    except FileNotFoundError:
        print(status_messages.status("Watchlist file already removed.", level="warn"))
    prompt_utils.press_enter_to_continue()


def _prompt_watchlist_choice(
    watchlists: Iterable[harvest.Watchlist],
) -> Optional[harvest.Watchlist]:
    watchlists = list(watchlists)
    if not watchlists:
        print(status_messages.status("No watchlists available.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return None

    slug_map: Dict[str, harvest.Watchlist] = {watchlist.slug: watchlist for watchlist in watchlists}
    print()
    menu_utils.print_header("Select watchlist")
    options = {str(index): wl.slug for index, wl in enumerate(watchlists, start=1)}
    menu_utils.print_menu({key: slug_map[slug].name for key, slug in options.items()}, is_main=False)
    menu_utils.print_hint("You can also type a watchlist slug directly.")
    choice = prompt_utils.prompt_text(
        "Selection",
        default="1",
        required=True,
        validator=lambda value: value in options or value in slug_map,
        error_message="Unknown watchlist. Enter the index or slug shown above.",
    )
    slug = options.get(choice, choice)
    return slug_map.get(slug)


def _resolve_app_names(packages: Iterable[str]) -> Dict[str, str]:
    package_list = [pkg for pkg in packages]
    if not package_list:
        return {}
    placeholders = ", ".join(["%s"] * len(package_list))
    query = (
        "SELECT package_name, COALESCE(app_name, package_name) AS label "
        "FROM android_app_definitions "
        f"WHERE package_name IN ({placeholders})"
    )
    rows = db_queries.run_sql(query, tuple(package_list), fetch="all", dictionary=True)
    mapping = {}
    if rows:
        for row in rows:
            pkg = str(row.get("package_name") or "")
            if pkg:
                mapping[pkg] = str(row.get("label") or pkg)
    return mapping


__all__ = ["manage_watchlists"]

