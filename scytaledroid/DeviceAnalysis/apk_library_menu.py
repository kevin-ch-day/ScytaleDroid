"""APK Library & Archives menu."""

from __future__ import annotations

import math
from typing import Iterable, List, Optional, Sequence

from scytaledroid.Utils.DisplayUtils import (
    display_settings,
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
    text_blocks,
    terminal,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from scytaledroid.DeviceAnalysis.services import apk_library_service
from scytaledroid.DeviceAnalysis.services.static_scope_service import static_scope_service
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup


def _group_selected(group: ArtifactGroup) -> bool:
    """Return True if any artifact in the group is selected for static analysis."""
    selected = static_scope_service.selected_set()
    return any(str(artifact.path) in selected for artifact in group.artifacts)


def _render_group_table(groups: Iterable[ArtifactGroup], *, show_selection: bool = False) -> None:
    rows: List[List[str]] = []
    for idx, group in enumerate(groups, start=1):
        selected = _group_selected(group)
        bullet = "●" if not terminal.use_ascii_ui() else "*"
        sel_flag = bullet if selected else ""
        rows.append(
            [
                str(idx),
                sel_flag,
                group.package_name,
                group.version_display,
                group.session_stamp or "—",
                "yes" if group.base_artifact else "missing base",
                str(len(group.artifacts)),
            ]
        )
    if not rows:
        print(status_messages.status("No APKs found for this view.", level="warn"))
        return
    table_kwargs = display_settings.apply_table_defaults({"compact": True})
    table_utils.render_table(
        ["#", "Sel", "Package", "Version", "Session", "Base?", "Artifacts"],
        rows,
        **table_kwargs,
    )


def _paginate(groups: Sequence[ArtifactGroup], page: int, page_size: int = 20) -> tuple[list[ArtifactGroup], int]:
    total = len(groups)
    pages = max(1, math.ceil(total / page_size)) if total else 1
    page = max(1, min(page, pages))
    start = (page - 1) * page_size
    end = start + page_size
    return list(groups[start:end]), pages


def _select_indices(subset: Sequence[ArtifactGroup], indices: Iterable[int], *, select: bool) -> None:
    for idx in indices:
        if 1 <= idx <= len(subset):
            group = subset[idx - 1]
            if select:
                static_scope_service.select_group(group)
            else:
                static_scope_service.remove_group(group)


def _parse_indices(token: str) -> list[int]:
    parts = token.replace(",", " ").split()
    result: list[int] = []
    for part in parts:
        if part.isdigit():
            result.append(int(part))
    return result


def _selection_help() -> str:
    return (
        "Commands: n/p=Next/Prev page, [page#], "
        "m <idx...>=mark, u <idx...>=unmark, t <idx...>=toggle, a=mark all on page, "
        "c=clear selection, s=show selection, 0=Back"
    )


def _browse_by_device() -> None:
    groups = apk_library_service.list_groups()
    by_device: dict[str, List[ArtifactGroup]] = {}
    for group in groups:
        serials = set()
        for artifact in group.artifacts:
            serial = artifact.metadata.get("device_serial")
            if isinstance(serial, str) and serial:
                serials.add(serial)
        if not serials:
            serials = {"unknown"}
        for serial in serials:
            by_device.setdefault(serial, []).append(group)

    devices = sorted(by_device)
    if not devices:
        print(status_messages.status("No devices found in APK library.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Browse APKs by device")
    options = {str(idx): serial for idx, serial in enumerate(devices, start=1)}
    for key, serial in options.items():
        print(f"{key}) {serial}  | APK groups: {len(by_device.get(serial, []))}")
    choice = prompt_utils.get_choice(list(options) + ["0"], default="1")
    if choice == "0":
        return
    serial = options.get(choice)
    if not serial:
        return
    print()
    title = f"APK sessions for {serial}"
    print(text_blocks.headline(title, width=display_settings.default_width(90)))
    device_groups = by_device.get(serial, [])
    page = 1
    while True:
        subset, pages = _paginate(device_groups, page)
        _render_group_table(subset, show_selection=True)
        if static_scope_service.count():
            print(
                status_messages.status(
                    f"Selected for static analysis: {static_scope_service.count()} APKs",
                    level="info",
                )
            )
        if not subset:
            prompt_utils.press_enter_to_continue()
            return
        if pages > 1 or True:
            # Always show commands so operators know how to mark/unmark.
            print(
                status_messages.status(
                    f"Page {page}/{pages}  | {_selection_help()}",
                    level="info",
                )
            )
        choice = prompt_utils.prompt_text(
            "Select command",
            default="0" if pages == 1 else "n",
        ).strip().lower()
        if choice in {"0", "q"}:
            break
        if choice in {"n", ""}:
            page = page + 1 if page < pages else pages
            continue
        if choice == "p":
            page = page - 1 if page > 1 else 1
            continue
        if choice.startswith("m"):
            indices = _parse_indices(choice[1:])
            _select_indices(subset, indices or range(1, len(subset) + 1), select=True)
            continue
        if choice.startswith("t"):
            indices = _parse_indices(choice[1:]) or list(range(1, len(subset) + 1))
            for idx in indices:
                if 1 <= idx <= len(subset):
                    group = subset[idx - 1]
                    if _group_selected(group):
                        static_scope_service.remove_group(group)
                    else:
                        static_scope_service.select_group(group)
            continue
        if choice.startswith("u"):
            indices = _parse_indices(choice[1:])
            _select_indices(subset, indices or range(1, len(subset) + 1), select=False)
            continue
        if choice == "a":
            _select_indices(subset, range(1, len(subset) + 1), select=True)
            continue
        if choice == "c":
            static_scope_service.clear()
            print(status_messages.status("Cleared current APK selection.", level="info"))
            continue
        if choice == "s":
            print(status_messages.status(f"Selected APKs: {static_scope_service.count()}", level="info"))
            continue
        try:
            page = int(choice)
        except ValueError:
            continue


def _browse_all() -> None:
    groups = apk_library_service.list_groups()
    print()
    menu_utils.print_header("All APKs")
    if not groups:
        print(status_messages.status("No APKs found.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return
    page = 1
    while True:
        subset, pages = _paginate(groups, page)
        _render_group_table(subset, show_selection=True)
        if static_scope_service.count():
            print(status_messages.status(f"Selected APKs: {static_scope_service.count()}", level="info"))
        if pages > 1 or True:
            print(status_messages.status(f"Page {page}/{pages} | {_selection_help()}", level="info"))
        choice = prompt_utils.prompt_text(
            "Select command",
            default="0" if pages == 1 else "n",
        ).strip().lower()
        if choice in {"0", "q"}:
            break
        if choice in {"n", ""}:
            page = page + 1 if page < pages else pages
            continue
        if choice == "p":
            page = page - 1 if page > 1 else 1
            continue
        if choice.startswith("m"):
            indices = _parse_indices(choice[1:])
            _select_indices(subset, indices or range(1, len(subset) + 1), select=True)
            continue
        if choice.startswith("t"):
            indices = _parse_indices(choice[1:]) or list(range(1, len(subset) + 1))
            for idx in indices:
                if 1 <= idx <= len(subset):
                    group = subset[idx - 1]
                    if _group_selected(group):
                        static_scope_service.remove_group(group)
                    else:
                        static_scope_service.select_group(group)
            continue
        if choice.startswith("u"):
            indices = _parse_indices(choice[1:])
            _select_indices(subset, indices or range(1, len(subset) + 1), select=False)
            continue
        if choice == "a":
            _select_indices(subset, range(1, len(subset) + 1), select=True)
            continue
        if choice == "c":
            static_scope_service.clear()
            print(status_messages.status("Cleared current APK selection.", level="info"))
            continue
        if choice == "s":
            print(status_messages.status(f"Selected APKs: {static_scope_service.count()}", level="info"))
            continue
        try:
            page = int(choice)
        except ValueError:
            continue


def _search_packages() -> None:
    query = prompt_utils.prompt_text("Search (package substring)", required=False).strip().lower()
    if not query:
        return
    groups = [
        g for g in apk_library_service.list_groups()
        if query in g.package_name.lower()
    ]
    print()
    menu_utils.print_header(f"Search results for '{query}'")
    if not groups:
        print(status_messages.status("No APKs match that query.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return
    page = 1
    while True:
        subset, pages = _paginate(groups, page)
        _render_group_table(subset, show_selection=True)
        if static_scope_service.count():
            print(status_messages.status(f"Selected APKs: {static_scope_service.count()}", level="info"))
        if pages > 1 or True:
            print(status_messages.status(f"Page {page}/{pages} | {_selection_help()}", level="info"))
        choice = prompt_utils.prompt_text(
            "Select command",
            default="0" if pages == 1 else "n",
        ).strip().lower()
        if choice in {"0", "q"}:
            break
        if choice in {"n", ""}:
            page = page + 1 if page < pages else pages
            continue
        if choice == "p":
            page = page - 1 if page > 1 else 1
            continue
        if choice.startswith("m"):
            indices = _parse_indices(choice[1:])
            _select_indices(subset, indices or range(1, len(subset) + 1), select=True)
            continue
        if choice.startswith("t"):
            indices = _parse_indices(choice[1:]) or list(range(1, len(subset) + 1))
            for idx in indices:
                if 1 <= idx <= len(subset):
                    group = subset[idx - 1]
                    if _group_selected(group):
                        static_scope_service.remove_group(group)
                    else:
                        static_scope_service.select_group(group)
            continue
        if choice.startswith("u"):
            indices = _parse_indices(choice[1:])
            _select_indices(subset, indices or range(1, len(subset) + 1), select=False)
            continue
        if choice == "a":
            _select_indices(subset, range(1, len(subset) + 1), select=True)
            continue
        if choice == "c":
            static_scope_service.clear()
            print(status_messages.status("Cleared current APK selection.", level="info"))
            continue
        if choice == "s":
            print(status_messages.status(f"Selected APKs: {static_scope_service.count()}", level="info"))
            continue
        try:
            page = int(choice)
        except ValueError:
            continue


def _selection_manager() -> None:
    """Show current selection and allow clearing."""
    print()
    menu_utils.print_header("APK selection for static analysis")
    count = static_scope_service.count()
    if count == 0:
        print(status_messages.status("No APKs selected yet. Browse and mark items first.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    groups = [g for g in apk_library_service.list_groups() if _group_selected(g)]
    subset, pages = _paginate(groups, 1, page_size=15)
    _render_group_table(subset, show_selection=True)
    if pages > 1:
        print(status_messages.status(f"Showing first page of selected items (total pages: {pages}).", level="info"))
    print(status_messages.status(f"Selected APKs (artifacts): {count}", level="info"))
    choice = prompt_utils.get_choice(["1", "2", "0"], default="0", casefold=True, prompt="1=Clear selection, 2=Keep, 0=Back")
    if choice == "1":
        static_scope_service.clear()
        print(status_messages.status("Cleared APK selection.", level="info"))
        prompt_utils.press_enter_to_continue()


def apk_library_menu(device_filter: Optional[str] = None) -> None:
    """Entry point for APK library & archives."""

    all_groups = apk_library_service.list_groups(device_filter=[device_filter] if device_filter else None)
    device_count = len(
        {
            artifact.metadata.get("device_serial")
            for group in all_groups
            for artifact in group.artifacts
            if isinstance(artifact.metadata.get("device_serial"), str)
        }
    )
    while True:
        selected_count = static_scope_service.count()
        print()
        print(
            text_blocks.headline(
                f"APK library & archives — groups: {len(all_groups)}   devices: {device_count}   selected: {selected_count}",
                width=display_settings.default_width(),
            )
        )
        items = [
            menu_utils.MenuOption("1", "Browse APKs by device"),
            menu_utils.MenuOption("2", "Browse APKs by session (coming soon)", disabled=True),
            menu_utils.MenuOption("3", "Browse all APKs (flat list)"),
            menu_utils.MenuOption("4", "Search APKs (by package name or label)"),
            menu_utils.MenuOption("5", "Show APKs without static analysis runs", disabled=True),
            menu_utils.MenuOption("6", "Show APKs with high-risk findings (from database)", disabled=True),
        ]
        if device_filter:
            items.insert(
                0,
                menu_utils.MenuOption(
                    "d",
                    f"Open library filtered to device {device_filter}",
                    badge="filtered",
                ),
            )
        items.append(
            menu_utils.MenuOption(
                "s",
                "Select APKs for static analysis",
                hint="Mark APKs and hand off to the Static Analysis menu",
            )
        )
        spec_kwargs = display_settings.apply_menu_defaults(
            {"items": items, "exit_label": "Back", "show_exit": True}
        )
        menu_utils.render_menu(menu_utils.MenuSpec(**spec_kwargs))
        choice = prompt_utils.get_choice(
            [opt.key for opt in items] + ["0"],
            default="d" if device_filter else "1",
            casefold=True,
        )

        if choice == "0":
            break
        if choice.lower() == "d" and device_filter:
            groups = apk_library_service.list_groups(device_filter=[device_filter])
            print()
            menu_utils.print_header(f"APK groups for device {device_filter}")
            _render_group_table(groups)
            prompt_utils.press_enter_to_continue()
            continue
        if choice == "1":
            _browse_by_device()
        elif choice == "3":
            _browse_all()
        elif choice == "4":
            _search_packages()
        else:
            print(status_messages.status("Option not available yet.", level="warn"))


__all__ = ["apk_library_menu"]
