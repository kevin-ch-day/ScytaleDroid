"""APK Library & Archives menu."""

from __future__ import annotations

from typing import Iterable, List, Optional

from scytaledroid.Utils.DisplayUtils import (
    display_settings,
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
    text_blocks,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from scytaledroid.DeviceAnalysis.services import apk_library_service
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup


def _render_group_table(groups: Iterable[ArtifactGroup]) -> None:
    rows: List[List[str]] = []
    for idx, group in enumerate(groups, start=1):
        rows.append(
            [
                str(idx),
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
        ["#", "Package", "Version", "Session", "Base?", "Artifacts"],
        rows,
        **table_kwargs,
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
    _render_group_table(by_device.get(serial, []))
    prompt_utils.press_enter_to_continue()


def _browse_all() -> None:
    groups = apk_library_service.list_groups()
    print()
    menu_utils.print_header("All APKs")
    _render_group_table(groups)
    prompt_utils.press_enter_to_continue()


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
    _render_group_table(groups)
    prompt_utils.press_enter_to_continue()


def apk_library_menu(device_filter: Optional[str] = None) -> None:
    """Entry point for APK library & archives."""

    while True:
        print()
        menu_utils.print_header("APK library & archives")
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
