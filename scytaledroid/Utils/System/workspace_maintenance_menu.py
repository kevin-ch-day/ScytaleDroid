"""Workspace maintenance & cleanup menu."""

from __future__ import annotations

from pathlib import Path

from scytaledroid.Utils.DisplayUtils import (
    display_settings,
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
    text_blocks,
)


def _dir_size_bytes(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for entry in path.rglob("*"):
        if entry.is_file():
            try:
                total += entry.stat().st_size
            except OSError:
                continue
    return total


def _humanize_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def _show_summary() -> None:
    data_dir = Path("data")
    apks_dir = data_dir / "device_apks"
    logs_dir = Path("logs")
    cache_dirs = [data_dir / "static_analysis" / "cache", Path("output")]
    apk_files = list(apks_dir.rglob("*.apk")) if apks_dir.exists() else []

    apks_size = _dir_size_bytes(apks_dir)
    logs_size = _dir_size_bytes(logs_dir)
    cache_size = sum(_dir_size_bytes(p) for p in cache_dirs)

    print()
    print(text_blocks.headline("Workspace usage summary", width=display_settings.default_width(80)))

    rows: list[list[str]] = []
    rows.append(["APK storage", str(apks_dir)])
    rows.append(["APK files", f"{len(apk_files)} file(s)"])
    rows.append(["APK size", _humanize_bytes(apks_size)])
    rows.append(["Logs dir", str(logs_dir)])
    rows.append(["Logs size", _humanize_bytes(logs_size)])
    for p in cache_dirs:
        rows.append([f"Cache {p}", _humanize_bytes(_dir_size_bytes(p))])
    rows.append(["Caches total", _humanize_bytes(cache_size)])

    table_kwargs = display_settings.apply_table_defaults({"compact": True, "accent_first_column": True})
    table_utils.render_table(["Item", "Value"], rows, **table_kwargs)
    prompt_utils.press_enter_to_continue()


def workspace_menu() -> None:
    """Render the workspace maintenance menu."""

    while True:
        print()
        menu_utils.print_header("Workspace maintenance & cleanup")
        items = [
            menu_utils.MenuOption("1", "Show workspace usage"),
            menu_utils.MenuOption("2", "Clear temporary files and caches"),
            menu_utils.MenuOption("3", "Clean unused APK files"),
            menu_utils.MenuOption("4", "Remove inactive devices"),
            menu_utils.MenuOption("5", "Clean old static analysis runs"),
            menu_utils.MenuOption("6", "Reset entire workspace [DESTRUCTIVE]"),
        ]
        spec_kwargs = display_settings.apply_menu_defaults(
            {"items": items, "exit_label": "Back", "show_exit": True}
        )
        menu_utils.render_menu(menu_utils.MenuSpec(**spec_kwargs))
        choice = prompt_utils.get_choice([opt.key for opt in items] + ["0"], default="1")

        if choice == "0":
            break
        if choice == "1":
            _show_summary()
        elif choice == "2":
            print()
            menu_utils.print_section("Clear temporary files and caches")
            print("This will remove:")
            print("• temp build artifacts")
            print("• intermediate analysis caches")
            print()
            print("Safe: does NOT delete APKs or analysis results.")
            if prompt_utils.prompt_yes_no("Proceed?", default=False):
                print(status_messages.status("Not implemented yet — planned for Phase-D.", level="warn"))
            else:
                print(status_messages.status("Cancelled.", level="info"))
            prompt_utils.press_enter_to_continue()
        elif choice == "3":
            print()
            menu_utils.print_section("Clean unused APK files")
            print("This will delete APKs older than a selected age that are not referenced by recent analyses.")
            print("You will choose an age threshold next.")
            if prompt_utils.prompt_yes_no("Proceed?", default=False):
                print(status_messages.status("Not implemented yet — planned for Phase-D.", level="warn"))
            else:
                print(status_messages.status("Cancelled.", level="info"))
            prompt_utils.press_enter_to_continue()
        elif choice == "4":
            print()
            menu_utils.print_section("Remove inactive devices")
            print("This will remove devices not seen within a chosen inactivity window.")
            if prompt_utils.prompt_yes_no("Proceed?", default=False):
                print(status_messages.status("Not implemented yet — planned for Phase-D.", level="warn"))
            else:
                print(status_messages.status("Cancelled.", level="info"))
            prompt_utils.press_enter_to_continue()
        elif choice == "5":
            print()
            menu_utils.print_section("Clean old static analysis runs")
            print("This will prune old static analysis runs from the database.")
            print("APKs are not deleted by this action.")
            if prompt_utils.prompt_yes_no("Proceed?", default=False):
                print(status_messages.status("Not implemented yet — planned for Phase-D.", level="warn"))
            else:
                print(status_messages.status("Cancelled.", level="info"))
            prompt_utils.press_enter_to_continue()
        elif choice == "6":
            print()
            print(text_blocks.headline("Reset entire workspace [DESTRUCTIVE]", width=80))
            print("This will permanently delete:")
            print("• all APKs")
            print("• all analysis results")
            print("• all device inventory snapshots/temp files")
            print()
            if prompt_utils.prompt_yes_no("Proceed?", default=False):
                print(status_messages.status("Workspace reset not yet implemented. No changes made.", level="warn"))
            else:
                print(status_messages.status("Cancelled reset.", level="info"))
            prompt_utils.press_enter_to_continue()
        else:
            print(status_messages.status("Option not available yet.", level="warn"))
            prompt_utils.press_enter_to_continue()


__all__ = ["workspace_menu"]
