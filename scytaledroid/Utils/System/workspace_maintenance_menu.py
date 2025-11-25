"""Workspace maintenance & cleanup menu."""

from __future__ import annotations

from pathlib import Path
from typing import List

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
    apks_dir = data_dir / "apks"
    logs_dir = Path("logs")
    cache_dirs = [data_dir / "static_analysis" / "cache", Path("output")]
    apk_files = list(apks_dir.rglob("*.apk")) if apks_dir.exists() else []

    apks_size = _dir_size_bytes(apks_dir)
    logs_size = _dir_size_bytes(logs_dir)
    cache_size = sum(_dir_size_bytes(p) for p in cache_dirs)

    print()
    print(text_blocks.headline("Workspace usage summary", width=display_settings.default_width(80)))

    rows: List[List[str]] = []
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


def _confirm(prompt: str, token: str) -> bool:
    answer = prompt_utils.prompt_text(prompt, required=False).strip()
    return answer.upper() == token.upper()


def workspace_menu() -> None:
    """Render the workspace maintenance menu."""

    while True:
        print()
        menu_utils.print_header("Workspace maintenance & cleanup")
        items = [
            menu_utils.MenuOption("1", "Show workspace usage summary"),
            menu_utils.MenuOption("2", "Prune old APKs from disk", hint="Deletes APKs older than a chosen age", disabled=True),
            menu_utils.MenuOption("3", "Remove stale devices (no longer seen)", disabled=True),
            menu_utils.MenuOption("4", "Prune old static analysis runs from database", disabled=True),
            menu_utils.MenuOption("5", "Clear temporary files and caches", disabled=True),
            menu_utils.MenuOption("6", "Reset entire workspace", badge="[!] Destructive"),
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
        elif choice == "6":
            print()
            print(text_blocks.headline("Reset entire workspace [!] Destructive", width=80))
            print(
                "This will delete ALL APKs under data/apks/, ALL static analysis runs/findings\n"
                "from the database (if configured), and ALL device inventory snapshots/temp files."
            )
            if _confirm("Type RESET-WORKSPACE to confirm, or anything else to cancel:", "RESET-WORKSPACE"):
                print(status_messages.status("Workspace reset not yet implemented. No changes made.", level="warn"))
            else:
                print(status_messages.status("Cancelled reset.", level="info"))
            prompt_utils.press_enter_to_continue()
        else:
            print(status_messages.status("Option not available yet.", level="warn"))
            prompt_utils.press_enter_to_continue()


__all__ = ["workspace_menu"]
