"""Interactive menu for APK static analysis workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from ..core.repository import group_artifacts
from .commands import COMMANDS, get_command, iter_commands
from .commands.models import Command
from .models import RunParameters
from .prompts import default_custom_tests, prompt_advanced_options
from .runner import launch_scan_flow
from .scope import select_scope


def static_analysis_menu() -> None:
    base_dir = Path(app_config.DATA_DIR) / "apks"
    groups = tuple(group_artifacts(base_dir))
    if not groups:
        print(
            status_messages.status(
                "No harvested APK groups found. Run Device Analysis → 7 to pull artifacts.",
                level="warn",
            )
        )
        prompt_utils.press_enter_to_continue()
        return

    scan_commands = tuple(iter_commands("scan"))
    readonly_commands = tuple(iter_commands("readonly"))
    selectable_ids = [cmd.id for cmd in COMMANDS]

    while True:
        print()
        menu_utils.print_header("Android APK Static Analysis")
        menu_entries = _menu_entries(scan_commands, readonly_commands)
        menu_utils.print_menu(menu_entries, is_main=False)
        choice = prompt_utils.get_choice(selectable_ids + ["0"], default="0")

        if choice == "0":
            break

        command = get_command(choice)
        if command is None:
            print(status_messages.status("Unsupported option selected.", level="warn"))
            continue

        if command.kind == "readonly":
            if command.handler:
                command.handler()
            else:
                print(status_messages.status(f"{command.title} not yet implemented.", level="warn"))
            continue

        if not command.profile:
            print(status_messages.status("Command missing run profile.", level="error"))
            continue

        selection = select_scope(groups)
        params = RunParameters(
            profile=command.profile,
            scope=selection.scope,
            scope_label=selection.label,
            selected_tests=(
                default_custom_tests() if command.profile == "custom" else tuple()
            ),
        )

        while True:
            action = ask_run_controls()
            if action == "back":
                break
            if action == "advanced":
                params = prompt_advanced_options(params)
                continue
            launch_scan_flow(selection, params, base_dir)
            break


def _menu_entries(
    scan_commands: Iterable[Command],
    readonly_commands: Iterable[Command],
) -> list[tuple[str, str, str]]:
    entries: list[tuple[str, str, str]] = []
    for cmd in scan_commands:
        entries.append((cmd.id, cmd.title, cmd.description))
    for cmd in readonly_commands:
        entries.append((cmd.id, cmd.title, cmd.description))
    return entries


def ask_run_controls() -> str:
    while True:
        print()
        menu_utils.print_section("Run controls")
        print("  R) Run with defaults")
        print("  A) Advanced options")
        print("  0) Back")

        response = prompt_utils.prompt_text(
            "",
            default="R",
            required=False,
            error_message="Invalid choice. Please try again.",
        )
        choice = (response or "R").strip().lower()

        if choice in {"", "r", "run", "1"}:
            return "run"
        if choice in {"a", "adv", "advanced", "2"}:
            return "advanced"
        if choice in {"0", "back", "b"}:
            return "back"

        print(status_messages.status("Invalid choice. Please try again.", level="warn"))


__all__ = ["static_analysis_menu", "ask_run_controls"]
