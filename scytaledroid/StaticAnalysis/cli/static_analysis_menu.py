"""Interactive menu for APK static analysis workflows."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Iterable, Sequence

from scytaledroid.Config import app_config
from scytaledroid.Database.db_utils.reset_static import reset_static_analysis_data
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from ..core.repository import group_artifacts
from .commands import COMMANDS, get_command, iter_commands
from .commands.models import Command
from .models import RunParameters
from .prompts import default_custom_tests, prompt_advanced_options
from .runner import launch_scan_flow
from .scope import select_scope
from scytaledroid.Database.db_utils.menus import query_runner


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

    workflow_commands = tuple(cmd for cmd in iter_commands("scan") if cmd.section == "workflow")
    tool_commands = tuple(cmd for cmd in iter_commands("scan") if cmd.section == "tools")
    insight_commands = tuple(cmd for cmd in iter_commands("readonly"))
    selectable_ids = [cmd.id for cmd in COMMANDS]

    while True:
        print()
        menu_utils.print_header("Android APK Static Analysis")
        print(status_messages.status("Choose a workflow to analyse APKs or open insight tooling.", level="info"))

        _print_command_section("Automated workflows", workflow_commands)
        _print_command_section("Interactive analysis tools", tool_commands)
        _print_command_section("Insight & reporting", insight_commands)

        print()
        menu_utils.print_menu([( "0", "Back", "Return to previous menu" )], padding=False, show_exit=False)
        choice = prompt_utils.get_choice(selectable_ids + ["0"], default="1")

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
        if command.force_app_scope and selection.scope != "app":
            print(status_messages.status("This workflow requires choosing a single app.", level="warn"))
            continue

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

            effective_params = _apply_command_overrides(params, command)

            if command.prompt_reset and _confirm_reset():
                _render_reset_outcome(reset_static_analysis_data(include_harvest=False))

            if command.persist and not effective_params.dry_run:
                effective_params = _prompt_session_label(effective_params)

            outcome = launch_scan_flow(selection, effective_params, base_dir)

            if command.auto_verify and not effective_params.dry_run:
                session_key = getattr(outcome, "session_stamp", None) if outcome else None
                if not session_key:
                    session_key = effective_params.session_stamp
                if session_key:
                    query_runner.render_session_digest(session_key)
                prompt_utils.press_enter_to_continue("Press Enter to continue…")
            break


def _print_command_section(title: str, commands: Sequence[Command]) -> None:
    if not commands:
        return
    entries: list[tuple[str, str, str]] = [
        (cmd.id, cmd.title, cmd.description) for cmd in commands
    ]
    print()
    menu_utils.print_section(title)
    menu_utils.print_menu(entries, padding=False, show_exit=False)


def _apply_command_overrides(params: RunParameters, command: Command) -> RunParameters:
    effective = params
    if command.dry_run or not command.persist:
        effective = replace(effective, dry_run=True)
    if command.force_app_scope:
        effective = replace(effective, verbose_output=True)
    return effective


def _confirm_reset() -> bool:
    return prompt_utils.prompt_yes_no(
        "Reset static-analysis tables before running?",
        default=False,
    )


def _render_reset_outcome(outcome) -> None:
    print()
    menu_utils.print_section("Reset summary")
    if outcome.truncated:
        print(status_messages.status(f"Truncated tables: {', '.join(outcome.truncated)}", level="success"))
    if outcome.failed:
        msg = ", ".join(f"{table} ({reason})" for table, reason in outcome.failed)
        print(status_messages.status(f"Failures: {msg}", level="error"))
    if outcome.skipped_protected:
        print(status_messages.status(
            f"Protected tables skipped: {', '.join(outcome.skipped_protected)}",
            level="info",
        ))
    if outcome.skipped_missing:
        print(status_messages.status(
            f"Missing tables skipped: {', '.join(outcome.skipped_missing)}",
            level="warn",
        ))
    if not (outcome.truncated or outcome.failed or outcome.skipped_missing):
        print(status_messages.status("No tables were modified.", level="info"))


def _prompt_session_label(params: RunParameters) -> RunParameters:
    current = params.session_stamp or ""
    label = prompt_utils.prompt_text(
        "Session label (press Enter to keep auto-generated)",
        default=current,
        required=False,
    ).strip()
    if not label:
        return params
    if label == current:
        return params
    return replace(params, session_stamp=label)


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
