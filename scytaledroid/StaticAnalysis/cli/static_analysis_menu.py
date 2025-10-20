"""Interactive menu for APK static analysis workflows."""

from __future__ import annotations

from pathlib import Path

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
from .menu_actions import (
    apply_command_overrides,
    ask_run_controls,
    confirm_reset,
    prompt_session_label,
    render_reset_outcome,
)


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
    default_key = workflow_commands[0].id if workflow_commands else None

    while True:
        print()
        menu_utils.print_header(
            "Android APK Static Analysis",
            subtitle="Detector workflows & tooling",
        )
        menu_utils.print_hint("Choose a workflow to analyse APKs or open insight tooling.")

        sections: list[tuple[str, tuple[Command, ...]]] = []
        if workflow_commands:
            sections.append(("Automated workflows", workflow_commands))
        if tool_commands:
            sections.append(("Interactive analysis tools", tool_commands))
        if insight_commands:
            sections.append(("Insight & reporting", insight_commands))

        rendered_section = False
        for title, commands in sections:
            if rendered_section:
                print()
            menu_utils.print_section(title)
            default = default_key if default_key in {cmd.id for cmd in commands} else None
            menu_utils.print_menu(
                [_command_option(cmd) for cmd in commands],
                show_exit=False,
                default=default,
            )
            rendered_section = True

        if rendered_section:
            print()
        menu_utils.print_menu([], show_exit=True, exit_label="Back", show_descriptions=False)
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

            effective_params = apply_command_overrides(params, command)

            if command.prompt_reset and confirm_reset():
                render_reset_outcome(reset_static_analysis_data(include_harvest=False))

            if command.persist and not effective_params.dry_run:
                effective_params = prompt_session_label(effective_params)

            outcome = launch_scan_flow(selection, effective_params, base_dir)

            if command.auto_verify and not effective_params.dry_run:
                session_key = getattr(outcome, "session_stamp", None) if outcome else None
                if not session_key:
                    session_key = effective_params.session_stamp
                if session_key:
                    query_runner.render_session_digest(session_key)
                prompt_utils.press_enter_to_continue("Press Enter to continue…")
            break


def _command_option(command: Command) -> menu_utils.MenuOption:
    badge = (command.profile or "").upper() if command.profile else None
    hints: list[str] = []
    if command.force_app_scope:
        hints.append("Requires single-app scope")
    if command.auto_verify:
        hints.append("Auto-verifies persistence")
    if command.dry_run or not command.persist:
        hints.append("Dry run")
    hint_text = " • ".join(hints) if hints else None
    return menu_utils.MenuOption(
        command.id,
        command.title,
        command.description,
        badge=badge,
        hint=hint_text,
    )



__all__ = ["static_analysis_menu"]
