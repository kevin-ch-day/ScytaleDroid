"""Interactive menu for APK static analysis workflows."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuItemSpec, MenuSpec

if TYPE_CHECKING:
    from .commands.models import Command
    from .models import RunParameters


@lru_cache(maxsize=1)
def _load_menu_actions():  # pragma: no cover - simple cache wrapper
    from . import menu_actions

    return menu_actions


def apply_command_overrides(
    params: "RunParameters",
    command: "Command",
) -> "RunParameters":
    actions = _load_menu_actions()
    return actions.apply_command_overrides(params, command)


def ask_run_controls() -> str:
    actions = _load_menu_actions()
    return actions.ask_run_controls()


def confirm_reset() -> bool:
    actions = _load_menu_actions()
    return actions.confirm_reset()


def prompt_session_label(params: "RunParameters") -> "RunParameters":
    actions = _load_menu_actions()
    return actions.prompt_session_label(params)


def render_reset_outcome(outcome: object) -> None:
    actions = _load_menu_actions()
    actions.render_reset_outcome(outcome)


def static_analysis_menu() -> None:
    from scytaledroid.Database.db_utils.menus import query_runner
    from scytaledroid.Database.db_utils.reset_static import reset_static_analysis_data

    from ..core.repository import group_artifacts
    from .commands import COMMANDS, get_command, iter_commands
    from .models import RunParameters
    from .prompts import default_custom_tests, prompt_advanced_options
    from .runner import launch_scan_flow
    from .scope import select_scope

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

    if not selectable_ids:
        print(status_messages.status("No static analysis commands are registered.", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    default_key = workflow_commands[0].id if workflow_commands else None
    default_choice = default_key or selectable_ids[0]

    while True:
        print()
        menu_utils.print_header("Android APK Static Analysis")
        workflow_spec = MenuSpec(
            items=[_command_option(cmd) for cmd in workflow_commands],
            show_exit=False,
            default=default_key if default_key in {cmd.id for cmd in workflow_commands} else None,
        )
        menu_utils.render_menu(workflow_spec)
        back_spec = MenuSpec(
            items=[],
            exit_label="Back",
            show_exit=True,
            show_descriptions=False,
        )
        menu_utils.render_menu(back_spec)
        choice = prompt_utils.get_choice(selectable_ids + ["0"], default=default_choice)

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
    return MenuItemSpec(
        key=command.id,
        label=command.title,
        description=command.description,
        badge=badge,
        hint=hint_text,
    )



__all__ = ["static_analysis_menu"]
