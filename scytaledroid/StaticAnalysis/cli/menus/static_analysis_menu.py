"""Interactive menu for APK static analysis workflows."""

from __future__ import annotations

import os
from functools import lru_cache
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuItemSpec, MenuSpec
from scytaledroid.DeviceAnalysis.services.static_scope_service import static_scope_service
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.StaticAnalysis.session import make_session_stamp

if TYPE_CHECKING:
    from ..commands.models import Command
    from ..core.models import RunParameters


@lru_cache(maxsize=1)
def _load_menu_actions():  # pragma: no cover - simple cache wrapper
    from . import actions

    return actions


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


def _build_dev_selection(groups, shortcut_id):
    from scytaledroid.StaticAnalysis.cli.core.models import ScopeSelection

    targets = {
        "C": ("CNN (com.cnn.mobile.android.phone)", "com.cnn.mobile.android.phone"),
        "T": ("TikTok (com.zhiliaoapp.musically)", "com.zhiliaoapp.musically"),
    }
    if shortcut_id not in targets:
        return None
    _, package = targets[shortcut_id]
    for group in groups:
        if getattr(group, "package_name", None) == package:
            return ScopeSelection(scope="app", label=package, groups=(group,))
    return None

def _library_scope_selection(groups):
    """Build a ScopeSelection from the APK library selection, if any."""
    from scytaledroid.StaticAnalysis.cli.core.models import ScopeSelection

    selected_paths = set(static_scope_service.get_selected())
    if not selected_paths:
        return None

    selected_groups = []
    for group in groups:
        if any(str(artifact.path) in selected_paths for artifact in group.artifacts):
            selected_groups.append(group)

    if not selected_groups:
        return None

    scope_label = f"Library selection ({len(selected_groups)} app{'s' if len(selected_groups) != 1 else ''})"
    scope_type = "app" if len(selected_groups) == 1 else "library-selection"
    return ScopeSelection(scope_type, scope_label, tuple(selected_groups))


def _choose_scope(groups):
    """Prompt for scope, preferring library selection when available."""
    from ..flows.selection import select_scope
    from scytaledroid.StaticAnalysis.cli.core.models import ScopeSelection

    library_scope = _library_scope_selection(groups)
    if library_scope:
        print()
        menu_utils.print_header("Static Analysis Scope")
        print(
            status_messages.status(
                f"APK library selection is active: {len(library_scope.groups)} group(s), {static_scope_service.count()} APKs.",
                level="info",
            )
        )
        choice = prompt_utils.get_choice(
            ["1", "2", "0"],
            default="1",
            prompt="1=Use selection  2=Choose different scope  0=Back ",
        )
        if choice == "0":
            return None
        if choice == "1":
            return library_scope

    return select_scope(groups)


def static_analysis_menu() -> None:
    from scytaledroid.Database.db_utils.menus import query_runner
    from scytaledroid.Database.db_utils.reset_static import reset_static_analysis_data

    from scytaledroid.StaticAnalysis.core.repository import group_artifacts
    from ..commands import COMMANDS, get_command, iter_commands
    from ..core.models import RunParameters
    from ..core.prompts import default_custom_tests, prompt_advanced_options
    from ..flows.selection import select_scope
    from scytaledroid.StaticAnalysis.services import static_service

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
    dev_commands = tuple(cmd for cmd in iter_commands("scan") if cmd.section == "dev")
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
        selected_apks = static_scope_service.count()
        if selected_apks:
            print(
                status_messages.status(
                    f"Library selection: {selected_apks} APKs marked. You can run scans on this selection.",
                    level="info",
                )
            )
        workflow_spec = MenuSpec(
            items=[_command_option(cmd) for cmd in workflow_commands],
            show_exit=False,
            default=default_key if default_key in {cmd.id for cmd in workflow_commands} else None,
        )
        if workflow_commands:
            print("Primary actions")
            print("---------------")
        menu_utils.render_menu(workflow_spec)
        if dev_commands:
            print("Calibration & regression")
            print("------------------------")
            menu_utils.render_menu(
                MenuSpec(
                    items=[_command_option(cmd) for cmd in dev_commands],
                    show_exit=False,
                    default=None,
                )
            )
        back_spec = MenuSpec(
            items=[],
            exit_label="Back",
            show_exit=True,
            show_descriptions=False,
        )
        menu_utils.render_menu(back_spec)
        choice_pool = selectable_ids + ["0"]
        choice = prompt_utils.get_choice(choice_pool, default=default_choice)

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

        selection = None
        if command.section == "dev":
            selection = _build_dev_selection(groups, command.id)
            if selection is None:
                print(status_messages.status("Dev shortcut target not found in repository.", level="error"))
                continue
        else:
            selection = _choose_scope(groups)
            if selection is None:
                continue
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
        if command.section == "dev":
            # Make dev runs easy to identify
            short = selection.label.split(".")[-1]
            params = replace(params, session_stamp=f"static-dev-{short}-{make_session_stamp()}")

        # Optional split breakdown prompt (default off to keep output compact).
        show_splits = prompt_utils.prompt_yes_no("Show split breakdown? (y/N)", default=False)
        os.environ["SCYTALEDROID_STATIC_SHOW_SPLITS"] = "1" if show_splits else "0"

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

            try:
                result = static_service.run_scan(
                    selection,
                    effective_params,
                    base_dir,
                    study_tag=getattr(effective_params, "study_tag", None),
                    pipeline_version=getattr(effective_params, "analysis_version", None),
                    catalog_versions=None,
                    config_hash=None,
                )
                outcome = result.outcome
            except static_service.StaticServiceError as exc:
                print(status_messages.status(f"Static analysis failed: {exc}", level="error"))
                log.error(f"Static analysis run failed: {exc}", category="static")
                prompt_utils.press_enter_to_continue()
                break

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
