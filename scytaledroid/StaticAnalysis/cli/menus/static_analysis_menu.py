"""Interactive menu for APK static analysis workflows."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuItemSpec, MenuSpec
from scytaledroid.DeviceAnalysis.services.static_scope_service import static_scope_service
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from .static_analysis_menu_helpers import (
    DEV_TARGETS,
    apply_command_overrides,
    ask_run_controls,
    build_dev_selection,
    choose_scope,
    collect_view_options,
    confirm_reset,
    inject_dev_session_label,
    prompt_session_label,
    render_reset_outcome,
    render_version_diff,
    resolve_last_selection,
)

if TYPE_CHECKING:
    from ..commands.models import Command
    from ..core.models import RunParameters



def static_analysis_menu() -> None:
    from scytaledroid.Database.db_utils.menus import query_runner
    from scytaledroid.Database.db_utils.reset_static import reset_static_analysis_data

    from scytaledroid.StaticAnalysis.core.repository import group_artifacts
    from ..commands import COMMANDS, get_command, iter_commands
    from ..core.models import RunParameters
    from ..core.run_prompts import default_custom_tests, prompt_advanced_options
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
            show_descriptions=False,
        )
        if workflow_commands:
            print("Primary actions")
            print("---------------")
        menu_utils.render_menu(workflow_spec)
        if dev_commands:
            print()
            print("Calibration & regression")
            print("------------------------")
            menu_utils.render_menu(
                MenuSpec(
                    items=[_command_option(cmd) for cmd in dev_commands],
                    show_exit=False,
                    default=None,
                    show_descriptions=False,
                )
            )
        print()
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
            selection = build_dev_selection(groups, command.id)
            if selection is None:
                label, package = DEV_TARGETS.get(command.id, ("Target", "unknown"))
                print(
                    status_messages.status(
                        f"{label} not found in APK library ({package}). Skipping fixture.",
                        level="warn",
                    )
                )
                continue
        elif command.id == "3":
            selection = resolve_last_selection(groups)
            if selection is None:
                prompt_utils.press_enter_to_continue()
                continue
        elif command.id == "4":
            selection = resolve_last_selection(groups)
            if selection is None:
                prompt_utils.press_enter_to_continue()
                continue
            render_version_diff(selection.label)
            prompt_utils.press_enter_to_continue()
            continue
        else:
            selection = choose_scope(groups)
            if selection is None:
                continue
            if command.force_app_scope and selection.scope != "app":
                print(status_messages.status("This workflow requires choosing a single app.", level="warn"))
                continue

        _, show_splits, show_artifacts = collect_view_options(command)

        params = RunParameters(
            profile=command.profile,
            scope=selection.scope,
            scope_label=selection.label,
            selected_tests=(
                default_custom_tests() if command.profile == "custom" else tuple()
            ),
        )
        if show_artifacts:
            params = replace(params, artifact_detail=True)
        if command.section == "dev":
            # Make dev runs easy to identify
            params = inject_dev_session_label(params, selection)

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
    return MenuItemSpec(
        key=command.id,
        label=command.title,
        description=command.description,
        badge=None,
        hint=None,
    )



__all__ = ["static_analysis_menu"]
