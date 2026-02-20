"""Interactive menu for APK static analysis workflows.

This file should stay focused on UI: prompts, menu layout, and dispatching to
execution helpers. Non-UI logic (batch runners, selection heuristics, etc.)
lives in separate modules.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.services.static_scope_service import static_scope_service
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuItemSpec, MenuSpec
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .static_analysis_menu_helpers import (
    apply_command_overrides,
    ask_run_controls,
    choose_scope,
    collect_view_options,
    confirm_reset,
    prompt_session_label,
    render_reset_outcome,
    render_version_diff,
    resolve_last_selection,
)

if TYPE_CHECKING:
    from ..commands.models import Command


def static_analysis_menu() -> None:
    from scytaledroid.Database.db_utils import schema_gate
    from scytaledroid.Database.db_utils.menus import query_runner
    from scytaledroid.Database.db_utils.reset_static import reset_static_analysis_data
    from scytaledroid.StaticAnalysis.cli.core.run_specs import build_static_run_spec
    from scytaledroid.StaticAnalysis.cli.flows.run_dispatch import execute_run_spec
    from scytaledroid.StaticAnalysis.core.repository import group_artifacts
    from scytaledroid.StaticAnalysis.services import static_service

    from ..commands import get_command, iter_commands
    from ..core.models import RunParameters
    from ..core.run_prompts import default_custom_tests, prompt_advanced_options

    ok, message, detail = schema_gate.static_schema_gate()
    if not ok:
        status_messages.print_status(f"[ERROR] {message}", level="error")
        if detail:
            status_messages.print_status(detail, level="error")
        status_messages.print_status(
            "Fix: Database Tools → Apply Tier-1 schema migrations (or import canonical DB export), then retry.",
            level="error",
        )
        return

    base_dir = Path(app_config.DATA_DIR) / "device_apks"
    groups = tuple(group_artifacts(base_dir))
    if not groups:
        print(
            status_messages.status(
                "No harvested APK groups found. Run Device Analysis → 2 to pull artifacts.",
                level="warn",
            )
        )
        prompt_utils.press_enter_to_continue()
        return

    workflow_commands = tuple(cmd for cmd in iter_commands("scan") if cmd.section == "workflow")
    selectable_ids = [cmd.id for cmd in workflow_commands]

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
        if command.selection_mode == "batch_dataset":
            from scytaledroid.StaticAnalysis.cli.flows.static_batch import run_dataset_static_batch

            run_dataset_static_batch(
                groups=groups,
                base_dir=base_dir,
                command=command,
                static_service=static_service,
                query_runner=query_runner,
                reset_static_analysis_data=reset_static_analysis_data,
            )
            continue
        if command.selection_mode == "last":
            selection = resolve_last_selection(groups)
            if selection is None:
                prompt_utils.press_enter_to_continue()
                continue
        elif command.selection_mode == "diff_last":
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

        _show_details, show_splits, show_artifacts, return_to_menu = collect_view_options(command)
        if return_to_menu:
            continue

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
        params = replace(params, show_split_summaries=show_splits)

        while True:
            action = ask_run_controls()
            if action == "back":
                break
            if action == "advanced":
                params = prompt_advanced_options(params)
                continue

            effective_params = apply_command_overrides(params, command)

            if command.persist and not effective_params.dry_run:
                effective_params = prompt_session_label(effective_params)

            if command.prompt_reset:
                reset_mode = confirm_reset()
                if reset_mode:
                    render_reset_outcome(
                        reset_static_analysis_data(
                            include_harvest=False,
                            session_label=effective_params.session_stamp,
                            truncate_all=(reset_mode == "truncate_all"),
                        )
                    )

            try:
                spec = build_static_run_spec(
                    selection=selection,
                    params=effective_params,
                    base_dir=base_dir,
                    run_mode="interactive",
                    quiet=False,
                    noninteractive=False,
                )
                outcome = execute_run_spec(spec)
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
