"""Interactive menu for APK static analysis workflows."""

from __future__ import annotations

import os
import io
import contextlib
import time
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
    from scytaledroid.StaticAnalysis.core.repository import group_artifacts
    from scytaledroid.StaticAnalysis.services import static_service
    from scytaledroid.StaticAnalysis.cli.core.run_specs import build_static_run_spec
    from scytaledroid.StaticAnalysis.cli.flows.run_dispatch import execute_run_spec
    from scytaledroid.StaticAnalysis.cli.core.models import ScopeSelection

    from ..commands import COMMANDS, get_command, iter_commands
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
        if choice == "6" and "5" in selectable_ids:
            choice = "5"

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
        if command.id == "5":
            _run_dataset_batch(
                groups,
                base_dir,
                command,
                static_service,
                query_runner,
                reset_static_analysis_data,
            )
            continue
        if command.id == "3":
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

            if command.prompt_reset and confirm_reset():
                render_reset_outcome(reset_static_analysis_data(include_harvest=False))

            if command.persist and not effective_params.dry_run:
                effective_params = prompt_session_label(effective_params)

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


def _run_dataset_batch(
    groups,
    base_dir: Path,
    command,
    static_service,
    query_runner,
    reset_static_analysis_data,
) -> None:
    from scytaledroid.DynamicAnalysis.profile_loader import load_profile_packages
    from scytaledroid.StaticAnalysis.cli.core.models import ScopeSelection
    from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
    from scytaledroid.StaticAnalysis.cli.core.run_specs import build_static_run_spec
    from scytaledroid.StaticAnalysis.cli.flows.run_dispatch import execute_run_spec
    from scytaledroid.StaticAnalysis.session import make_session_stamp, normalize_session_stamp

    dataset_pkgs = {pkg.lower() for pkg in load_profile_packages("RESEARCH_DATASET_ALPHA")}
    if not dataset_pkgs:
        print(status_messages.status("Research Dataset Alpha profile has no apps.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    batch_groups = [group for group in groups if group.package_name and group.package_name.lower() in dataset_pkgs]
    if not batch_groups:
        print(
            status_messages.status(
                "No APK artifacts found for Research Dataset Alpha in the local library.",
                level="warn",
            )
        )
        prompt_utils.press_enter_to_continue()
        return

    quiet = True

    failures = []
    total = len(batch_groups)
    completed = 0
    batch_start = time.monotonic()
    for group in batch_groups:
        session_stamp = normalize_session_stamp(f"{make_session_stamp()}-{group.package_name}")
        display_name = ""
        for artifact in group.artifacts:
            label = artifact.metadata.get("app_label")
            if isinstance(label, str) and label.strip():
                display_name = label.strip()
                break
        selection_label = f"{display_name} ({group.package_name})" if display_name else group.package_name
        selection = ScopeSelection(scope="app", label=selection_label, groups=(group,))
        index = completed + 1
        print(
            status_messages.status(
                f"Batch {index}/{total}: {selection_label} | done={completed} fail={len(failures)}",
                level="info",
            )
        )
        print(status_messages.status("Status: running (quiet batch mode)", level="info"))

        params = RunParameters(
            profile=command.profile,
            scope=selection.scope,
            scope_label=selection.label,
            selected_tests=tuple(),
            session_stamp=session_stamp,
            show_split_summaries=False,
        )
        effective_params = apply_command_overrides(params, command)

        # Batch mode: no reset prompts; keep state deterministic.

        try:
            buffer_out = io.StringIO()
            buffer_err = io.StringIO()
            with contextlib.redirect_stdout(buffer_out), contextlib.redirect_stderr(buffer_err):
                spec = build_static_run_spec(
                    selection=selection,
                    params=effective_params,
                    base_dir=base_dir,
                    run_mode="batch",
                    quiet=True,
                    noninteractive=True,
                )
                outcome = execute_run_spec(spec)
        except static_service.StaticServiceError as exc:
            failures.append(f"{selection.label}: {exc}")
            print(status_messages.status(f"Static analysis failed: {exc}", level="error"))
            log.error(f"Static analysis run failed: {exc}", category="static")
            continue
        duration = None
        status_label = "ok"
        if outcome is None:
            status_label = "unknown"
        else:
            duration = getattr(outcome, "duration_seconds", None)
            if getattr(outcome, "failures", None):
                status_label = "failed"
            elif getattr(outcome, "aborted", False):
                status_label = "aborted"
        duration_label = f"{duration:.1f}s" if isinstance(duration, (int, float)) else "n/a"
        print(
            status_messages.status(
                f"Completed: {selection_label} | status={status_label} | duration={duration_label}",
                level="success" if status_label == "ok" else "warn",
            )
        )
        completed += 1
        elapsed = time.monotonic() - batch_start
        avg = elapsed / completed if completed else 0.0
        remaining = total - completed
        eta = avg * remaining if avg > 0 else 0.0
        print(
            status_messages.status(
                f"Progress: {completed}/{total} | fail={len(failures)} | ETA {eta:.1f}s",
                level="info",
            )
        )

        if command.auto_verify and not effective_params.dry_run and not quiet:
            session_key = getattr(outcome, "session_stamp", None) if outcome else None
            if not session_key:
                session_key = effective_params.session_stamp
            if session_key:
                query_runner.render_session_digest(session_key)

    if failures:
        print()
        menu_utils.print_section("Batch summary")
        for failure in failures:
            print(status_messages.status(f"Failed: {failure}", level="warn"))
    else:
        print()
        menu_utils.print_section("Batch summary")
        print(status_messages.status("All batch runs completed.", level="success"))
    elapsed = time.monotonic() - batch_start
    print(status_messages.status(f"Completed {completed}/{total} apps in {elapsed:.1f}s.", level="info"))
    prompt_utils.press_enter_to_continue("Press Enter to continue…")
