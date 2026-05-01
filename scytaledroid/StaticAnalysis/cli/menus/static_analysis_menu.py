"""Interactive scope-first menu for APK static analysis workflows."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.DeviceAnalysis.services.static_scope_service import static_scope_service
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .static_analysis_menu_helpers import (
    apply_command_overrides,
    ask_run_controls,
    collect_view_options,
    confirm_reset,
    describe_last_selection,
    prompt_run_setup,
    prompt_session_label,
    render_run_preflight,
    render_reset_outcome,
    render_version_diff,
    resolve_last_selection,
)
from .static_analysis_menu_ops import (
    choose_all_scope_variant as _choose_all_scope_variant,
    choose_run_profile as _choose_run_profile,
    distinct_package_count as _distinct_package_count,
    latest_scope_for_all as _latest_scope_for_all,
    search_app_scope as _search_app_scope,
)

if TYPE_CHECKING:
    from ..commands.models import Command
    from ..core.models import ScopeSelection


def _run_command_for_selection(
    command: "Command",
    selection: "ScopeSelection",
    *,
    analysis_root,
    persistence_gate_status,
    query_runner,
    prompt_advanced_options,
    reset_static_analysis_data,
    build_static_run_spec,
    execute_run_spec,
    static_service,
) -> None:
    from ..core.models import RunParameters

    if command.persist and not command.dry_run:
        persistence_ready, persistence_detail = persistence_gate_status()
        if not persistence_ready:
            print(
                status_messages.status(
                    f"Static analysis persistence gate failed: {persistence_detail}",
                    level="error",
                )
            )
            print(
                status_messages.status(
                    "Run Database Tools → Apply Tier-1 schema migrations, or use a dry-run command.",
                    level="error",
                )
            )
            prompt_utils.press_enter_to_continue()
            return

    show_splits = False
    show_artifacts = False
    if command.kind == "readonly":
        _show_details, show_splits, show_artifacts, return_to_menu = collect_view_options(command)
        if return_to_menu:
            return

    params = RunParameters(
        profile=command.profile or "full",
        scope=selection.scope,
        scope_label=selection.label,
        selected_tests=tuple(),
    )
    if show_artifacts:
        params = replace(params, artifact_detail=True)
    params = replace(params, show_split_summaries=show_splits)

    while True:
        effective_params = apply_command_overrides(params, command)
        reset_mode = None

        if command.persist and not effective_params.dry_run:
            action, effective_params, reset_mode = prompt_run_setup(
                effective_params,
                selection,
                command,
            )
            if action == "cancel":
                return
            if action == "advanced":
                params = prompt_advanced_options(effective_params)
                continue
        else:
            action = ask_run_controls()
            if action == "back":
                return
            if action == "advanced":
                params = prompt_advanced_options(params)
                continue

        if reset_mode == "session":
            render_reset_outcome(
                reset_static_analysis_data(
                    include_harvest=False,
                    session_label=effective_params.session_stamp,
                    truncate_all=(reset_mode == "truncate_all"),
                ),
                session_label=effective_params.session_stamp,
            )

        try:
            spec = build_static_run_spec(
                selection=selection,
                params=effective_params,
                base_dir=analysis_root,
                run_mode="interactive",
                quiet=False,
                noninteractive=False,
            )
            outcome = execute_run_spec(spec)
        except static_service.StaticServiceError as exc:
            print(status_messages.status(f"Static analysis failed: {exc}", level="error"))
            log.error(f"Static analysis run failed: {exc}", category="static")
            prompt_utils.press_enter_to_continue()
            return

        if command.auto_verify and not effective_params.dry_run and not getattr(outcome, "aborted", False):
            session_key = getattr(outcome, "session_stamp", None) if outcome else None
            if not session_key:
                session_key = effective_params.session_stamp
            if session_key:
                query_runner.render_session_digest(session_key)
            prompt_utils.press_enter_to_continue("Press Enter to continue…")
        return


def static_analysis_menu() -> None:
    from scytaledroid.Database.db_utils import schema_gate
    from scytaledroid.Database.db_utils.menus import query_runner
    from scytaledroid.Database.db_utils.reset_static import reset_static_analysis_data
    from scytaledroid.DeviceAnalysis.apk_library_menu import apk_library_menu
    from scytaledroid.StaticAnalysis.cli.core.run_specs import build_static_run_spec
    from scytaledroid.StaticAnalysis.cli.flows.run_dispatch import execute_run_spec
    from scytaledroid.StaticAnalysis.cli.flows.selection import select_category_scope
    from scytaledroid.StaticAnalysis.cli.persistence.reports.session_diagnostics import render_static_diagnostics_menu
    from scytaledroid.StaticAnalysis.core.repository import group_artifacts
    from scytaledroid.StaticAnalysis.services import static_service

    from ..commands import get_command
    from ..core.run_prompts import prompt_advanced_options

    analysis_root = artifact_store.analysis_apk_root()

    def _load_groups() -> tuple:
        return tuple(group_artifacts())

    def _persistence_gate_status() -> tuple[bool, str | None]:
        ok_base, message_base, detail_base = schema_gate.check_base_schema()
        if not ok_base:
            detail = f" {detail_base}" if detail_base else ""
            return False, f"{message_base}{detail}"
        ok_static, message_static, detail_static = schema_gate.static_schema_gate()
        if not ok_static:
            detail = f" {detail_static}" if detail_static else ""
            return False, f"{message_static}{detail}"
        return True, None

    def _dispatch_run(command: "Command", selection: "ScopeSelection") -> None:
        _run_command_for_selection(
            command,
            selection,
            analysis_root=analysis_root,
            persistence_gate_status=_persistence_gate_status,
            query_runner=query_runner,
            prompt_advanced_options=prompt_advanced_options,
            reset_static_analysis_data=reset_static_analysis_data,
            build_static_run_spec=build_static_run_spec,
            execute_run_spec=execute_run_spec,
            static_service=static_service,
        )

    while True:
        groups = _load_groups()
        static_scope_service.prune_missing_paths(
            tuple(str(artifact.path) for group in groups for artifact in group.artifacts)
        )
        if not groups:
            print(
                status_messages.status(
                    "No harvested APK groups found. Run Device Analysis → Execute Harvest, then retry.",
                    level="warn",
                )
            )
            prompt_utils.press_enter_to_continue()
            return

        last_info = describe_last_selection(groups)

        print()
        menu_utils.print_header(
            "Android APK Static Analysis",
            "Analyze APKs that have already been harvested and stored locally.",
        )
        menu_utils.print_hint("This does not query the live device inventory.")

        pkgs = _distinct_package_count(groups)
        print()
        menu_utils.print_section("Harvested library")
        print(f"  Packages          : {pkgs}")
        print(f"  Harvest captures  : {len(groups)}")
        print("  Capture meaning   : one package/version harvested in one session;")
        print("                      may include a base APK plus split APKs.")

        persistence_ready, persistence_detail = _persistence_gate_status()
        if not persistence_ready:
            print(
                status_messages.status(
                    f"Persistence unavailable: {persistence_detail}",
                    level="warn",
                )
            )
            print(
                status_messages.status(
                    "Dry-run commands remain available; persisted scans will gate when selected.",
                    level="warn",
                )
            )

        menu_utils.print_section("Run scope")
        print("  1) Analyze all harvested apps")
        print("  2) Analyze by profile")
        print("  3) Analyze one app")
        print("  4) Re-analyze last app")

        menu_utils.print_section("Review")
        print("  5) View previous static runs")
        print("  6) Compare two app versions")
        print("  D) APK drilldown")
        print("  L) Library details")

        print()
        print("0) Back")

        choice = prompt_utils.get_choice(
            ["1", "2", "3", "4", "5", "6", "D", "L", "0"],
            default="1",
            casefold=True,
        )

        if choice == "0":
            break

        if choice == "5":
            render_static_diagnostics_menu()
            continue

        if choice.lower() == "l":
            apk_library_menu()
            continue

        if choice == "4":
            command = get_command("3")
            selection = resolve_last_selection(groups)
            if command is None or selection is None:
                print(status_messages.status("No prior app is available to re-analyze.", level="warn"))
                prompt_utils.press_enter_to_continue()
                continue
            if last_info.get("label"):
                print()
                menu_utils.print_header("Re-analyze Last App", str(last_info.get("label") or ""))
            _dispatch_run(command, selection)
            continue

        if choice == "6":
            selection = _search_app_scope(groups)
            if selection is None:
                continue
            package_name = selection.groups[0].package_name if selection.groups else selection.label
            render_version_diff(package_name)
            prompt_utils.press_enter_to_continue()
            continue

        if choice.lower() == "d":
            selection = _search_app_scope(groups)
            if selection is None:
                continue
            command = get_command("D")
            if command is None:
                print(status_messages.status("Static drilldown command is not registered.", level="error"))
                prompt_utils.press_enter_to_continue()
                continue
            _dispatch_run(command, selection)
            continue

        selection: ScopeSelection | None
        if choice == "1":
            selection = _latest_scope_for_all(groups)
            selection = _choose_all_scope_variant(selection)
            if selection is None:
                continue
            print()
            menu_utils.print_header(
                "Analyze All Harvested Apps",
                "Targets below follow 'newest capture per package' (batch options may shorten the list).",
            )
            menu_utils.print_metrics(
                [
                    ("Apps in run", len(selection.groups)),
                    ("Batch label", selection.label),
                ]
            )
        elif choice == "2":
            selection = select_category_scope(groups)
        elif choice == "3":
            selection = _search_app_scope(groups)
        else:
            print(status_messages.status("Unsupported option selected.", level="warn"))
            continue

        if selection is None:
            continue
        if not selection.groups:
            print(status_messages.status("No APK targets were resolved for that scope.", level="warn"))
            prompt_utils.press_enter_to_continue()
            continue

        command = _choose_run_profile()
        if command is None:
            continue

        _dispatch_run(command, selection)


__all__ = [
    "static_analysis_menu",
]
