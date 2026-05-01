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

if TYPE_CHECKING:
    from ..commands.models import Command
    from ..core.models import ScopeSelection


def _distinct_package_count(groups: tuple) -> int:
    return len(
        {
            str(getattr(group, "package_name", "") or "").strip().lower()
            for group in groups
            if getattr(group, "package_name", None)
        }
    )


def _latest_scope_for_all(groups: tuple) -> "ScopeSelection":
    from ..core.models import ScopeSelection
    from ..flows.selection import select_latest_groups

    grouped: dict[str, list[object]] = {}
    order: list[str] = []
    for group in groups:
        package = str(getattr(group, "package_name", "") or "").strip().lower()
        if not package:
            continue
        if package not in grouped:
            grouped[package] = []
            order.append(package)
        grouped[package].append(group)

    selected = []
    for package in order:
        selected.extend(select_latest_groups(tuple(grouped[package])))
    return ScopeSelection("all", "All harvested apps", tuple(selected))


def _choose_all_scope_variant(selection: "ScopeSelection") -> "ScopeSelection | None":
    from ..core.models import ScopeSelection

    total = len(selection.groups)
    print()
    menu_utils.print_section("Batch Size")
    print("1) All apps")
    print("2) Smoke batch (5)")
    print("3) Smoke batch (10)")
    print("4) Smoke batch (20)")
    print("5) Persistence test batch (10)")
    print("0) Back")
    choice = prompt_utils.get_choice(["1", "2", "3", "4", "5", "0"], default="1")
    if choice == "0":
        return None
    if choice == "1":
        return selection

    batch_sizes = {"2": 5, "3": 10, "4": 20, "5": 10}
    batch_size = min(batch_sizes[choice], total)
    scoped = tuple(selection.groups[:batch_size])
    return ScopeSelection(
        "all",
        (
            f"Persistence test ({batch_size} apps)"
            if choice == "5"
            else f"Smoke batch ({batch_size} apps)"
        ),
        scoped,
    )


def _search_app_scope(groups: tuple) -> "ScopeSelection | None":
    from ..core.models import ScopeSelection
    from ..flows.selection import select_latest_groups
    from ...core.repository import list_packages

    packages = list_packages(groups)
    if not packages:
        print(status_messages.status("No packages available for analysis.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return None

    print()
    menu_utils.print_header("Analyze One App")
    print("Search by package or app name.")
    print()
    print("Examples:")
    print("- signal")
    print("- instagram")
    print("- com.whatsapp")
    print("- twitter")
    print("- google")
    print()
    query = prompt_utils.prompt_text("Search", required=False).strip().lower()
    if not query:
        return None

    indexed_matches: list[tuple[int, tuple[str, str, int, str | None]]] = [
        (idx, item)
        for idx, item in enumerate(packages)
        if query in item[0].lower() or (item[3] and query in item[3].lower())
    ]
    if not indexed_matches:
        print(status_messages.status(f"No apps matched '{query}'.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return None

    def _match_rank(item: tuple[str, str, int, str | None], original_index: int) -> tuple[int, int, int, int, int]:
        package_name, _version, _count, app_label = item
        package_lc = package_name.lower()
        label_lc = str(app_label or "").lower()

        if package_lc == query:
            rank = 0
        elif label_lc == query:
            rank = 1
        elif package_lc.startswith(query):
            rank = 2
        elif label_lc.startswith(query):
            rank = 3
        elif query in package_lc:
            rank = 4
        else:
            rank = 5

        return (
            rank,
            len(package_name),
            len(str(app_label or package_name)),
            0 if package_name.startswith("com.") else 1,
            original_index,
        )

    matches = [item for _idx, item in sorted(indexed_matches, key=lambda entry: _match_rank(entry[1], entry[0]))]

    print()
    menu_utils.print_section("Matches")
    limited = matches[:20]
    for idx, (package, _version, _count, app_label) in enumerate(limited, start=1):
        label = app_label or package
        print(f"{idx}) {label:<18} {package}")
    print("0) Back")
    choice = prompt_utils.get_choice(
        [str(i) for i in range(1, len(limited) + 1)] + ["0"],
        default="1",
    )
    if choice == "0":
        return None

    package_name, _version, _count, app_label = limited[int(choice) - 1]
    matching_groups = tuple(group for group in groups if group.package_name == package_name)
    scoped = select_latest_groups(matching_groups)
    label = f"{app_label} | {package_name}" if app_label else package_name
    return ScopeSelection("app", label, scoped)


def _choose_run_profile() -> "Command | None":
    from ..commands import get_command
    from ..commands.models import Command

    print()
    menu_utils.print_section("Analysis Preset")
    print("1) Full analysis")
    print("2) Fast analysis")
    print("3) Persistence test")
    print("4) Advanced profiles")
    print("0) Back")
    choice = prompt_utils.get_choice(["1", "2", "3", "4", "0"], default="1", casefold=True)
    if choice == "0":
        return None
    if choice in {"1", "2"}:
        command = get_command(choice)
        if command is not None:
            return command
    if choice == "3":
        return Command(
            id="T",
            title="Persistence test",
            description="Run a compact end-to-end persistence/finalization validation.",
            kind="scan",
            profile="full",
            section="workflow",
            auto_verify=True,
            prompt_reset=True,
            workers_override="2",
        )

    print()
    menu_utils.print_section("Advanced Profiles")
    print("1) Metadata smoke")
    print("2) Permission audit")
    print("3) Strings and secrets")
    print("4) IPC and components")
    print("5) Network surface")
    print("6) Crypto hygiene")
    print("7) SDK inventory")
    print("0) Back")
    choice = prompt_utils.get_choice(["1", "2", "3", "4", "5", "6", "7", "0"], default="1")
    if choice == "0":
        return None
    focused_profiles = {
        "1": ("metadata", "Metadata smoke"),
        "2": ("permissions", "Permission audit"),
        "3": ("strings", "Strings and secrets"),
        "4": ("ipc", "IPC and components"),
        "5": ("nsc", "Network surface"),
        "6": ("crypto", "Crypto hygiene"),
        "7": ("sdk", "SDK inventory"),
    }
    profile, title = focused_profiles[choice]
    return Command(
        id=choice,
        title=title,
        description=title,
        kind="scan",
        profile=profile,
        section="workflow",
        auto_verify=True,
    )


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
        menu_utils.print_header("Android APK Static Analysis")
        print()
        print(f"APK library: {_distinct_package_count(groups)} packages")

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

        print("1) Analyze all harvested apps")
        print("2) Analyze by profile")
        print("3) Analyze one app")
        print("4) Re-analyze last app")

        print()
        print("5) View previous static runs")
        print("6) Compare two app versions")

        print()
        print("D) APK drilldown")
        print("L) Library details")

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
            continue

        selection: ScopeSelection | None
        if choice == "1":
            selection = _latest_scope_for_all(groups)
            selection = _choose_all_scope_variant(selection)
            if selection is None:
                continue
            print()
            menu_utils.print_header("Analyze All Apps")
            menu_utils.print_metrics(
                [
                    ("Packages", len(selection.groups)),
                    ("Mode", "latest per package"),
                    ("Scope", selection.label),
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


__all__ = [
    "static_analysis_menu",
    "_distinct_package_count",
]
