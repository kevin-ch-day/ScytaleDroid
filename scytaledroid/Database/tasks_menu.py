"""Interactive menu for database provisioning tasks."""

from __future__ import annotations

from typing import Dict

from scytaledroid.Database.db_func.harvest import dynamic_loading, storage_surface
from scytaledroid.Database.db_func.permissions import detected_permissions, permission_support
from scytaledroid.Database.db_func.static_analysis import static_findings, string_analysis
from scytaledroid.Database.db_utils.menus import query_runner
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Persistence import db_writer


def show_database_tasks_menu() -> None:
    while True:
        print()
        menu_utils.print_header("Database Tasks")
        print(status_messages.status("Use provisioning options first, then run verification queries to confirm persistence.", level="info"))

        provisioning = [
            menu_utils.MenuOption("1", "Provision static-analysis tables", "Create findings/string summary tables if absent"),
            menu_utils.MenuOption("2", "Provision permission-analytics tables", "Create permission signal and audit tables"),
            menu_utils.MenuOption("3", "Provision harvest support tables", "Ensure file provider, dynload, and detected permission tables"),
            menu_utils.MenuOption("4", "Seed permission signal catalog", "Insert default signal weights for permission scoring"),
        ]
        verification = [
            menu_utils.MenuOption("5", "Latest session snapshot", "Show most recent session stamp and table counts"),
            menu_utils.MenuOption("6", "Session table counts", "Validate counts for a specific session stamp"),
            menu_utils.MenuOption("7", "Runs and buckets by package", "List run metadata and scoring buckets"),
            menu_utils.MenuOption("8", "Harvest artifacts by package", "View harvested APK entries for a package"),
            menu_utils.MenuOption("9", "Verify MASVS persistence", "Check latest MASVS counts for a package"),
            menu_utils.MenuOption("10", "MASVS coverage overview", "Aggregate PASS/WARN/FAIL across latest package runs"),
            menu_utils.MenuOption("11", "Audit run persistence gaps", "List runs missing static findings summaries"),
        ]

        valid_keys = ["0"]

        print()
        menu_utils.print_section("Provisioning")
        menu_utils.print_menu(provisioning, padding=False, show_exit=False, default="1")
        valid_keys.extend(option.key for option in provisioning)

        print()
        menu_utils.print_section("Verification & Queries")
        menu_utils.print_menu(verification, padding=False, show_exit=False)
        valid_keys.extend(option.key for option in verification)

        print()
        menu_utils.print_menu([menu_utils.MenuOption("0", "Back", "Return to the previous menu")], padding=False, show_exit=False)

        seen: set[str] = set()
        ordered_keys: list[str] = []
        for key in valid_keys:
            if key not in seen:
                ordered_keys.append(key)
                seen.add(key)

        choice = prompt_utils.get_choice(ordered_keys, default="1")

        if choice == "0":
            break
        if choice == "1":
            _provision_static_tables()
        elif choice == "2":
            _provision_permission_tables()
        elif choice == "3":
            _provision_harvest_tables()
        elif choice == "4":
            _seed_permission_signals()
        elif choice == "5":
            query_runner.show_latest_session()
        elif choice == "6":
            query_runner.prompt_session_counts()
        elif choice == "7":
            query_runner.prompt_runs_for_package()
        elif choice == "8":
            query_runner.prompt_harvest_for_package()
        elif choice == "9":
            query_runner.prompt_masvs_by_package()
        elif choice == "10":
            query_runner.prompt_masvs_overview()
        elif choice == "11":
            query_runner.prompt_persistence_audit()
        else:
            print(status_messages.status("Option not implemented yet.", level="warn"))


def _render_results(title: str, results: Dict[str, bool]) -> None:
    print()
    menu_utils.print_section(title)
    for table, success in results.items():
        level = "success" if success else "error"
        print(status_messages.status(f"{table}: {'OK' if success else 'FAILED'}", level=level))
    print()
    prompt_utils.press_enter_to_continue()


def _provision_static_tables() -> None:
    results = {
        "runs / buckets / metrics / findings": db_writer.ensure_schema(),
        "static_findings_summary / static_findings": static_findings.ensure_tables(),
        "static_string_summary / static_string_samples": string_analysis.ensure_tables(),
    }
    _render_results("Static-analysis tables", results)


def _provision_permission_tables() -> None:
    results = permission_support.ensure_all()
    _render_results("Permission analytics tables", results)


def _provision_harvest_tables() -> None:
    results = {
        "static_fileproviders / static_provider_acl": storage_surface.ensure_tables(),
        "static_dynload_events / static_reflection_calls": dynamic_loading.ensure_tables(),
        "android_detected_permissions": detected_permissions.ensure_table(),
    }
    _render_results("Harvest support tables", results)


def _seed_permission_signals() -> None:
    inserted = updated = 0
    try:
        outcome = permission_support.seed_signal_catalog()
        inserted = outcome.get("inserted", 0)
        updated = outcome.get("updated", 0)
        print(status_messages.status(
            f"Seeded permission signal catalog (inserted={inserted}, updated={updated})",
            level="success",
        ))
    except Exception as exc:  # pragma: no cover - defensive
        print(status_messages.status(f"Failed to seed catalog: {exc}", level="error"))
    print()
    prompt_utils.press_enter_to_continue()


__all__ = ["show_database_tasks_menu"]
