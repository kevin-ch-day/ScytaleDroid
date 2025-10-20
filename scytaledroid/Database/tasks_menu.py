"""Interactive menu for database provisioning tasks."""

from __future__ import annotations

from scytaledroid.Database.db_utils.menus import query_runner
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from .tasks_actions import (
    provision_harvest_tables,
    provision_permission_tables,
    provision_static_tables,
    seed_permission_signals,
)


def show_database_tasks_menu() -> None:
    """Display the database tasks menu and dispatch actions."""

    actions = {
        "1": provision_static_tables,
        "2": provision_permission_tables,
        "3": provision_harvest_tables,
        "4": seed_permission_signals,
        "5": query_runner.show_latest_session,
        "6": query_runner.prompt_session_counts,
        "7": query_runner.prompt_runs_for_package,
        "8": query_runner.prompt_harvest_for_package,
        "9": query_runner.prompt_masvs_by_package,
        "10": query_runner.prompt_masvs_overview,
        "11": query_runner.prompt_persistence_audit,
    }

    while True:
        print()
        menu_utils.print_header("Database Tasks")
        print(
            status_messages.status(
                "Use provisioning options first, then run verification queries to confirm persistence.",
                level="info",
            )
        )

        provisioning = [
            menu_utils.MenuOption(
                "1",
                "Provision static-analysis tables",
                "Create findings/string summary tables if absent",
            ),
            menu_utils.MenuOption(
                "2",
                "Provision permission-analytics tables",
                "Create permission signal and audit tables",
            ),
            menu_utils.MenuOption(
                "3",
                "Provision harvest support tables",
                "Ensure file provider, dynload, and detected permission tables",
            ),
            menu_utils.MenuOption(
                "4",
                "Seed permission signal catalog",
                "Insert default signal weights for permission scoring",
            ),
        ]
        verification = [
            menu_utils.MenuOption(
                "5",
                "Latest session snapshot",
                "Show most recent session stamp and table counts",
            ),
            menu_utils.MenuOption(
                "6",
                "Session table counts",
                "Validate counts for a specific session stamp",
            ),
            menu_utils.MenuOption(
                "7",
                "Runs and buckets by package",
                "List run metadata and scoring buckets",
            ),
            menu_utils.MenuOption(
                "8",
                "Harvest artifacts by package",
                "View harvested APK entries for a package",
            ),
            menu_utils.MenuOption(
                "9",
                "Verify MASVS persistence",
                "Check latest MASVS counts for a package",
            ),
            menu_utils.MenuOption(
                "10",
                "MASVS coverage overview",
                "Aggregate PASS/WARN/FAIL across latest package runs",
            ),
            menu_utils.MenuOption(
                "11",
                "Audit run persistence gaps",
                "List runs missing static findings summaries",
            ),
        ]

        print()
        menu_utils.print_section("Provisioning")
        menu_utils.print_menu(provisioning, padding=False, show_exit=False, default="1")

        print()
        menu_utils.print_section("Verification & Queries")
        menu_utils.print_menu(verification, padding=False, show_exit=False)

        print()
        menu_utils.print_menu(
            [menu_utils.MenuOption("0", "Back", "Return to the previous menu")],
            padding=False,
            show_exit=False,
        )

        valid_keys = [option.key for option in provisioning + verification] + ["0"]
        choice = prompt_utils.get_choice(valid_keys, default="1")

        if choice == "0":
            break

        action = actions.get(choice)
        if action is None:
            print(status_messages.status("Option not implemented yet.", level="warn"))
            continue

        action()


__all__ = ["show_database_tasks_menu"]
