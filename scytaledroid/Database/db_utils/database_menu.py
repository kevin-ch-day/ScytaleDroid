"""Top-level Database Utilities menu."""

from __future__ import annotations

from collections.abc import Callable

from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.db_utils.menus import (
    catalog_hygiene_menu,
    db_health_integrity_menu,
    health_checks,
    permission_intel_snapshot_menu,
    query_runner,
    static_session_diagnostics_menu,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec

from .action_groups.status_actions import write_db_schema_snapshot_audit
from .menu_actions import (
    apply_canonical_schema_bootstrap,
    audit_static_risk_coverage,
    backfill_app_version_target_sdks,
    backfill_permission_audit_snapshot_totals,
    backfill_static_permission_risk_vnext,
    backfill_static_run_findings_totals,
    collapse_duplicate_app_versions,
    ensure_dynamic_tier_migrations,
    freeze_duplicate_permission_intel_tables,
    ingest_analysis_cohort_from_publication_bundle,
    maybe_clear_screen,
    purge_static_session_for_rerun,
    reconcile_static_session_artifacts,
    refresh_static_dynamic_summary_cache,
    run_inventory_determinism_comparator,
    seed_dataset_profile,
    show_connection_and_config,
    sync_contracts_to_db,
)


def _maintenance_menu() -> None:
    actions: dict[str, Callable[[], None]] = {
        "1": apply_canonical_schema_bootstrap,
        "2": ensure_dynamic_tier_migrations,
        "3": ingest_analysis_cohort_from_publication_bundle,
        "4": seed_dataset_profile,
        "5": sync_contracts_to_db,
        "6": backfill_static_run_findings_totals,
        "7": backfill_permission_audit_snapshot_totals,
        "8": backfill_static_permission_risk_vnext,
        "9": backfill_app_version_target_sdks,
        "10": collapse_duplicate_app_versions,
        "11": audit_static_risk_coverage,
        "12": refresh_static_dynamic_summary_cache,
        "13": reconcile_static_session_artifacts,
        "14": purge_static_session_for_rerun,
        "15": freeze_duplicate_permission_intel_tables,
    }

    options: list[MenuOption] = [
        MenuOption("1", "Apply canonical schema updates"),
        MenuOption("2", "Apply optional dynamic migrations"),
        MenuOption("3", "Import analysis cohort from publication bundle"),
        MenuOption("4", "Seed research dataset profile"),
        MenuOption("5", "Sync contract labels and ordering"),
        MenuOption("6", "Backfill static findings totals"),
        MenuOption("7", "Backfill permission-audit snapshot totals"),
        MenuOption("8", "Backfill static risk surfaces"),
        MenuOption("9", "Backfill app_versions targetSdk"),
        MenuOption("10", "Collapse duplicate app_versions"),
        MenuOption("11", "Audit static risk coverage gaps"),
        MenuOption("12", "Refresh static/dynamic summary cache"),
        MenuOption("13", "Reconcile static session artifacts"),
        MenuOption("14", "Purge stale static session for re-run"),
        MenuOption("15", "Freeze duplicate permission-intel tables"),
    ]

    while True:
        print()
        menu_utils.print_header("Database Maintenance & Repair")
        menu_utils.print_hint(
            "These actions can write to the database or derived cache surfaces."
        )
        menu_utils.print_section("Write-Capable Actions")
        menu_utils.render_menu(
            MenuSpec(
                items=options,
                exit_label="Back",
                show_exit=True,
                padding=False,
                show_descriptions=False,
            )
        )
        choice = prompt_utils.get_choice(
            menu_utils.selectable_keys(options, include_exit=True),
            default="0",
            disabled=[option.key for option in options if option.disabled],
        )
        if choice == "0":
            return
        action = actions.get(choice)
        if action:
            action()


def database_menu() -> None:
    """Render the database utilities menu and dispatch to sub-menus."""

    actions: dict[str, Callable[[], None]] = {
        "1": db_health_integrity_menu.database_health_and_integrity_menu,
        "2": permission_intel_snapshot_menu.permission_intel_and_snapshot_menu,
        "3": show_connection_and_config,
        "4": query_runner.run_query_menu,
        "5": run_inventory_determinism_comparator,
        "6": write_db_schema_snapshot_audit,
        "7": _maintenance_menu,
        "8": catalog_hygiene_menu.catalog_hygiene_menu,
        "9": static_session_diagnostics_menu.static_session_diagnostics_menu,
    }

    options: list[MenuOption] = [
        MenuOption(
            "1",
            "Database health & integrity (summary, latest-session checks, evidence linkage)",
        ),
        MenuOption(
            "2",
            "Permission Intel & snapshot governance (Intel DSN: snapshot status + readiness)",
        ),
        MenuOption("3", "Connection and target info"),
        MenuOption("4", "Curated SQL queries"),
        MenuOption("5", "Inventory determinism comparator"),
        MenuOption("6", "Schema snapshot audit"),
        MenuOption("7", "Maintenance, repair, and migrations"),
        MenuOption("8", "Catalog hygiene (display-name report / override preview & apply)"),
        MenuOption(
            "9",
            "Static & registry diagnostics (ledger invariants, artifact registry, session probes)",
        ),
    ]

    while True:
        maybe_clear_screen()
        schema_ver = diagnostics.get_schema_version() or "<unknown>"
        expected_schema = "0.2.6"
        connection_ok = diagnostics.check_connection()
        server_info = diagnostics.get_server_info() if connection_ok else {}
        target_database = server_info.get("database") or "<unknown>"
        menu_utils.print_header("Database Tools")
        menu_utils.print_hint(
            "Inspect schema, integrity, and governance state. "
            "Core DB vs Permission Intel: items 1 vs 2."
        )
        menu_utils.print_section("Database State")
        menu_utils.print_metrics(
            [
                ("Schema", schema_ver),
                ("Baseline", expected_schema),
                ("Connection", "OK" if connection_ok else "Unavailable"),
                ("Target DB", target_database),
            ]
        )
        if schema_ver != expected_schema and schema_ver != "<unknown>":
            print(status_messages.status(f"Schema baseline mismatch: expected {expected_schema}.", level="warn"))
            menu_utils.print_hint(
                "Open Maintenance, repair, and migrations (option 7) to apply schema updates before DB-backed workflows."
            )

        menu_utils.print_section("Read-Only Diagnostics")
        menu_utils.render_menu(
            MenuSpec(
                items=options,
                exit_label="Back",
                show_exit=True,
                padding=False,
                show_descriptions=False,
            )
        )

        choice = prompt_utils.get_choice(
            menu_utils.selectable_keys(options, include_exit=True),
            default="0",
            disabled=[option.key for option in options if option.disabled],
        )

        if choice == "0":
            break

        action = actions.get(choice)
        if action:
            action()


if __name__ == "__main__":  # pragma: no cover
    database_menu()
