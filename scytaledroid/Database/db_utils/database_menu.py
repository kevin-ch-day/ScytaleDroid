"""Top-level Database Utilities menu."""

from __future__ import annotations

from collections.abc import Callable

from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.db_utils.menus import health_checks
from scytaledroid.Database.db_utils.menus import query_runner
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec

from .menu_actions import (
    apply_canonical_schema_bootstrap,
    audit_static_risk_coverage,
    backfill_permission_audit_snapshot_totals,
    backfill_app_version_target_sdks,
    collapse_duplicate_app_versions,
    backfill_static_permission_risk_vnext,
    backfill_static_run_findings_totals,
    ensure_dynamic_tier_migrations,
    freeze_duplicate_permission_intel_tables,
    ingest_analysis_cohort_from_publication_bundle,
    maybe_clear_screen,
    purge_static_session_for_rerun,
    reconcile_static_session_artifacts,
    run_inventory_determinism_comparator,
    refresh_static_dynamic_summary_cache,
    seed_dataset_profile,
    show_connection_and_config,
    show_governance_snapshot_status,
    write_db_schema_snapshot_audit,
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
        "1": health_checks.run_health_summary,
        "2": health_checks.run_health_checks,
        "3": health_checks.run_evidence_integrity_check,
        "4": show_governance_snapshot_status,
        "5": show_connection_and_config,
        "6": query_runner.run_query_menu,
        "7": run_inventory_determinism_comparator,
        "8": write_db_schema_snapshot_audit,
        "9": _maintenance_menu,
    }

    options: list[MenuOption] = [
        MenuOption("1", "Health summary"),
        MenuOption("2", "Integrity and contract checks"),
        MenuOption("3", "Evidence linkage check"),
        MenuOption("4", "Governance snapshot status"),
        MenuOption("5", "Connection and target info"),
        MenuOption("6", "Curated SQL queries"),
        MenuOption("7", "Inventory determinism comparator"),
        MenuOption("8", "Schema snapshot audit"),
        MenuOption("9", "Maintenance, repair, and migrations"),
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
            "Inspect schema, integrity, and governance state."
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
            menu_utils.print_hint("Open Maintenance, repair, and migrations to apply schema updates before DB-backed workflows.")

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
