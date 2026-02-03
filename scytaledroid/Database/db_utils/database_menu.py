"""Top-level Database Utilities menu."""

from __future__ import annotations

from typing import Callable, Dict, List

from scytaledroid.Database.db_utils.menus import (
    health_checks,
    query_runner,
    schema_browser,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec

from .menu_actions import (
    ensure_dynamic_tier_migrations,
    maybe_clear_screen,
    seed_paper_dataset_profile,
    show_connection_and_config,
    show_db_status,
)
from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.db_core import db_config


def database_menu() -> None:
    """Render the database utilities menu and dispatch to sub-menus."""

    actions: Dict[str, Callable[[], None]] = {
        "1": seed_paper_dataset_profile,
        "2": ensure_dynamic_tier_migrations,
        "3": show_connection_and_config,
        "4": schema_browser.show_schema_browser,
        "5": health_checks.run_health_summary,
        "6": health_checks.run_app_identity_audit,
        "7": health_checks.run_evidence_integrity_check,
        "8": query_runner.run_query_menu,
        "9": health_checks.prompt_cleanup_orphan_inventory,
        "10": health_checks.prompt_finalize_stale_runs,
        "12": health_checks.prompt_delete_orphan_permission_snapshots,
        "13": health_checks.prompt_backfill_pcap_metadata,
        "14": health_checks.prompt_recompute_network_signal_quality,
        "11": health_checks.prompt_reset_static_data,
    }

    options: List[MenuOption] = [
        MenuOption("1", "Seed research dataset profile"),
        MenuOption("2", "Apply Tier-1 schema migrations"),
        MenuOption("3", "Check connection & show config"),
        MenuOption("4", "Schema browser (tables, indexes)"),
        MenuOption("5", "Health summary (one screen)"),
        MenuOption("6", "App identity audit (duplicates, missing version)"),
        MenuOption("7", "Evidence integrity check (missing/sha mismatch)"),
        MenuOption("8", "Curated queries (read-only)"),
        MenuOption("9", "Cleanup orphan snapshots (repair)"),
        MenuOption("10", "Recover stale RUNNING runs (finalize)"),
        MenuOption("12", "Delete orphan permission snapshots (repair)"),
        MenuOption("13", "Backfill PCAP metadata (repair)"),
        MenuOption("14", "Recompute network signal quality (repair)"),
        MenuOption("11", "Reset static analysis data (DESTRUCTIVE)"),
    ]

    while True:
        maybe_clear_screen()
        cfg = db_config.DB_CONFIG
        backend = str(cfg.get("engine", "sqlite"))
        database = str(cfg.get("database", "<unknown>"))
        host = str(cfg.get("host", "<local>"))
        schema_ver = diagnostics.get_schema_version() or "<unknown>"
        expected_schema = "0.2.5"
        menu_utils.print_header("Database Tools")
        print(f"Backend: {backend}")
        print(f"Database: {database}")
        print(f"Host: {host}")
        if schema_ver != expected_schema and schema_ver != "<unknown>":
            print(f"Schema: {schema_ver} (Tier-1 expects {expected_schema}) [OUTDATED]")
            print("Tip: Run option (2) Apply Tier-1 schema migrations")
        else:
            print(f"Schema: {schema_ver}")
        print()

        research_options = options[:2]
        read_only_options = options[2:8]
        maintenance_options = [options[8], options[9], options[10], options[11], options[12]]
        danger_options = [options[13]]

        menu_utils.print_section("Research / Tier-1")
        menu_utils.render_menu(
            MenuSpec(
                items=research_options,
                exit_label=None,
                show_exit=False,
                padding=True,
                show_descriptions=False,
            )
        )
        menu_utils.print_section("Read-only Diagnostics")
        menu_utils.render_menu(
            MenuSpec(
                items=read_only_options,
                exit_label=None,
                show_exit=False,
                padding=True,
                show_descriptions=False,
            )
        )
        menu_utils.print_section("Maintenance / Repairs")
        menu_utils.render_menu(
            MenuSpec(
                items=maintenance_options,
                exit_label=None,
                show_exit=False,
                padding=True,
                show_descriptions=False,
            )
        )
        menu_utils.print_section("Danger Zone (Destructive)")
        menu_utils.render_menu(
            MenuSpec(
                items=danger_options,
                exit_label="Back",
                show_exit=True,
                padding=True,
                show_descriptions=False,
            )
        )

        choice = prompt_utils.get_choice([option.key for option in options] + ["0"], default="1")

        if choice == "0":
            break

        action = actions.get(choice)
        if action:
            action()


if __name__ == "__main__":  # pragma: no cover
    database_menu()
