"""Top-level Database Utilities menu."""

from __future__ import annotations

from typing import Callable, Dict, List

from scytaledroid.Database.db_utils.menus import (
    health_checks,
    query_runner,
    schema_browser,
)
from scytaledroid.DynamicAnalysis.exports.dataset_export import export_manifest_csv
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
        "3": _run_manifest_export,
        "4": show_connection_and_config,
        "5": schema_browser.show_schema_browser,
        "6": health_checks.run_health_summary,
        "7": health_checks.run_app_identity_audit,
        "8": health_checks.run_evidence_integrity_check,
        "9": query_runner.run_query_menu,
        "10": health_checks.run_tier1_audit_report,
        "11": health_checks.prompt_cleanup_orphan_inventory,
        "12": health_checks.prompt_finalize_stale_runs,
        "13": health_checks.prompt_reset_static_data,
    }

    options: List[MenuOption] = [
        MenuOption(
            "1",
            "Seed research dataset profile",
            "Create/update Research Dataset Alpha (v1).",
        ),
        MenuOption(
            "2",
            "Apply Tier-1 schema migrations",
            "Adds tier + network_signal_quality columns.",
        ),
        MenuOption(
            "3",
            "Export dynamic dataset manifest (CSV)",
            "Build the ScytaleDroid-Dyn-v1 manifest export.",
        ),
        MenuOption(
            "4",
            "Check connection & show config",
            "Verify DB connection, backend, schema version.",
        ),
        MenuOption(
            "5",
            "Schema browser (tables, indexes)",
            "Inspect table schema, PKs, and indexes.",
        ),
        MenuOption(
            "6",
            "Health summary (one screen)",
            "One-screen DB health and counts.",
        ),
        MenuOption(
            "7",
            "App identity audit (duplicates, missing version)",
            "Find duplicate packages and missing versions.",
        ),
        MenuOption(
            "8",
            "Evidence integrity check (missing/sha mismatch)",
            "Detect missing or mismatched evidence artifacts.",
        ),
        MenuOption(
            "9",
            "Curated queries (read-only)",
            "Safe, read-only SQL checks.",
        ),
        MenuOption(
            "10",
            "Tier-1 audit report (dataset readiness)",
            "One-screen Tier-1 readiness and schema checks.",
        ),
        MenuOption(
            "11",
            "Cleanup orphan snapshots (repair)",
            "Remove orphaned inventory snapshots.",
        ),
        MenuOption(
            "12",
            "Recover stale RUNNING runs (finalize)",
            "Finalize orphaned RUNNING sessions.",
        ),
        MenuOption(
            "13",
            "Reset static analysis data (DESTRUCTIVE)",
            "Clear static analysis tables (dangerous).",
        ),
    ]

    while True:
        maybe_clear_screen()
        cfg = db_config.DB_CONFIG
        backend = str(cfg.get("engine", "sqlite"))
        database = str(cfg.get("database", "<unknown>"))
        host = str(cfg.get("host", "<local>"))
        schema_ver = diagnostics.get_schema_version() or "<unknown>"
        menu_utils.print_header("Database Tools")
        print(f"Backend: {backend}")
        print(f"Database: {database}")
        print(f"Host: {host}")
        print(f"Schema: {schema_ver}")
        print()

        menu_utils.print_section("Research / Tier-1")
        menu_utils.render_menu(
            MenuSpec(
                items=options[:3],
                exit_label=None,
                show_exit=False,
                padding=True,
                show_descriptions=False,
            )
        )
        menu_utils.print_section("Read-only Diagnostics")
        menu_utils.render_menu(
            MenuSpec(
                items=options[3:10],
                exit_label=None,
                show_exit=False,
                padding=True,
                show_descriptions=False,
            )
        )
        menu_utils.print_section("Maintenance / Repairs")
        menu_utils.render_menu(
            MenuSpec(
                items=options[10:12],
                exit_label=None,
                show_exit=False,
                padding=True,
                show_descriptions=False,
            )
        )
        menu_utils.print_section("Danger Zone (Destructive)")
        menu_utils.render_menu(
            MenuSpec(
                items=options[12:],
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


def _run_manifest_export() -> None:
    from pathlib import Path
    from scytaledroid.Config import app_config
    from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages

    default_path = Path(app_config.OUTPUT_DIR) / "exports" / "scytaledroid_dyn_v1_manifest.csv"
    print(status_messages.status(f"Export path: {default_path}", level="info"))
    if not prompt_utils.prompt_yes_no("Generate manifest export now?", default=True):
        return
    output_path = export_manifest_csv(default_path)
    print(status_messages.status(f"Manifest written: {output_path}", level="success"))
    prompt_utils.press_enter_to_continue()


if __name__ == "__main__":  # pragma: no cover
    database_menu()
