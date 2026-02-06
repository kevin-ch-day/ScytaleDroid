"""Top-level Database Utilities menu."""

from __future__ import annotations

from collections.abc import Callable

from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.db_utils.menus import health_checks
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec

from .menu_actions import (
    apply_canonical_schema_bootstrap,
    ensure_dynamic_tier_migrations,
    maybe_clear_screen,
    show_connection_and_config,
)


def database_menu() -> None:
    """Render the database utilities menu and dispatch to sub-menus."""

    actions: dict[str, Callable[[], None]] = {
        "1": apply_canonical_schema_bootstrap,
        "2": ensure_dynamic_tier_migrations,
        "3": show_connection_and_config,
        "6": health_checks.run_health_summary,
        "8": health_checks.run_evidence_integrity_check,
        "10": health_checks.prompt_cleanup_orphan_inventory,
        "11": health_checks.prompt_finalize_stale_runs,
        "13": health_checks.prompt_delete_orphan_permission_snapshots,
        "14": health_checks.prompt_backfill_pcap_metadata,
        "15": health_checks.prompt_recompute_network_signal_quality,
        "12": health_checks.prompt_reset_static_data,
    }

    options: list[MenuOption] = [
        MenuOption("1", "Apply canonical schema bootstrap (static + registry + ML)"),
        MenuOption("2", "Apply Tier-1 schema migrations"),
        MenuOption("3", "Connection & config"),
        MenuOption("6", "Health summary"),
        MenuOption("8", "Evidence integrity check"),
        MenuOption("10", "Cleanup orphan snapshots"),
        MenuOption("11", "Recover stale RUNNING runs"),
        MenuOption("13", "Delete orphan permission snapshots"),
        MenuOption("14", "Backfill PCAP metadata"),
        MenuOption("15", "Recompute network signal quality"),
        MenuOption("12", "Reset"),
    ]

    while True:
        maybe_clear_screen()
        cfg = db_config.DB_CONFIG
        backend = str(cfg.get("engine", "sqlite"))
        database = str(cfg.get("database", "<unknown>"))
        host = str(cfg.get("host", "<local>"))
        schema_ver = diagnostics.get_schema_version() or "<unknown>"
        expected_schema = "0.2.6"
        menu_utils.print_header("Database Tools")
        print(f"Backend: {backend}")
        print(f"Database: {database}")
        print(f"Host: {host}")
        print(f"Config: {db_config.DB_CONFIG_SOURCE}")
        if schema_ver != expected_schema and schema_ver != "<unknown>":
            print(f"Schema: {schema_ver} (Tier-1 expects {expected_schema}) [OUTDATED]")
            print("Tip: Run option (2) Apply canonical schema bootstrap")
        else:
            print(f"Schema: {schema_ver}")
        print()

        research_options = options[:2]
        read_only_options = [options[2], options[3], options[4]]
        maintenance_options = [options[5], options[6], options[7], options[8], options[9]]
        danger_options = [options[10]]

        menu_utils.print_section("Research / Tier-1")
        menu_utils.render_menu(
            MenuSpec(
                items=research_options,
                exit_label=None,
                show_exit=False,
                padding=False,
                show_descriptions=False,
            )
        )
        print()
        menu_utils.print_section("Read-only Diagnostics")
        menu_utils.render_menu(
            MenuSpec(
                items=read_only_options,
                exit_label=None,
                show_exit=False,
                padding=False,
                show_descriptions=False,
            )
        )
        print()
        menu_utils.print_section("Maintenance / Repairs")
        menu_utils.render_menu(
            MenuSpec(
                items=maintenance_options,
                exit_label=None,
                show_exit=False,
                padding=False,
                show_descriptions=False,
            )
        )
        print()
        menu_utils.print_section("Danger Zone (Destructive)")
        menu_utils.render_menu(
            MenuSpec(
                items=danger_options,
                exit_label="Back",
                show_exit=True,
                padding=False,
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
