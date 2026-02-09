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
    show_governance_snapshot_status,
    show_connection_and_config,
)


def database_menu() -> None:
    """Render the database utilities menu and dispatch to sub-menus."""

    actions: dict[str, Callable[[], None]] = {
        "1": apply_canonical_schema_bootstrap,
        "2": health_checks.run_health_summary,
        "3": health_checks.run_evidence_integrity_check,
        "4": show_governance_snapshot_status,
        "5": show_connection_and_config,
        "6": ensure_dynamic_tier_migrations,
    }

    options: list[MenuOption] = [
        MenuOption("1", "Apply canonical schema updates (required for paper-grade)"),
        MenuOption("2", "Health summary (paper-grade readiness)"),
        MenuOption("3", "DB integrity check (DB snapshot linkage)"),
        MenuOption("4", "Governance snapshot (import/status)"),
        MenuOption("5", "Connection & config (diagnostic)"),
        MenuOption("6", "Tier-1 migrations (dynamic/ML; optional)"),
    ]

    while True:
        maybe_clear_screen()
        cfg = db_config.DB_CONFIG
        schema_ver = diagnostics.get_schema_version() or "<unknown>"
        expected_schema = "0.2.6"
        menu_utils.print_header("Database Tools")
        if schema_ver != expected_schema and schema_ver != "<unknown>":
            print(f"Schema: {schema_ver} (Tier-1 expects {expected_schema}) [OUTDATED]")
            print("Tip: Run option (1) Apply canonical schema updates")
        else:
            print(f"Schema: {schema_ver}")
        print()

        menu_utils.print_section("Readiness & Integrity")
        menu_utils.render_menu(
            MenuSpec(
                items=options,
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
