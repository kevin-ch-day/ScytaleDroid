"""Top-level Database Utilities menu."""

from __future__ import annotations

from collections.abc import Callable

from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.db_utils.menus import health_checks
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec

from .menu_actions import (
    apply_canonical_schema_bootstrap,
    ensure_dynamic_tier_migrations,
    ingest_analysis_cohort_from_publication_bundle,
    maybe_clear_screen,
    seed_paper_dataset_profile,
    show_connection_and_config,
    show_governance_snapshot_status,
    sync_paper_contracts_to_db,
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
        "7": ingest_analysis_cohort_from_publication_bundle,
        "8": seed_paper_dataset_profile,
        "9": sync_paper_contracts_to_db,
    }

    options: list[MenuOption] = [
        MenuOption("1", "Apply schema updates"),
        MenuOption("2", "Health summary"),
        MenuOption("3", "Integrity check"),
        MenuOption("4", "Governance status"),
        MenuOption("5", "Connection diagnostics"),
        MenuOption("6", "Optional migrations"),
        MenuOption("7", "Ingest analysis cohort from research bundle"),
        MenuOption("8", "Seed dataset profile"),
        MenuOption("9", "Sync contract labels and ordering"),
    ]

    while True:
        maybe_clear_screen()
        schema_ver = diagnostics.get_schema_version() or "<unknown>"
        expected_schema = "0.2.6"
        menu_utils.print_header("Database Tools")
        if schema_ver != expected_schema and schema_ver != "<unknown>":
            print(f"Schema: {schema_ver} (baseline expects {expected_schema}) [OUTDATED]")
            print("Tip: Run option (1) Apply schema updates")
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
