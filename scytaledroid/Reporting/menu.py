"""Menu dispatcher for reporting workflows.

Reporting is paper-facing and should reflect current publication artifacts first.
Older DB-centric "baseline pack" helpers remain available elsewhere, but they
should not dominate the default operator view when writing a paper.
"""

from __future__ import annotations

import os
import traceback

from scytaledroid.Utils.DisplayUtils import error_panels, menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption

from .menu_actions import (
    # Back-compat: some tests and older tooling monkeypatch this symbol.
    # It is no longer used by the default paper-facing reporting UI.
    fetch_tier1_status as fetch_tier1_status,
    fetch_publication_status,
    handle_export_freeze_anchored_csvs,
    handle_generate_exploratory_risk_scoring,
    handle_generate_publication_results_numbers,
    handle_generate_profile_v3_exports,
    handle_generate_publication_scientific_qa,
    handle_generate_publication_pipeline_audit,
    handle_print_manuscript_snapshot,
    handle_refresh_phase_e_bundle,
    handle_write_canonical_publication_bundle,
    view_saved_reports,
)


def reporting_menu() -> None:
    """Render the reporting menu until the user chooses to exit."""

    actions_all = {
        "1": handle_refresh_phase_e_bundle,
        "2": handle_generate_publication_results_numbers,
        "3": handle_generate_publication_scientific_qa,
        "4": handle_generate_publication_pipeline_audit,
        "5": handle_write_canonical_publication_bundle,
        "6": handle_export_freeze_anchored_csvs,
        "7": handle_print_manuscript_snapshot,
        "10": handle_generate_profile_v3_exports,
        "8": handle_generate_exploratory_risk_scoring,
        "9": view_saved_reports,
    }

    publication_control_options = [
        MenuOption("1", "Regenerate publication artifacts"),
        MenuOption("2", "Generate Results section (Section V)"),
        MenuOption("3", "Generate Scientific QA"),
        MenuOption("4", "Generate Pipeline audit"),
    ]
    export_options = [
        MenuOption("5", "Write canonical publication bundle (output/publication/)"),
        MenuOption("6", "Export freeze-anchored CSVs (paper-facing)"),
        MenuOption("7", "Print manuscript snapshot (1-screen)"),
    ]
    exploratory_options = [
        MenuOption("8", "Experimental risk model (SRS/DRS/FRS) (NOT FOR PAPER)"),
    ]
    reports_options = [MenuOption("9", "View saved reports")]
    profile_options = [MenuOption("10", "Generate Profile v3 exports (structural)")]

    visible_keys = {
        it.key for it in (publication_control_options + export_options + exploratory_options + reports_options + profile_options)
    }
    actions = {k: v for k, v in actions_all.items() if k in visible_keys}

    while True:
        print()
        menu_utils.print_header("Reporting")
        status = fetch_publication_status()
        audit = str(status.get("paper_audit_result") or "unknown")
        quota = status.get("evidence_quota_counted")
        expected = status.get("evidence_quota_expected")
        freeze_hash = str(status.get("freeze_dataset_hash") or "")
        freeze_short = freeze_hash[:12] if freeze_hash else "missing"
        pub_ready = "READY" if status.get("publication_ready") else "MISSING"
        tables_label = status.get("publication_tables_label") or "0"
        figs_label = status.get("publication_figures_label") or "0"
        results_ok = (status.get("results_numbers_label") or "").strip().lower() == "present"
        qa_ok = (status.get("qa_label") or "").strip().lower() == "present"

        # Compact paper-facing status card.
        if quota is not None and expected is not None:
            counts = f"{quota}/{expected} runs"
        else:
            counts = "runs unknown"
        print("Publication (Freeze Anchored)")
        print(f"Audit: {audit} | {counts} | Freeze {freeze_short} | Publication {pub_ready}")
        print(f"Artifacts: Tables {tables_label} | Figures {figs_label} | Results {'✓' if results_ok else '✗'} | QA {'✓' if qa_ok else '✗'}")
        print("Model: Isolation Forest (RDI)")

        menu_utils.print_section("Publication Control")
        menu_utils.print_menu(
            publication_control_options,
            show_exit=False,
            show_descriptions=False,
            compact=True,
        )
        menu_utils.print_section("Exports")
        menu_utils.print_menu(
            export_options,
            show_exit=False,
            show_descriptions=False,
            compact=True,
        )
        menu_utils.print_section("Exploratory (Non-Canonical)")
        menu_utils.print_menu(
            exploratory_options,
            show_exit=True,
            exit_label="Back",
            show_descriptions=False,
            compact=True,
        )
        menu_utils.print_menu(
            reports_options,
            show_exit=False,
            show_descriptions=False,
            compact=True,
        )
        menu_utils.print_menu(
            profile_options,
            show_exit=False,
            show_descriptions=False,
            compact=True,
        )
        choice = prompt_utils.get_choice(
            menu_utils.selectable_keys(
                [*publication_control_options, *export_options, *exploratory_options, *reports_options, *profile_options],
                include_exit=True,
            ),
            default="0",
        )

        if choice == "0":
            break

        action = actions.get(choice)
        if action:
            try:
                action()
            except Exception as exc:  # pragma: no cover - operator-facing guard
                debug = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower() == "debug"
                details = []
                if debug:
                    details = traceback.format_exc().splitlines()[-20:]
                error_panels.print_error_panel(
                    "Reporting Action Failed",
                    str(exc),
                    details=details,
                    hint="Re-run with SCYTALEDROID_UI_LEVEL=debug for a full traceback.",
                )
                prompt_utils.press_enter_to_continue()
        else:  # pragma: no cover - defensive path
            print(status_messages.status("Invalid selection.", level="warn"))
            prompt_utils.press_enter_to_continue()


__all__ = ["reporting_menu"]
