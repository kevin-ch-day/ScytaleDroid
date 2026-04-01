"""Menu dispatcher for reporting workflows."""

from __future__ import annotations

import os
import traceback

from scytaledroid.Utils.DisplayUtils import error_panels, menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption

from .menu_actions import (
    fetch_tier1_status as fetch_tier1_status,
    fetch_publication_status,
    handle_export_freeze_anchored_csvs,
    handle_generate_exploratory_risk_scoring,
    handle_generate_publication_results_numbers,
    handle_generate_profile_v3_phase2_exports,
    handle_generate_profile_v3_exports,
    handle_profile_v3_integrity_gates,
    handle_lint_profile_v2_bundle,
    handle_generate_publication_scientific_qa,
    handle_generate_publication_pipeline_audit,
    handle_print_manuscript_snapshot,
    handle_refresh_phase_e_bundle,
    handle_write_canonical_publication_bundle,
    view_saved_reports,
)


def reporting_menu() -> None:
    """Render the reporting menu until the user chooses to exit."""

    while True:
        print()
        menu_utils.print_header("Reporting")
        options = [
            MenuOption("1", "Frozen cohort archive tools"),
            MenuOption("2", "Structural cohort archive tools"),
            MenuOption("3", "Exploratory / saved reports"),
        ]
        menu_utils.print_menu(options, show_exit=True, exit_label="Back", show_descriptions=False, compact=True)
        top_choice = prompt_utils.get_choice(menu_utils.selectable_keys(options, include_exit=True), default="0")
        if top_choice == "0":
            break

        if top_choice == "1":
            _reporting_menu_v2_frozen()
        elif top_choice == "2":
            _reporting_menu_v3_structural()
        elif top_choice == "3":
            _reporting_menu_exploratory()
        else:
            print(status_messages.status("Invalid selection.", level="warn"))
            prompt_utils.press_enter_to_continue()


__all__ = ["reporting_menu"]


def _reporting_menu_v2_frozen() -> None:
    actions = {
        "1": handle_refresh_phase_e_bundle,
        "2": handle_generate_publication_results_numbers,
        "3": handle_generate_publication_scientific_qa,
        "4": handle_generate_publication_pipeline_audit,
        "5": handle_write_canonical_publication_bundle,
        "6": handle_export_freeze_anchored_csvs,
        "7": handle_print_manuscript_snapshot,
        "8": handle_lint_profile_v2_bundle,
    }
    options = [
        MenuOption("1", "Refresh frozen archive artifacts"),
        MenuOption("2", "Generate archived results numbers"),
        MenuOption("3", "Generate archived scientific QA"),
        MenuOption("4", "Generate archived pipeline audit"),
        MenuOption("5", "Write frozen-cohort archive bundle (output/publication/)"),
        MenuOption("6", "Export archived frozen-cohort CSVs"),
        MenuOption("7", "Print archived manuscript snapshot"),
        MenuOption("8", "Lint frozen-cohort archive bundle"),
        MenuOption("9", "Snapshot export refresh (COMING SOON)", disabled=True),
    ]

    while True:
        print()
        menu_utils.print_header("Reporting · Frozen Cohort Archive")
        status = fetch_publication_status()
        freeze_hash = str(status.get("freeze_dataset_hash") or "")
        freeze_short = freeze_hash[:12] if freeze_hash else "missing"
        pub_root = str(status.get("publication_root_label") or "output/publication")
        print("Active export profile: frozen cohort archive")
        print(f"Output root: {pub_root}")
        print(f"Freeze: {freeze_short}")

        audit = str(status.get("paper_audit_result") or "unknown")
        quota = status.get("evidence_quota_counted")
        expected = status.get("evidence_quota_expected")
        pub_ready = "READY" if status.get("publication_ready") else "NOT READY"
        tables_label = status.get("publication_tables_label") or "0"
        figs_label = status.get("publication_figures_label") or "0"
        results_ok = (status.get("results_numbers_label") or "").strip().lower() == "present"
        qa_ok = (status.get("qa_label") or "").strip().lower() == "present"
        if quota is not None and expected is not None:
            counts = f"{quota}/{expected} runs"
        else:
            counts = "runs unknown"
        print(f"Status: Audit {audit} | {counts} | Bundle {pub_ready}")
        print(f"Artifacts: Tables {tables_label} | Figures {figs_label} | Results {'✓' if results_ok else '✗'} | QA {'✓' if qa_ok else '✗'}")

        menu_utils.print_menu(options, show_exit=True, exit_label="Back", show_descriptions=False, compact=True)
        choice = prompt_utils.get_choice(menu_utils.selectable_keys(options, include_exit=True, disabled=[o.key for o in options if o.disabled]), default="0")
        if choice == "0":
            return
        action = actions.get(choice)
        if action:
            try:
                action()
            except Exception as exc:  # pragma: no cover
                debug = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower() == "debug"
                details = traceback.format_exc().splitlines()[-20:] if debug else []
                error_panels.print_error_panel(
                    "Reporting Action Failed",
                    str(exc),
                    details=details,
                    hint="Re-run with SCYTALEDROID_UI_LEVEL=debug for a full traceback.",
                )
                prompt_utils.press_enter_to_continue()


def _reporting_menu_v3_structural() -> None:
    actions = {
        "1": handle_profile_v3_integrity_gates,
        "2": handle_generate_profile_v3_exports,
        "3": handle_generate_profile_v3_phase2_exports,
    }
    options = [
        MenuOption("1", "Run structural archive integrity gates"),
        MenuOption("2", "Generate structural archive exports"),
        MenuOption("3", "Generate structural archive draft exports"),
    ]
    from pathlib import Path

    from scytaledroid.Publication.profile_v3_contract import lint_profile_v3_bundle

    while True:
        print()
        menu_utils.print_header("Reporting · Structural Cohort Archive")
        out_root = Path("output") / "publication" / "profile_v3"
        lint = lint_profile_v3_bundle(out_root)
        ready = "READY" if lint.ok else "NOT READY"
        print("Active export profile: structural cohort archive")
        print(f"Output root: {out_root}")
        print(f"Bundle: {ready}")
        if lint.errors:
            print(status_messages.status(f"First error: {lint.errors[0]}", level="warn"))
        if lint.warnings:
            print(status_messages.status(f"Warnings: {len(lint.warnings)}", level="info"))
        menu_utils.print_menu(options, show_exit=True, exit_label="Back", show_descriptions=False, compact=True)
        choice = prompt_utils.get_choice(menu_utils.selectable_keys(options, include_exit=True), default="0")
        if choice == "0":
            return
        action = actions.get(choice)
        if action:
            try:
                action()
            except Exception as exc:  # pragma: no cover
                debug = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower() == "debug"
                details = traceback.format_exc().splitlines()[-20:] if debug else []
                error_panels.print_error_panel(
                    "Reporting Action Failed",
                    str(exc),
                    details=details,
                    hint="Re-run with SCYTALEDROID_UI_LEVEL=debug for a full traceback.",
                )
                prompt_utils.press_enter_to_continue()


def _reporting_menu_exploratory() -> None:
    actions = {
        "1": handle_generate_exploratory_risk_scoring,
        "2": view_saved_reports,
    }
    options = [
        MenuOption("1", "Experimental risk model (SRS/DRS/FRS)"),
        MenuOption("2", "View saved reports"),
    ]
    while True:
        print()
        menu_utils.print_header("Reporting · Exploratory")
        menu_utils.print_menu(options, show_exit=True, exit_label="Back", show_descriptions=False, compact=True)
        choice = prompt_utils.get_choice(menu_utils.selectable_keys(options, include_exit=True), default="0")
        if choice == "0":
            return
        action = actions.get(choice)
        if action:
            try:
                action()
            except Exception as exc:  # pragma: no cover
                debug = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower() == "debug"
                details = traceback.format_exc().splitlines()[-20:] if debug else []
                error_panels.print_error_panel(
                    "Reporting Action Failed",
                    str(exc),
                    details=details,
                    hint="Re-run with SCYTALEDROID_UI_LEVEL=debug for a full traceback.",
                )
                prompt_utils.press_enter_to_continue()
