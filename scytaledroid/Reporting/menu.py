"""Menu dispatcher for reporting workflows."""

from __future__ import annotations

import os
import traceback

from scytaledroid.Utils.DisplayUtils import error_panels, menu_utils, prompt_utils, status_messages, summary_cards
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption

from .menu_actions import (
    fetch_tier1_status as fetch_tier1_status,
    fetch_publication_status,
    handle_cross_analysis_summary,
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
        print(
            summary_cards.format_summary_card(
                "Reporting Workspace",
                [
                    summary_cards.summary_item("Frozen archive", "validated exports and bundle generation", value_style="accent"),
                    summary_cards.summary_item("Structural archive", "integrity gates and structural exports", value_style="accent"),
                    summary_cards.summary_item("Exploratory", "saved reports and non-canonical analysis", value_style="info"),
                ],
                footer="Choose the archive profile that matches the evidence contract you are working with.",
            )
        )
        options = [
            MenuOption("1", "Frozen cohort archive tools"),
            MenuOption("2", "Structural cohort archive tools"),
            MenuOption("3", "Exploratory / saved reports"),
        ]
        menu_utils.print_hint("Frozen archive is the canonical export path; exploratory remains separate by design.")
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
        audit = str(status.get("freeze_audit_result") or status.get("paper_audit_result") or "unknown")
        quota = status.get("evidence_quota_counted")
        expected = status.get("evidence_quota_expected")
        pub_ready = "READY" if status.get("publication_ready") else "NOT READY"
        tables_label = status.get("publication_tables_label") or "0"
        figs_label = status.get("publication_figures_label") or "0"
        results_ok = (status.get("results_numbers_label") or "").strip().lower() == "present"
        qa_ok = (status.get("qa_label") or "").strip().lower() == "present"
        analysis_ok = bool(status.get("analysis_ready"))
        analysis_label = str(status.get("analysis_label") or "missing")
        if quota is not None and expected is not None:
            counts = f"{quota}/{expected} runs"
        else:
            counts = "runs unknown"
        footer = f"Output root: {pub_root}"
        if status.get("analysis_cohort_label"):
            footer = f"{footer} · DB cohort: {status['analysis_cohort_label']}"
        print(
            summary_cards.format_summary_card(
                "Frozen Archive Status",
                [
                    summary_cards.summary_item("Audit", audit, value_style="success" if audit == "GO" else "warning"),
                    summary_cards.summary_item("Quota", counts, value_style="accent"),
                    summary_cards.summary_item("Bundle", pub_ready, value_style="success" if pub_ready == "READY" else "warning"),
                    summary_cards.summary_item("Derived", analysis_label, value_style="success" if analysis_ok else "warning"),
                    summary_cards.summary_item("Freeze", freeze_short, value_style="accent"),
                    summary_cards.summary_item("Tables", tables_label, value_style="accent"),
                    summary_cards.summary_item("Figures", figs_label, value_style="accent"),
                    summary_cards.summary_item("Results", "present" if results_ok else "missing", value_style="success" if results_ok else "warning"),
                    summary_cards.summary_item("QA", "present" if qa_ok else "missing", value_style="success" if qa_ok else "warning"),
                ],
                subtitle="Active export profile: frozen cohort archive",
                footer=footer,
            )
        )

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
        print(
            summary_cards.format_summary_card(
                "Structural Archive Status",
                [
                    summary_cards.summary_item("Bundle", ready, value_style="success" if lint.ok else "warning"),
                    summary_cards.summary_item("Warnings", len(lint.warnings), value_style="warning" if lint.warnings else "muted"),
                    summary_cards.summary_item("Errors", len(lint.errors), value_style="error" if lint.errors else "muted"),
                ],
                subtitle="Active export profile: structural cohort archive",
                footer=f"Output root: {out_root}",
            )
        )
        if lint.errors:
            menu_utils.print_hint(f"First error: {lint.errors[0]}")
        if lint.warnings:
            menu_utils.print_hint(f"Warnings: {len(lint.warnings)}")
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
        "3": handle_cross_analysis_summary,
    }
    options = [
        MenuOption("1", "Experimental risk model (SRS/DRS/FRS)"),
        MenuOption("2", "View saved reports"),
        MenuOption("3", "Cross-analysis summary (static + dynamic + regime)"),
    ]
    while True:
        print()
        menu_utils.print_header("Reporting · Exploratory")
        print(
            summary_cards.format_summary_card(
                "Exploratory Reporting",
                [
                    summary_cards.summary_item("Purpose", "non-canonical analysis and saved report review", value_style="info"),
                    summary_cards.summary_item("Boundary", "kept separate from frozen archive outputs", value_style="warning"),
                ],
                footer="Use this area for experimental outputs that should not affect canonical exports.",
            )
        )
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
