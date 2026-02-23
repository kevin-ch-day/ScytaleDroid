"""Menu dispatcher for reporting workflows.

Reporting is paper-facing and should reflect current publication artifacts first.
Older DB-centric "baseline pack" helpers remain available elsewhere, but they
should not dominate the default operator view when writing a paper.
"""

from __future__ import annotations

import os

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, summary_cards
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec

from .menu_actions import (
    # Back-compat: some tests and older tooling monkeypatch this symbol.
    # It is no longer used by the default paper-facing reporting UI.
    fetch_tier1_status as fetch_tier1_status,
    fetch_publication_status,
    handle_export_freeze_anchored_csvs,
    handle_generate_paper2_results_numbers,
    handle_refresh_phase_e_bundle,
    handle_write_canonical_publication_bundle,
    view_saved_reports,
)


def reporting_menu() -> None:
    """Render the reporting menu until the user chooses to exit."""

    actions_all = {
        "1": handle_refresh_phase_e_bundle,
        "2": handle_write_canonical_publication_bundle,
        "3": handle_export_freeze_anchored_csvs,
        "4": handle_generate_paper2_results_numbers,
        "5": view_saved_reports,
    }

    core_options = [
        MenuOption("1", "Refresh Phase E baseline bundle (ML + tables + figures)"),
        MenuOption("2", "Write canonical publication directory (output/publication/)"),
        MenuOption("3", "Export freeze-anchored CSVs (run summary + PCAP features + protocol ledger)"),
        MenuOption("4", "Generate Paper #2 Results numbers (Section V)"),
    ]
    reports_options = [
        MenuOption("5", "View saved reports"),
    ]

    core_visible = core_options
    reports_visible = reports_options
    visible_keys = {it.key for it in (core_visible + reports_visible)}
    actions = {k: v for k, v in actions_all.items() if k in visible_keys}

    while True:
        print()
        menu_utils.print_header("Reporting")
        status = fetch_publication_status()
        audit = status.get("paper_audit_result") or "unknown"
        can_freeze = "YES" if status.get("can_freeze") else "NO"
        quota = status.get("evidence_quota_counted")
        expected = status.get("evidence_quota_expected")
        quota_label = f"{quota}/{expected}" if quota is not None and expected is not None else "unknown"
        freeze_hash = str(status.get("freeze_dataset_hash") or "")
        freeze_short = freeze_hash[:12] if freeze_hash else "missing"
        pub_ready = "✅" if status.get("publication_ready") else "⚠️"
        pub_root = status.get("publication_root_label") or "output/publication"
        tables_label = status.get("publication_tables_label") or "0"
        figs_label = status.get("publication_figures_label") or "0"
        results_label = status.get("results_numbers_label") or "missing"
        exports_label = status.get("exports_label") or "missing"
        summary_items = [
            summary_cards.summary_item("Paper audit", f"{audit} (CAN_FREEZE={can_freeze})", value_style="progress"),
            summary_cards.summary_item("Evidence quota counted", quota_label, value_style="progress"),
            summary_cards.summary_item("Freeze dataset hash", freeze_short, value_style="muted"),
            summary_cards.summary_item(f"Publication bundle {pub_ready}", pub_root, value_style="progress"),
            summary_cards.summary_item("Tables", str(tables_label), value_style="muted"),
            summary_cards.summary_item("Figures", str(figs_label), value_style="muted"),
            summary_cards.summary_item("Results numbers (Sec V)", str(results_label), value_style="muted"),
            summary_cards.summary_item("Freeze-anchored exports", str(exports_label), value_style="muted"),
        ]
        footer = str(status.get("footer") or "")
        summary_cards.print_summary_card(
            "Paper #2 Publication Status",
            summary_items,
            subtitle="Evidence + Freeze + Publication bundle (paper-facing)",
            footer=footer,
        )
        print()
        menu_utils.print_section("Core")
        menu_utils.render_menu(MenuSpec(items=core_visible, show_exit=False, exit_label=None, show_descriptions=False, padding=True))
        menu_utils.print_section("Reports")
        menu_utils.render_menu(MenuSpec(items=reports_visible, show_exit=False, exit_label=None, show_descriptions=False, padding=True))
        menu_utils.render_menu(MenuSpec(items=[], default=None, show_exit=True, exit_label="Back"))
        choice = prompt_utils.get_choice(
            menu_utils.selectable_keys(
                [*core_visible, *reports_visible],
                include_exit=True,
            ),
            default="0",
        )

        if choice == "0":
            break

        action = actions.get(choice)
        if action:
            action()
        else:  # pragma: no cover - defensive path
            print(status_messages.status("Invalid selection.", level="warn"))
            prompt_utils.press_enter_to_continue()


__all__ = ["reporting_menu"]
