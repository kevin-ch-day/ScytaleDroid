"""Dynamic Analysis hub menu orchestration."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from scytaledroid.Database.db_utils import schema_gate
from scytaledroid.DynamicAnalysis.menus.menu_overview import (
    build_dynamic_menu_sections,
    render_dynamic_menu_overview,
)
from scytaledroid.Utils.DisplayUtils import (
    colors,
    menu_utils,
    prompt_utils,
    status_messages,
    text_blocks,
)
from scytaledroid.Utils.DisplayUtils.terminal import get_terminal_width


@dataclass(frozen=True)
class DynamicAnalysisMenuCallbacks:
    warn_if_code_changed: Callable[[], None]
    load_ui_defaults: Callable[[], Any]
    resolve_active_cohort_for_run: Callable[[], dict[str, object] | None]
    run_guided_dataset_run: Callable[[Any], None]
    run_focused_app_run: Callable[[Any], None]
    run_paper_freeze_readiness: Callable[[], None]
    run_state_summary: Callable[[], None]
    run_freeze_readiness_audit: Callable[[], None]
    verify_host_pcap_tools: Callable[[], None]
    choose_active_research_cohort: Callable[[], None]
    repair_reindex_tracker: Callable[[], None]
    prune_incomplete_dynamic_evidence_dirs: Callable[[], None]
    open_legacy_structural_archive: Callable[[Callable[[], None]], None]
    run_cohort_security_audit_export: Callable[[], None]


def _pause_if_verbose() -> None:
    level = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower()
    if level in {"details", "debug"}:
        prompt_utils.press_enter_to_continue()


def _ordered_menu_actions(sections: Any) -> list[Any]:
    ordered = getattr(sections, "ordered_actions", None)
    if ordered is not None:
        ordered_list = list(ordered)
        if ordered_list:
            return ordered_list
    all_options = getattr(sections, "all_options", None)
    if all_options is not None:
        all_options_list = list(all_options)
        if all_options_list:
            return all_options_list
    return [
        *list(getattr(sections, "primary_actions", []) or []),
        *list(getattr(sections, "validation", []) or []),
        *list(getattr(sections, "maintenance", []) or []),
        *list(getattr(sections, "archive_export", []) or []),
    ]


def _run_maintenance_advanced_menu(callbacks: DynamicAnalysisMenuCallbacks) -> None:
    options = [
        menu_utils.MenuOption("1", "Reindex tracker"),
        menu_utils.MenuOption("2", "Prune incomplete evidence"),
        menu_utils.MenuOption("3", "Legacy structural tools"),
        menu_utils.MenuOption("4", "Cohort security audit export"),
    ]

    while True:
        print()
        menu_utils.print_header("Maintenance / Advanced")
        menu_utils.print_menu(options, show_exit=True, exit_label="Back", show_descriptions=False, compact=True)
        choice = prompt_utils.get_choice(menu_utils.selectable_keys(options, include_exit=True), default="0")

        if choice == "0":
            return
        if choice == "1":
            callbacks.repair_reindex_tracker()
            _pause_if_verbose()
            continue
        if choice == "2":
            callbacks.prune_incomplete_dynamic_evidence_dirs()
            _pause_if_verbose()
            continue
        if choice == "3":
            callbacks.open_legacy_structural_archive(_pause_if_verbose)
            _pause_if_verbose()
            continue
        if choice == "4":
            callbacks.run_cohort_security_audit_export()
            _pause_if_verbose()
            continue


def run_dynamic_analysis_menu(callbacks: DynamicAnalysisMenuCallbacks) -> None:
    ok, message, detail = schema_gate.dynamic_schema_gate()
    if not ok:
        status_messages.print_status(message, level="warn")
        if detail:
            status_messages.print_status(detail, level="warn")
        status_messages.print_status(
            "Note: DB-backed features may be unavailable. Dynamic capture and evidence-pack workflows remain enabled.",
            level="warn",
        )

    sections = build_dynamic_menu_sections()
    options = _ordered_menu_actions(sections)
    ui_defaults = callbacks.load_ui_defaults()

    while True:
        print()
        if colors.colors_enabled():
            text_blocks.print_accent_rule(width=min(56, max(28, get_terminal_width() - 4)))
        menu_utils.print_header("Dynamic Analysis")
        callbacks.warn_if_code_changed()
        render_dynamic_menu_overview()
        print()
        menu_utils.print_section("Actions")
        menu_utils.print_menu(
            options, show_exit=False, show_descriptions=False, compact=True
        )
        menu_utils.print_menu(
            [], show_exit=True, exit_label="Back", show_descriptions=False, compact=True
        )
        choice = prompt_utils.get_choice(
            menu_utils.selectable_keys(options, include_exit=True),
            disabled=[option.key for option in options if option.disabled],
        )

        if choice == "0":
            return
        if choice == "1":
            callbacks.warn_if_code_changed()
            callbacks.run_focused_app_run(ui_defaults)
            _pause_if_verbose()
            continue
        if choice == "2":
            selected = callbacks.resolve_active_cohort_for_run()
            if isinstance(selected, dict):
                callbacks.warn_if_code_changed()
                callbacks.run_guided_dataset_run(ui_defaults)
            _pause_if_verbose()
            continue
        if choice == "3":
            callbacks.run_paper_freeze_readiness()
            _pause_if_verbose()
            continue
        if choice == "4":
            callbacks.verify_host_pcap_tools()
            _pause_if_verbose()
            continue
        if choice == "5":
            callbacks.run_state_summary()
            _pause_if_verbose()
            continue
        if choice == "6":
            callbacks.run_freeze_readiness_audit()
            _pause_if_verbose()
            continue
        if choice == "7":
            callbacks.choose_active_research_cohort()
            _pause_if_verbose()
            continue
        if choice == "8":
            _run_maintenance_advanced_menu(callbacks)
            continue
