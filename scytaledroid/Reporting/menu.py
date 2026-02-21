"""Menu dispatcher for reporting workflows."""

from __future__ import annotations

import os

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, summary_cards
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec

from .menu_actions import (
    fetch_tier1_status,
    handle_dataset_readiness_dashboard,
    handle_tier1_audit_report,
    handle_tier1_end_to_end,
    handle_tier1_export_pack,
    handle_tier1_quick_fix,
    handle_write_canonical_publication_bundle,
    view_saved_reports,
)


def _legacy_publication_enabled() -> bool:
    value = os.getenv("SCYTALEDROID_ENABLE_LEGACY_PUBLICATION", "0").strip().lower()
    return value in {"1", "true", "yes", "on"}


def reporting_menu() -> None:
    """Render the reporting menu until the user chooses to exit."""

    actions_all = {
        # Core
        "1": handle_tier1_export_pack,
        "2": handle_tier1_audit_report,
        "3": handle_dataset_readiness_dashboard,
        "4": handle_tier1_quick_fix,
        "5": handle_tier1_end_to_end,
        "6": view_saved_reports,
    }

    core_options = [
        MenuOption("1", "Export baseline dataset pack (manifest + telemetry + summary)"),
        MenuOption("2", "Baseline audit report (dataset readiness)"),
        MenuOption("3", "Dataset readiness dashboard (app install/harvest/static/dynamic)"),
        MenuOption("4", "Baseline quick fix (reindex DB + audit + optional export)"),
        MenuOption("5", "Baseline end-to-end (reindex + audit + export)"),
    ]
    reports_options = [
        MenuOption("6", "View saved reports"),
    ]

    legacy_export_options: list[MenuOption] = []
    if _legacy_publication_enabled():
        actions_all["7"] = handle_write_canonical_publication_bundle
        legacy_export_options.append(
            MenuOption("7", "Legacy export: write canonical publication bundle")
        )

    core_visible = core_options
    reports_visible = reports_options
    visible_keys = {it.key for it in (core_visible + legacy_export_options + reports_visible)}
    actions = {k: v for k, v in actions_all.items() if k in visible_keys}

    while True:
        print()
        menu_utils.print_header("Reporting")
        status = fetch_tier1_status()
        schema_ver = status.get("schema_version") or "<unknown>"
        expected = status.get("expected_schema") or "<unknown>"
        tier1_ready = status.get("tier1_ready_runs", 0)
        evidence_valid = status.get("evidence_dataset_valid", 0)
        evidence_total = status.get("evidence_dataset_packs", 0)
        db_dataset = status.get("db_dynamic_sessions_dataset", 0)
        last_export_path = status.get("last_export_path")
        last_export_at = status.get("last_export_at")
        pcap_valid = status.get("pcap_valid_runs", 0)
        pcap_total = status.get("pcap_total_runs", 0)
        feature_health_status = status.get("feature_health_status")
        feature_health_at = status.get("feature_health_at")
        schema_outdated = schema_ver != expected
        schema_label = (
            f"{schema_ver} (expects {expected}) [OUTDATED]" if schema_outdated else str(schema_ver)
        )
        schema_style = "severity_high" if schema_outdated else "severity_info"
        ready_badge = "✅" if tier1_ready and int(tier1_ready) > 0 else "⚠️"
        export_label = f"{last_export_path} @ {last_export_at}" if last_export_path else "none"
        pcap_label = f"{pcap_valid}/{pcap_total}" if pcap_total else "none"
        pcap_style = "severity_low" if pcap_total and pcap_valid == 0 else "progress"
        evidence_label = f"{evidence_valid}/{evidence_total}" if evidence_total else "none"
        db_dataset_label = str(db_dataset or 0)
        if feature_health_status:
            feature_health_label = f"{feature_health_status} @ {feature_health_at}" if feature_health_at else str(feature_health_status)
        else:
            feature_health_label = "missing"
        summary_items = [
            summary_cards.summary_item("Schema", schema_label, value_style=schema_style),
            summary_cards.summary_item(
                f"Baseline QA-pass (DB) {ready_badge}",
                str(tier1_ready),
                value_style="progress",
            ),
            summary_cards.summary_item("Dataset packs valid (evidence)", evidence_label, value_style="progress"),
            summary_cards.summary_item("DB dataset runs tracked", db_dataset_label, value_style="muted"),
            summary_cards.summary_item("PCAP valid runs", pcap_label, value_style=pcap_style),
            summary_cards.summary_item("Feature Health (export)", feature_health_label, value_style="muted"),
            summary_cards.summary_item("Last export", export_label, value_style="muted"),
        ]
        footer = ""
        if schema_outdated:
            footer = "Next step: Database Tools → Apply baseline schema migrations."
        elif evidence_valid and int(evidence_valid) > 0 and (not tier1_ready or int(tier1_ready) == 0):
            footer = "Fix: Evidence valid but DB QA-pass is 0. Run [4] Baseline quick fix."
        elif (not last_export_path) or (feature_health_status is None):
            footer = "Tip: Run [1] Export baseline dataset pack to generate Feature Health."
        else:
            footer = "All checks green."
        summary_cards.print_summary_card(
            "Research Baseline Status",
            summary_items,
            subtitle="ScytaleDroid-Dyn-v1 readiness snapshot",
            footer=footer,
        )
        print()
        menu_utils.print_section("Core")
        menu_utils.render_menu(MenuSpec(items=core_visible, show_exit=False, exit_label=None, show_descriptions=False, padding=True))
        if legacy_export_options:
            menu_utils.print_section("Exports (Legacy)")
            menu_utils.render_menu(
                MenuSpec(
                    items=legacy_export_options,
                    show_exit=False,
                    exit_label=None,
                    show_descriptions=False,
                    padding=True,
                )
            )
        menu_utils.print_section("Reports")
        menu_utils.render_menu(MenuSpec(items=reports_visible, show_exit=False, exit_label=None, show_descriptions=False, padding=True))
        menu_utils.render_menu(MenuSpec(items=[], default=None, show_exit=True, exit_label="Back"))
        choice = prompt_utils.get_choice(
            menu_utils.selectable_keys(
                [*core_visible, *legacy_export_options, *reports_visible],
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
