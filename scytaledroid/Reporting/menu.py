"""Menu dispatcher for reporting workflows."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, summary_cards
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec

from .menu_actions import (
    handle_device_report,
    handle_recent_static_runs,
    handle_static_report,
    handle_tier1_audit_report,
    handle_tier1_export_pack,
    handle_tier1_qa_failures_report,
    fetch_tier1_status,
    view_saved_reports,
)


def reporting_menu() -> None:
    """Render the reporting menu until the user chooses to exit."""

    actions = {
        "1": handle_tier1_export_pack,
        "2": handle_tier1_audit_report,
        "7": handle_tier1_qa_failures_report,
        "3": handle_device_report,
        "4": handle_static_report,
        "5": view_saved_reports,
        "6": handle_recent_static_runs,
    }

    options = [
        MenuOption("1", "Export Tier-1 dataset pack (manifest + telemetry + summary)"),
        MenuOption("2", "Tier-1 audit report (dataset readiness)"),
        MenuOption("7", "Tier-1 QA failures (last 10 runs)"),
        MenuOption("3", "Generate device summary report"),
        MenuOption("4", "Generate static analysis report"),
        MenuOption("5", "View saved reports"),
        MenuOption("6", "Recent static analysis runs"),
    ]

    while True:
        print()
        menu_utils.print_header("Reporting")
        status = fetch_tier1_status()
        schema_ver = status.get("schema_version") or "<unknown>"
        expected = status.get("expected_schema") or "<unknown>"
        tier1_ready = status.get("tier1_ready_runs", 0)
        last_export_path = status.get("last_export_path")
        last_export_at = status.get("last_export_at")
        pcap_valid = status.get("pcap_valid_runs", 0)
        pcap_total = status.get("pcap_total_runs", 0)
        schema_outdated = schema_ver != expected
        schema_label = (
            f"{schema_ver} (expects {expected}) [OUTDATED]" if schema_outdated else str(schema_ver)
        )
        schema_style = "severity_high" if schema_outdated else "severity_info"
        ready_badge = "✅" if tier1_ready and int(tier1_ready) > 0 else "⚠️"
        export_label = f"{last_export_path} @ {last_export_at}" if last_export_path else "none"
        pcap_label = f"{pcap_valid}/{pcap_total}" if pcap_total else "none"
        pcap_style = "severity_low" if pcap_total and pcap_valid == 0 else "progress"
        summary_items = [
            summary_cards.summary_item("Schema", schema_label, value_style=schema_style),
            summary_cards.summary_item(
                f"Tier-1 ready runs {ready_badge}",
                str(tier1_ready),
                value_style="progress",
            ),
            summary_cards.summary_item("PCAP valid runs", pcap_label, value_style=pcap_style),
            summary_cards.summary_item("Last export", export_label, value_style="muted"),
        ]
        footer = "Tip: Run Tier-1 audit if schema or readiness is out-of-date."
        if schema_outdated:
            footer = "Next step: Database Tools → Apply Tier-1 schema migrations"
        summary_cards.print_summary_card(
            "Research Dataset Status",
            summary_items,
            subtitle="ScytaleDroid-Dyn-v1 readiness snapshot",
            footer=footer,
        )
        print()
        menu_utils.print_section("Research / Tier-1")
        menu_utils.render_menu(
            MenuSpec(
                items=options[:3],
                show_exit=False,
                exit_label=None,
                show_descriptions=False,
                padding=True,
            )
        )
        menu_utils.print_section("Operational Reports")
        menu_utils.render_menu(
            MenuSpec(
                items=options[2:],
                show_exit=False,
                exit_label=None,
                show_descriptions=False,
                padding=True,
            )
        )
        menu_utils.render_menu(MenuSpec(items=[], default=None, show_exit=True, exit_label="Back"))
        choice = prompt_utils.get_choice([option.key for option in options] + ["0"], default="0")

        if choice == "0":
            break

        action = actions.get(choice)
        if action:
            action()
        else:  # pragma: no cover - defensive path
            print(status_messages.status("Option not implemented yet.", level="warn"))
            prompt_utils.press_enter_to_continue()


__all__ = ["reporting_menu"]
