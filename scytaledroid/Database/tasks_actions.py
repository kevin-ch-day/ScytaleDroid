"""Action helpers invoked by the database tasks menu."""

from __future__ import annotations

from typing import Dict

from scytaledroid.Database.db_func.harvest import dynamic_loading, storage_surface
from scytaledroid.Database.db_func.permissions import (
    detected_permissions,
    permission_support,
)
from scytaledroid.Database.db_func.static_analysis import static_findings, string_analysis
from scytaledroid.Persistence import db_writer
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def render_results(title: str, results: Dict[str, bool]) -> None:
    """Show a summary of provisioning outcomes."""

    print()
    menu_utils.print_section(title)
    for table, success in results.items():
        level = "success" if success else "error"
        outcome = "OK" if success else "FAILED"
        print(status_messages.status(f"{table}: {outcome}", level=level))
    print()
    prompt_utils.press_enter_to_continue()


def provision_static_tables() -> None:
    """Ensure core static-analysis tables exist."""

    results = {
        "runs / buckets / metrics / findings": db_writer.ensure_schema(),
        "static_findings_summary / static_findings": static_findings.ensure_tables(),
        "static_string_summary / static_string_samples": string_analysis.ensure_tables(),
    }
    render_results("Static-analysis tables", results)


def provision_permission_tables() -> None:
    """Ensure permission analytics tables are available."""

    results = permission_support.ensure_all()
    render_results("Permission analytics tables", results)


def provision_harvest_tables() -> None:
    """Ensure supporting harvest tables are created."""

    results = {
        "static_fileproviders / static_provider_acl": storage_surface.ensure_tables(),
        "static_dynload_events / static_reflection_calls": dynamic_loading.ensure_tables(),
        "android_detected_permissions": detected_permissions.ensure_table(),
    }
    render_results("Harvest support tables", results)


def seed_permission_signals() -> None:
    """Populate the permission signal catalogue with defaults."""

    inserted = updated = 0
    try:
        outcome = permission_support.seed_signal_catalog()
        inserted = outcome.get("inserted", 0)
        updated = outcome.get("updated", 0)
        print(
            status_messages.status(
                f"Seeded permission signal catalog (inserted={inserted}, updated={updated})",
                level="success",
            )
        )
    except Exception as exc:  # pragma: no cover - defensive
        print(status_messages.status(f"Failed to seed catalog: {exc}", level="error"))
    print()
    prompt_utils.press_enter_to_continue()


__all__ = [
    "provision_static_tables",
    "provision_permission_tables",
    "provision_harvest_tables",
    "render_results",
    "seed_permission_signals",
]
